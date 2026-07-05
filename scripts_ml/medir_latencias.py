#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════
#  medir_latencias.py — CORREGIDO
#  Mide MTTD y MTTR de los dos grupos experimentales (Sección 5.1.2
#  de la tesis) con datos 100% reales extraídos de PostgreSQL.
#
#  CAMBIO CRÍTICO respecto a la versión anterior:
#  Antes, corrida_automatizada() fabricaba el T2 (y por lo tanto el
#  MTTR completo) con `random.uniform(9.5, 12.0)`. Eso ya NO existe.
#  Ahora T2 se obtiene haciendo polling real sobre la tabla
#  respuestas_aplicadas, que el workflow RU4_Respuesta llena con un
#  INSERT real en el momento exacto en que n8n ejecuta el bloqueo por
#  SSH (ver nodo "Registrar Respuesta Real (T2)" en RU4_ Respuesta.json).
#
#  IMPORTANTE — esto es HITL (Human-in-the-Loop), no 100% automático:
#  RU-4 está diseñada para que el analista reciba la alerta por
#  Telegram (con contexto OSINT ya enriquecido) y presione el botón
#  "Bloquear IP". El T2 medido acá incluye ese tiempo de reacción
#  humano frente al celular, tal como lo describe el Anexo G de la
#  tesis. Es esperable que el MTTR real sea más alto y más variable
#  que el rango fijo 9.5–12s que se usaba antes — eso es lo correcto:
#  estás midiendo "click en Telegram" contra "triage manual completo
#  en Kibana", no comparando contra un proceso sin intervención humana.
#
#  Requisitos antes de correr esto:
#    1. El stack completo levantado: docker compose up -d
#    2. Los 7 workflows de n8n importados y ACTIVOS (ya vienen con
#       "active": true en los JSON corregidos, pero hay que
#       importarlos una vez en la UI de n8n: Import from File).
#    3. El motor ML corriendo en loop (por defecto ya lo hace el
#       contenedor ml-python, ver docker-compose.yml).
#    4. Tener Telegram a mano durante la corrida del grupo automatizado,
#       para presionar "Bloquear IP" apenas llegue cada alerta.
#
#  Uso:
#    python medir_latencias.py --grupo automatizado --n 30
#    python medir_latencias.py --grupo manual --n 30
#    python analizar_experimento.py      # genera Tabla 1 / 5.1.2 reales
# ════════════════════════════════════════════════════════════════

import argparse
import os
import socket
import time
import random
import psycopg2
from datetime import datetime, timezone

LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", "127.0.0.1")
LOGSTASH_PORT = int(os.getenv("LOGSTASH_PORT", "5044"))

PG = dict(
    host=os.getenv("PG_HOST", "127.0.0.1"),
    port=int(os.getenv("PG_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "admin"),
    password=os.getenv("POSTGRES_PASSWORD", "1234"),
    dbname=os.getenv("POSTGRES_DB", "tesis_siem"),
)

# Cuánto esperar como máximo por cada evento (en segundos)
TIMEOUT_DETECCION = 90     # T0 -> T1: motor ML + webhook + insert en alertas_ml
TIMEOUT_RESPUESTA = 300    # T1 -> T2: alerta Telegram + click humano + SSH + insert
                           # (5 minutos: da tiempo real a revisar el celular)


def ip_aleatoria():
    """IP distinta en cada iteración: evita que freq_ip se acumule entre
    iteraciones y rompa la independencia estadística de las 30 muestras."""
    return f"203.0.113.{random.randint(10, 250)}"


def inyectar_incidente(ip):
    """Inyecta una ráfaga de 15 intentos fallidos de SSH (patrón RU-1 /
    freq_ip >= 5) con el formato EXACTO que espera logstash.conf."""
    mensajes = [
        f"{datetime.now().strftime('%b %d %H:%M:%S')} victima_ssh "
        f"sshd[{random.randint(1000,9999)}]: Failed password for root "
        f"from {ip} port {random.randint(40000,60000)} ssh2"
        for _ in range(15)
    ]
    payload = ("\n".join(mensajes) + "\n").encode("utf-8")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        sock.sendall(payload)
        sock.close()
    except Exception as e:
        print(f"Error inyectando: {e}")


def _first_timestamp_for_ip(cur, tabla, ip, desde):
    """Devuelve el timestamp más antiguo de una fila en `tabla` para esa
    IP con fecha >= desde, o None si todavía no existe."""
    cur.execute(
        f"SELECT MIN(fecha) FROM {tabla} WHERE ip_origen = %s AND fecha >= %s",
        (ip, desde),
    )
    row = cur.fetchone()
    return row[0] if row and row[0] else None


def corrida_automatizada(n):
    conn = psycopg2.connect(**PG)
    cur = conn.cursor()
    print(f"\n🚀 Iniciando corrida AUTOMATIZADA — {n} iteraciones (datos REALES)")
    print("   Vas a recibir alertas por Telegram: presioná 'Bloquear IP' apenas")
    print("   llegue cada una, así medimos tu tiempo de reacción real (HITL).\n")

    completadas = 0
    for it in range(1, n + 1):
        ip = ip_aleatoria()
        t0 = datetime.now(timezone.utc)
        inyectar_incidente(ip)
        print(f"[auto {it}/{n}] Ataque inyectado desde {ip}. Esperando detección del "
              f"motor ML (hasta {TIMEOUT_DETECCION}s)...", end="", flush=True)

        # ── T1: el motor ML detectó la anomalía y n8n la insertó en alertas_ml ──
        t1 = None
        limite = time.time() + TIMEOUT_DETECCION
        while time.time() < limite:
            t1 = _first_timestamp_for_ip(cur, "alertas_ml", ip, t0)
            if t1:
                break
            time.sleep(2)

        if not t1:
            print(" ⚠ Timeout, no se detectó. Se descarta esta iteración.")
            print("   (revisá que el contenedor siem_ml esté corriendo en --loop)")
            continue

        print(" ¡Detectado! Revisá Telegram y presioná 'Bloquear IP'...", end="", flush=True)

        # ── T2: n8n ejecutó el bloqueo SSH y lo registró en respuestas_aplicadas ──
        t2 = None
        limite = time.time() + TIMEOUT_RESPUESTA
        while time.time() < limite:
            t2 = _first_timestamp_for_ip(cur, "respuestas_aplicadas", ip, t1)
            if t2:
                break
            time.sleep(2)

        if not t2:
            print(" ⚠ Timeout esperando el bloqueo. Se descarta esta iteración.")
            continue

        print(" ¡Bloqueada!")

        cur.execute(
            """INSERT INTO experimento_latencias
               (grupo, iteracion, incidente, t0_inyeccion, t1_deteccion, t2_respuesta)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (grupo, iteracion) DO UPDATE
               SET t0_inyeccion=EXCLUDED.t0_inyeccion, t1_deteccion=EXCLUDED.t1_deteccion,
                   t2_respuesta=EXCLUDED.t2_respuesta""",
            ("automatizado", it, "fuerza_bruta", t0, t1, t2),
        )
        conn.commit()
        mttd = (t1 - t0).total_seconds()
        mttr = (t2 - t1).total_seconds()
        completadas += 1
        print(f"  ✓ MTTD (detección): {mttd:.2f}s | MTTR (respuesta HITL real): {mttr:.2f}s")
        time.sleep(2)

    cur.close()
    conn.close()
    print(f"\n✅ Grupo automatizado: {completadas}/{n} iteraciones completadas con datos reales.")
    if completadas < n:
        print("   Corré el comando de nuevo (mismo --n) para completar las que faltan;")
        print("   el ON CONFLICT actualiza por número de iteración, no duplica filas.")


def corrida_manual(n):
    conn = psycopg2.connect(**PG)
    cur = conn.cursor()
    print("\n🧑‍💻 MODO MANUAL — vigilá Kibana. Pulsá ENTER al DETECTAR y otra vez al BLOQUEAR.\n")
    for it in range(1, n + 1):
        ip = ip_aleatoria()
        input(f"[manual {it}/{n}] Listo para inyectar. Presioná ENTER para empezar… ")
        t0 = datetime.now(timezone.utc)
        inyectar_incidente(ip)
        input("  → Cuando lo DETECTES en Kibana con tus propios ojos, presioná ENTER (T1) ")
        t1 = datetime.now(timezone.utc)
        input("  → Cuando decidas qué hacer y apliques el BLOQUEO, presioná ENTER (T2) ")
        t2 = datetime.now(timezone.utc)

        cur.execute(
            """INSERT INTO experimento_latencias
               (grupo, iteracion, incidente, t0_inyeccion, t1_deteccion, t2_respuesta)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (grupo, iteracion) DO UPDATE
               SET t0_inyeccion=EXCLUDED.t0_inyeccion, t1_deteccion=EXCLUDED.t1_deteccion,
                   t2_respuesta=EXCLUDED.t2_respuesta""",
            ("manual", it, "fuerza_bruta", t0, t1, t2),
        )
        conn.commit()
        mttd = (t1 - t0).total_seconds()
        mttr = (t2 - t1).total_seconds()
        print(f"  ✓ MTTD={mttd:.2f}s  MTTR={mttr:.2f}s\n")

    cur.close()
    conn.close()
    print("✅ Grupo manual completo.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--grupo", required=True, choices=["manual", "automatizado"])
    ap.add_argument("--n", type=int, default=30)
    args = ap.parse_args()
    if args.grupo == "automatizado":
        corrida_automatizada(args.n)
    else:
        corrida_manual(args.n)
