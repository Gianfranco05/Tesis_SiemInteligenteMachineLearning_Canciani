#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════
#  medir_grupo_manual.py
#  Mide el MTTR del grupo de CONTROL (analista humano).
#
#  QUÉ MIDE:
#    T1 = momento en que llega la alerta (sistema notifica la anomalía)
#    T2 = momento en que el analista decide y ejecuta el bloqueo
#    MTTR = T2 - T1
#
#  PROTOCOLO:
#    - El script inyecta el ataque y muestra la alerta simulada
#      (equivalente a lo que llegaría por Telegram).
#    - VOS leés la alerta, evaluás la IP, el score, el país.
#    - Cuando decidís bloquear, apretás ENTER. Ese es T2.
#    - NO apretar Enter de inmediato: tomarte el tiempo real
#      que necesitarías para leer y decidir (típico: 10-30s).
#
#  Uso:
#    docker exec -e PG_HOST=siem_postgres -it siem_ml python /app/medir_grupo_manual.py
# ════════════════════════════════════════════════════════════════

import os
import socket
import time
import random
import psycopg2
from datetime import datetime, timezone

LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", "siem_logstash")
LOGSTASH_PORT = int(os.getenv("LOGSTASH_PORT", "5044"))
PG = dict(
    host=os.getenv("PG_HOST", "siem_postgres"),
    port=int(os.getenv("PG_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "admin"),
    password=os.getenv("POSTGRES_PASSWORD", "1234"),
    dbname=os.getenv("POSTGRES_DB", "tesis_siem"),
)

# IPs y países simulados para el contexto de la alerta
ALERTAS_SIMULADAS = [
    {"ip": "185.220.101.45", "pais": "Rusia",          "score": 0.87, "reportes": 142, "isp": "Tor Exit Node"},
    {"ip": "203.0.113.66",   "pais": "China",           "score": 0.91, "reportes": 89,  "isp": "AS4134 ChinaTelecom"},
    {"ip": "45.33.32.156",   "pais": "Estados Unidos",  "score": 0.79, "reportes": 34,  "isp": "Linode LLC"},
    {"ip": "91.121.87.32",   "pais": "Francia",         "score": 0.83, "reportes": 67,  "isp": "OVH SAS"},
    {"ip": "198.51.100.77",  "pais": "Países Bajos",    "score": 0.95, "reportes": 211, "isp": "Mullvad VPN"},
    {"ip": "103.21.244.14",  "pais": "India",           "score": 0.74, "reportes": 28,  "isp": "AS55720 Reliance"},
    {"ip": "77.247.181.163", "pais": "Alemania",        "score": 0.88, "reportes": 156, "isp": "Chaos Computer Club"},
    {"ip": "162.247.74.74",  "pais": "Estados Unidos",  "score": 0.82, "reportes": 73,  "isp": "Tor Project"},
    {"ip": "185.130.44.108", "pais": "Bulgaria",        "score": 0.93, "reportes": 198, "isp": "AS57858 Privatix"},
    {"ip": "109.70.100.27",  "pais": "Austria",         "score": 0.86, "reportes": 91,  "isp": "AS3209 Vodafone"},
]

INCIDENTES = ["fuerza_bruta", "fuerza_bruta", "fuerza_bruta",
               "fuerza_bruta", "fuerza_bruta", "spike", "nocturno"]


def inyectar(incidente, ip):
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    if incidente == "fuerza_bruta":
        msgs = [
            f"{ts} victima_ssh sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user admin from {ip} port {random.randint(40000,60000)} ssh2\n"
            for _ in range(8)
        ]
    elif incidente == "nocturno":
        msgs = [f"Jun 15 03:22:11 victima_ssh sshd[1025]: Accepted password for root from {ip} port 22 ssh2\n"]
    else:
        msgs = [f"{ts} victima_ssh kernel: CPU usage spike 98% from process {ip}\n"]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        sock.sendall("".join(msgs).encode("utf-8"))
        sock.close()
    except Exception as e:
        print(f"  ⚠ No se pudo conectar a Logstash ({e}). Continuando de todas formas.")


def guardar(cur, conn, iteracion, incidente, ip, t1, t2):
    mttr = (t2 - t1).total_seconds()
    cur.execute(
        """INSERT INTO experimento_latencias
               (grupo, iteracion, incidente, t0_inyeccion, t1_deteccion, t2_respuesta)
           VALUES ('manual', %s, %s, %s, %s, %s)
           ON CONFLICT (grupo, iteracion) DO UPDATE
             SET t0_inyeccion = EXCLUDED.t0_inyeccion,
                 t1_deteccion = EXCLUDED.t1_deteccion,
                 t2_respuesta = EXCLUDED.t2_respuesta;""",
        (iteracion, incidente, t1, t1, t2),  # T0=T1 para el manual (MTTR = T2-T1)
    )
    conn.commit()
    return mttr


def mostrar_alerta(alerta, incidente):
    """Simula la alerta que llegaría por Telegram al analista."""
    tipo = {
        "fuerza_bruta": "FUERZA BRUTA SSH",
        "nocturno":     "ACCESO NOCTURNO SOSPECHOSO",
        "spike":        "PICO INUSUAL DE CPU",
    }.get(incidente, "ANOMALÍA DETECTADA")

    print("\n" + "═" * 55)
    print("  🚨 ALERTA DE SEGURIDAD — MOTOR ML")
    print("═" * 55)
    print(f"  Tipo de Amenaza:    {tipo}")
    print(f"  IP Atacante:        {alerta['ip']}")
    print(f"  Score de Riesgo:    {alerta['score']}/1.00")
    print(f"  País de Origen:     {alerta['pais']}")
    print(f"  ISP:                {alerta['isp']}")
    print(f"  Reportes AbuseIPDB: {alerta['reportes']}")
    print(f"  Acción sugerida:    BLOQUEO via iptables")
    print("═" * 55)
    print("  ↑ Esto es lo que verías en Telegram.")
    print("  Leé la alerta, evaluá el contexto y decidí.")
    print("  Cuando decidas BLOQUEAR, presioná ENTER (T2).")


def main():
    try:
        conn = psycopg2.connect(**PG)
        cur = conn.cursor()
    except Exception as e:
        print(f"❌ No se pudo conectar a PostgreSQL: {e}")
        print("   Verificá que PG_HOST apunte al contenedor correcto.")
        return

    print("\n" + "═" * 55)
    print("  MEDICIÓN GRUPO MANUAL — PROTOCOLO MTTR")
    print("═" * 55)
    print("""
  INSTRUCCIONES IMPORTANTES:
  • Cada iteración simula que el sistema detectó una amenaza
    y te envió la alerta (igual que Telegram).
  • Tu trabajo: leer la alerta, evaluar IP/score/país,
    y cuando decidas bloquear, presionar ENTER.
  • Tiempo esperado por iteración: 10-30 segundos.
  • NO apretar Enter de inmediato: eso invalidaría la medición.
  • Hacé el proceso como si fuera real.
""")
    input("  Presioná ENTER cuando estés listo para comenzar… ")

    resultados = []
    n = 30
    for it in range(1, n + 1):
        incidente = INCIDENTES[(it - 1) % len(INCIDENTES)]
        alerta = ALERTAS_SIMULADAS[(it - 1) % len(ALERTAS_SIMULADAS)]

        print(f"\n[{it}/{n}] Inyectando incidente '{incidente}'...")
        inyectar(incidente, alerta["ip"])

        # T1: el sistema detectó y "notificó" — arranca el timer del analista
        t1 = datetime.now(timezone.utc)
        mostrar_alerta(alerta, incidente)

        # El analista lee, evalúa y decide
        input()  # ENTER = T2

        t2 = datetime.now(timezone.utc)
        mttr = guardar(cur, conn, it, incidente, alerta["ip"], t1, t2)
        resultados.append(mttr)
        print(f"  ✓ MTTR = {mttr:.2f}s")

        if it < n:
            print(f"\n  Próxima iteración en 3 segundos...")
            time.sleep(3)

    cur.close()
    conn.close()

    import numpy as np
    arr = np.array(resultados)
    print("\n" + "═" * 55)
    print("  RESUMEN GRUPO MANUAL")
    print("═" * 55)
    print(f"  n          = {len(arr)}")
    print(f"  Media MTTR = {arr.mean():.2f} s")
    print(f"  Desv. Est. = {arr.std(ddof=1):.2f} s")
    print(f"  Mediana    = {np.median(arr):.2f} s")
    print(f"  Mín / Máx  = {arr.min():.2f}s / {arr.max():.2f}s")
    print("═" * 55)
    print("\n  ✅ Datos guardados en PostgreSQL (tabla experimento_latencias).")
    print("  Corré analizar_experimento.py para ver el análisis completo.\n")


if __name__ == "__main__":
    main()
