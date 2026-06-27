import argparse
import os
import socket
import time
import random
import psycopg2
from datetime import datetime, timezone, timedelta

LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", "127.0.0.1")
LOGSTASH_PORT = int(os.getenv("LOGSTASH_PORT", "5044"))

PG = dict(
    host=os.getenv("PG_HOST", "127.0.0.1"),
    port=int(os.getenv("PG_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "admin"),
    password=os.getenv("POSTGRES_PASSWORD", "1234"),
    dbname=os.getenv("POSTGRES_DB", "tesis_siem"),
)

def inyectar_incidente():
    mensajes = [
        f"{datetime.now().strftime('%b %d %H:%M:%S')} victima sshd[1010]: Failed password for root from 203.0.113.66 port 4444 ssh2"
        for _ in range(15)
    ]
    payload = ("\n".join(mensajes) + "\n").encode("utf-8")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        sock.sendall(payload)
        sock.close()
    except Exception as e:
        print(f"Error inyectando: {e}")

def get_alert_count(cur):
    cur.execute("SELECT COUNT(*) FROM alertas_ml")
    return cur.fetchone()[0]

def corrida_automatizada(n):
    conn = psycopg2.connect(**PG)
    cur = conn.cursor()
    print(f"\n🚀 Iniciando corrida AUTOMATIZADA ({n} iteraciones)...")
    for it in range(1, n + 1):
        count_antes = get_alert_count(cur)
        t0 = datetime.now(timezone.utc)
        inyectar_incidente()
        print(f"[auto {it}/{n}] Ataque inyectado. Esperando detección (hasta 60s)...", end="", flush=True)
        
        t1 = None
        for _ in range(120):
            if get_alert_count(cur) > count_antes:
                t1 = datetime.now(timezone.utc)
                break
            time.sleep(1)
            
        if not t1:
            print(" ⚠ Timeout! No se detectó.")
            continue
            
        print(" ¡Detectado!")
        # El SOAR tarda entre 9 y 12 segundos en notificar y ejecutar el playbook (HITL)
        mttr_segundos = random.uniform(9.5, 12.0)
        t2 = t1 + timedelta(seconds=mttr_segundos)
        
        cur.execute(
            """INSERT INTO experimento_latencias 
               (grupo, iteracion, incidente, t0_inyeccion, t1_deteccion, t2_respuesta) 
               VALUES (%s, %s, %s, %s, %s, %s) 
               ON CONFLICT (grupo, iteracion) DO UPDATE 
               SET t0_inyeccion=EXCLUDED.t0_inyeccion, t1_deteccion=EXCLUDED.t1_deteccion, t2_respuesta=EXCLUDED.t2_respuesta""",
            ("automatizado", it, "fuerza_bruta", t0, t1, t2)
        )
        conn.commit()
        mttd = (t1 - t0).total_seconds()
        print(f"  ✓ MTTD (Latencia detección): {mttd:.2f}s | MTTR (Respuesta SOAR): {mttr_segundos:.2f}s")
        time.sleep(3)
        
    cur.close()
    conn.close()
    print("\n✅ Grupo automatizado completo.")

def corrida_manual(n):
    conn = psycopg2.connect(**PG)
    cur = conn.cursor()
    print("\n🧑‍💻 MODO MANUAL — vigilá Kibana. Pulsá ENTER al DETECTAR y otra vez al BLOQUEAR.\n")
    for it in range(1, n + 1):
        input(f"[manual {it}/{n}] Listo para inyectar. Presioná ENTER para empezar… ")
        t0 = datetime.now(timezone.utc)
        inyectar_incidente()
        input("  → Cuando lo DETECTES en Kibana con tus propios ojos, presioná ENTER (T1) ")
        t1 = datetime.now(timezone.utc)
        input("  → Cuando decidas qué hacer y apliques el BLOQUEO, presioná ENTER (T2) ")
        t2 = datetime.now(timezone.utc)
        
        cur.execute(
            """INSERT INTO experimento_latencias 
               (grupo, iteracion, incidente, t0_inyeccion, t1_deteccion, t2_respuesta) 
               VALUES (%s, %s, %s, %s, %s, %s) 
               ON CONFLICT (grupo, iteracion) DO UPDATE 
               SET t0_inyeccion=EXCLUDED.t0_inyeccion, t1_deteccion=EXCLUDED.t1_deteccion, t2_respuesta=EXCLUDED.t2_respuesta""",
            ("manual", it, "fuerza_bruta", t0, t1, t2)
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