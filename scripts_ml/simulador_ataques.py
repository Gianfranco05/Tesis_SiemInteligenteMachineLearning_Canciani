import socket
import time
import random
import requests
from datetime import datetime

# Configuración centralizada
HOST = 'siem_logstash'
PORT = 5044
WEBHOOK_N8N = "http://siem_n8n:5678/webhook/alerta-ml"

def obtener_timestamp_syslog():
    # Genera la fecha en formato Syslog: "May 28 15:30:00"
    return datetime.now().strftime("%b %d %H:%M:%S")

def obtener_timestamp_diurno():
    # Fuerza una hora laboral aleatoria (08:00 - 18:59) para tráfico orgánico legítimo
    hora = random.randint(8, 18)
    minuto = random.randint(0, 59)
    segundo = random.randint(0, 59)
    return datetime.now().strftime(f"%b %d {hora:02d}:{minuto:02d}:{segundo:02d}")

def enviar_log(mensaje, verbose=True):
    """Función maestra para enviar logs TCP a Logstash"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        sock.sendall(mensaje.encode('utf-8'))
        sock.close()
        if verbose:
            print(f"✅ Log enviado a Logstash: {mensaje.strip()}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

# ══════════════════════════════════════════════════════════
# TRÁFICO ORGÁNICO NORMAL (la "línea base" legítima de la red)
# Representa el 85% del tráfico según Shiravi et al. (2012).
# Estos eventos DEBEN ser clasificados como NORMALES por el ML.
# ══════════════════════════════════════════════════════════

def generar_login_exitoso_diurno():
    """Login SSH legítimo de un usuario real en horario laboral."""
    usuarios = ["gianfranco", "admin", "operador", "soporte", "devops"]
    ip_interna = f"192.168.1.{random.randint(10, 49)}"
    usuario = random.choice(usuarios)
    timestamp = obtener_timestamp_diurno()
    return f"{timestamp} servidor_app sshd[{random.randint(1000, 9999)}]: Accepted password for {usuario} from {ip_interna} port {random.randint(40000, 60000)} ssh2\n"

def generar_sesion_cerrada():
    """Cierre de sesión normal de un usuario."""
    usuarios = ["gianfranco", "admin", "operador", "soporte"]
    ip_interna = f"192.168.1.{random.randint(10, 49)}"
    usuario = random.choice(usuarios)
    timestamp = obtener_timestamp_diurno()
    return f"{timestamp} servidor_app sshd[{random.randint(1000, 9999)}]: Disconnected from user {usuario} {ip_interna} port {random.randint(40000, 60000)}\n"

def generar_evento_cron():
    """Tarea programada del sistema (cron), ruido de fondo normal."""
    tareas = ["backup_diario.sh", "rotate_logs", "update_check", "session-cleanup"]
    timestamp = obtener_timestamp_diurno()
    return f"{timestamp} servidor_app CRON[{random.randint(1000, 9999)}]: (root) CMD ({random.choice(tareas)})\n"

def generar_evento_systemd_normal():
    """Mensaje rutinario de systemd, operación normal del SO."""
    servicios = ["nginx.service", "postgresql.service", "docker.service", "ssh.service"]
    acciones = ["Started", "Reloaded", "Listening on"]
    timestamp = obtener_timestamp_diurno()
    return f"{timestamp} servidor_app systemd[1]: {random.choice(acciones)} {random.choice(servicios)}\n"

def generar_resolucion_dns():
    """Consulta DNS interna normal."""
    dominios = ["repo.empresa.local", "ntp.empresa.local", "git.empresa.local", "mail.empresa.local"]
    timestamp = obtener_timestamp_diurno()
    return f"{timestamp} servidor_app systemd-resolved[{random.randint(100, 999)}]: Positive cache hit for {random.choice(dominios)}\n"

GENERADORES_NORMALES = [
    generar_login_exitoso_diurno,
    generar_sesion_cerrada,
    generar_evento_cron,
    generar_evento_systemd_normal,
    generar_resolucion_dns,
]

def inyectar_trafico_organico(cantidad, verbose=False):
    """Inyecta `cantidad` de eventos normales aleatorios (línea base legítima)."""
    print(f"\n[~] Inyectando {cantidad} eventos de tráfico orgánico normal...")
    for i in range(cantidad):
        generador = random.choice(GENERADORES_NORMALES)
        enviar_log(generador(), verbose=verbose)
        time.sleep(0.02)
    print(f"✅ {cantidad} eventos normales inyectados (línea base).")

# ══════════════════════════════════════════════════════════
# VECTORES DE ATAQUE (telemetría sintética anómala = 15%)
# ══════════════════════════════════════════════════════════

def ru1_fuerza_bruta(verbose=True):
    print("\n[!] Simulando RU-1: Fuerza Bruta SSH...")
    ip_atacante = f"192.168.1.{random.randint(50, 100)}"
    timestamp = obtener_timestamp_syslog()

    for i in range(15):
        # Formato exacto que espera tu Grok filter en Logstash
        mensaje = f"{timestamp} victima_ssh sshd[1024]: Failed password for root from {ip_atacante} port 50234 ssh2\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.1)

def ru2_acceso_nocturno(verbose=True):
    print("\n[!] Simulando RU-2: Acceso en horario anómalo...")
    ip_admin = f"192.168.1.{random.randint(10, 15)}"
    # Forzamos una hora de madrugada en el timestamp
    timestamp_nocturno = datetime.now().strftime("%b %d 03:15:00")

    mensaje = f"{timestamp_nocturno} victima_ssh sshd[1025]: Accepted password for admin from {ip_admin} port 50235 ssh2\n"
    enviar_log(mensaje, verbose=verbose)

def ru3_spike_recursos(verbose=True):
    print("\n[!] Simulando RU-3: Pico inusual de CPU...")
    cpu_usage = random.randint(95, 99)
    ip_servidor = f"192.168.1.{random.randint(20, 30)}"
    timestamp = obtener_timestamp_syslog()

    mensaje = f"{timestamp} victima_ssh systemd[1]: METRICA ANOMALA: SPIKE_CPU detectado al {cpu_usage}% (Desviacion > 3 sigma) en host {ip_servidor}\n"
    enviar_log(mensaje, verbose=verbose)

def ru4_machine_learning():
    print("\n[!] Simulando RU-4: Motor ML (Isolation Forest)...")
    print("📊 Analizando entropía multidimensional...")
    time.sleep(1)

    score_anomalia = round(random.uniform(0.85, 0.99), 2)
    ip_sospechosa = f"192.168.1.{random.randint(200, 250)}"

    print(f"⚠️ Anomalía detectada (Score: {score_anomalia}). Disparando SOAR...")

    alerta_json = {
        "regla": "RU-4",
        "algoritmo": "Isolation Forest",
        "tipo_patron": "Comportamiento Multidimensional Atípico",
        "ip_origen": ip_sospechosa,
        "score_riesgo": score_anomalia,
        "accion": "Requiere correlación y bloqueo"
    }

    try:
        respuesta = requests.post(WEBHOOK_N8N, json=alerta_json)
        if respuesta.status_code == 200:
            print("✅ Webhook entregado. ¡Revisá tu Telegram para bloquear la IP!")
        else:
            print(f"❌ Error en n8n: {respuesta.status_code}")
    except Exception as e:
        print(f"❌ Error al contactar webhook: {e}")

# ══════════════════════════════════════════════════════════
# ESCENARIO TESIS — Dataset balanceado 85/15 (Shiravi et al.)
# Genera de una sola vez el dataset realista que valida el F1-Score
# reportado en la Tabla 2 del documento.
# ══════════════════════════════════════════════════════════

def escenario_tesis():
    print("\n" + "="*55)
    print("  🎓 GENERANDO ESCENARIO DE VALIDACIÓN (TESIS)")
    print("  Proporción objetivo: ~85% orgánico / ~15% anómalo")
    print("  (Modelo de Shiravi et al., 2012)")
    print("="*55)

    # ── 15% ANÓMALO: los vectores de ataque ──────────────────
    # RU-1 genera 15 logs, RU-2 genera 1, RU-3 genera 1 = 17 anómalos
    ru1_fuerza_bruta(verbose=False)
    ru2_acceso_nocturno(verbose=False)
    ru3_spike_recursos(verbose=False)
    eventos_anomalos = 17

    # ── 85% ORGÁNICO: tráfico normal de fondo ────────────────
    # Para que 17 sea el ~15%, el total debe ser ~113 -> 96 normales
    eventos_normales = round(eventos_anomalos * 85 / 15)
    inyectar_trafico_organico(eventos_normales, verbose=False)

    total = eventos_anomalos + eventos_normales
    pct_anom = round(eventos_anomalos / total * 100, 1)
    pct_norm = round(eventos_normales / total * 100, 1)

    print("\n" + "="*55)
    print("  ✅ ESCENARIO GENERADO")
    print(f"  Eventos anomalos:  {eventos_anomalos:>3} ({pct_anom}%)")
    print(f"  Eventos normales:  {eventos_normales:>3} ({pct_norm}%)")
    print(f"  Total dataset:     {total:>3}")
    print("="*55)
    print("\n💡 Ahora ejecuta el motor ML para validar las metricas:")
    print("   python /app/motor_ml.py\n")

def menu():
    while True:
        print("\n" + "="*45)
        print("🚀 SIMULADOR DE AMENAZAS SIEM (MODO TESIS)")
        print("="*45)
        print("1. Ejecutar RU-1: Fuerza Bruta SSH")
        print("2. Ejecutar RU-2: Acceso Exitoso (Madrugada)")
        print("3. Ejecutar RU-3: Pico Inusual de Consumo")
        print("4. Ejecutar RU-4: Anomalía Machine Learning (HITL)")
        print("5. Inyectar solo trafico organico normal")
        print("6. ESCENARIO TESIS (dataset balanceado 85/15)")
        print("7. Salir")

        opcion = input("\nElige una opcion (1-7): ")

        if opcion == '1':
            ru1_fuerza_bruta()
        elif opcion == '2':
            ru2_acceso_nocturno()
        elif opcion == '3':
            ru3_spike_recursos()
        elif opcion == '4':
            ru4_machine_learning()
        elif opcion == '5':
            try:
                n = int(input("Cuantos eventos normales? (ej. 50): "))
            except ValueError:
                n = 50
            inyectar_trafico_organico(n, verbose=True)
        elif opcion == '6':
            escenario_tesis()
        elif opcion == '7':
            print("\nFinalizando simulador...")
            break
        else:
            print("\n❌ Opcion no valida.")

if __name__ == "__main__":
    menu()
