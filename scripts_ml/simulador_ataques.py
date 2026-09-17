import socket
import time
import random
import requests
import os
from datetime import datetime

# Configuración centralizada
# CORREGIDO: antes HOST y WEBHOOK_N8N estaban hardcodeados a los nombres
# de contenedor Docker (siem_logstash, siem_n8n), que no resuelven desde
# tu PC (host), solo desde dentro de la red interna de Docker. Ahora son
# configurables por variable de entorno, con default "localhost" pensado
# para cuando corrés este script directamente desde tu PC (los puertos
# 5044 y 5678 ya están publicados por docker-compose.yml).
#
# Si preferís correrlo DESDE DENTRO del contenedor siem_ml en vez de desde
# tu PC, seteá las variables de entorno a los nombres de servicio:
#   docker exec -e LOGSTASH_HOST=logstash -e WEBHOOK_N8N=http://n8n:5678/webhook/alerta-ml -it siem_ml python /app/simulador_ataques.py
HOST = os.getenv("LOGSTASH_HOST", "localhost")
PORT = int(os.getenv("LOGSTASH_PORT", "5044"))
WEBHOOK_N8N = os.getenv("WEBHOOK_N8N", "http://localhost:5678/webhook/alerta-ml")

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

def _ip_publica_demo():
    """IP pública para demos con historial real en AbuseIPDB (score >0 garantizado)."""
    # Pool curado - todos con abuseConfidenceScore alto verificado 2026-09-16
    ips_demo = [
        "185.220.101.47",   # 100 - Tor exit DE
        "185.220.101.1",    # 100 - Tor exit
        "185.220.101.33",   # 100 - Tor exit
        "171.25.193.78",    # 100 - Tor exit
        "45.33.32.156",     # 11 - Linode US (abuso moderado)
    ]
    return random.choice(ips_demo)


def ru1_fuerza_bruta(verbose=True):
    print("\n[!] Simulando RU-1: Fuerza Bruta SSH...")
    ip_atacante = _ip_publica_demo()
    timestamp = obtener_timestamp_syslog()

    for i in range(15):
        # Formato exacto que espera tu Grok filter en Logstash
        mensaje = f"{timestamp} victima_ssh sshd[1024]: Failed password for root from {ip_atacante} port 50234 ssh2\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.1)

def ru2_acceso_nocturno(verbose=True):
    print("\n[!] Simulando RU-2: Acceso en horario anómalo...")
    # Usamos IP pública para que AbuseIPDB devuelva OSINT real (privadas dan vacío)
    ip_admin = _ip_publica_demo()
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

HOSTS_INTERNOS_RU6 = [
    "servidor_db", "servidor_web", "servidor_backup", "servidor_monitor",
    "servidor_ci", "servidor_files", "servidor_vpn", "servidor_dns",
]

def ru6_movimiento_lateral(verbose=True, n_hosts=6):
    """RU-6 (MITRE T1021.004): tras comprometer credenciales validas en un
    host, el atacante las reutiliza para autenticarse por SSH contra N hosts
    internos DISTINTOS en una ventana corta (pivoteo/reconocimiento
    post-compromiso). Reutiliza enviar_log/obtener_timestamp_diurno y el
    mismo formato "Accepted password" que ya parsea el grok de RU-2 en
    Logstash (unico cambio: el hostname varía evento a evento, en vez
    de ser siempre "victima_ssh"/"servidor_app"). Se mantiene en horario
    diurno a proposito: la senal de este ataque es la DIVERSIDAD de hosts
    por IP, no el horario (eso ya lo cubre RU-2).
    Devuelve la cantidad de eventos generados (= hosts atacados)."""
    ip_atacante = _ip_publica_demo()
    usuario = random.choice(["admin", "operador", "devops", "soporte"])
    hosts_elegidos = random.sample(HOSTS_INTERNOS_RU6, min(n_hosts, len(HOSTS_INTERNOS_RU6)))
    print(f"\n[!] Simulando RU-6: Movimiento Lateral SSH ({usuario}@{ip_atacante} -> {len(hosts_elegidos)} hosts)...")

    for host in hosts_elegidos:
        timestamp = obtener_timestamp_diurno()
        mensaje = f"{timestamp} {host} sshd[{random.randint(1000, 9999)}]: Accepted password for {usuario} from {ip_atacante} port {random.randint(40000, 60000)} ssh2\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.3)

    return len(hosts_elegidos)

def ru4_machine_learning():
    print("\n[!] Simulando RU-4: Motor ML (Isolation Forest)...")
    print("📊 Analizando entropía multidimensional...")
    time.sleep(1)

    score_anomalia = round(random.uniform(0.85, 0.99), 2)
    ip_sospechosa = _ip_publica_demo()

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

def escenario_configurable(n_ru1: int, n_ru2: int, n_ru3: int, verbose: bool = False,
                            n_ru6: int = 0, ru6_hosts: int = 6):
    """Genera un escenario con proporciones RU-1/RU-2/RU-3 configurables,
    manteniendo fijos el total de eventos anomalos (n_ru1+n_ru2+n_ru3) frente
    al ratio 85/15 organico/anomalo de Shiravi et al. usado en escenario_tesis().
    Permite variar la COMPOSICION interna de anomalias (fuerza bruta vs
    acceso nocturno/spike) sin alterar la tasa total de anomalias, para
    aislar el efecto de esa composicion en las metricas del motor ML.

    n_ru6: cantidad de INSTANCIAS de RU-6 (movimiento lateral) a inyectar;
    cada instancia genera ru6_hosts eventos (una IP contra ru6_hosts hosts
    distintos). Default 0 preserva el comportamiento previo del escenario
    (sin RU-6), para no alterar corridas ya publicadas que llamen a esta
    funcion sin el parametro nuevo."""
    print("\n" + "="*55)
    print("  🎓 ESCENARIO CONFIGURABLE (validacion RU-1 vs RU-2/RU-3/RU-6)")
    print(f"  RU-1={n_ru1}  RU-2={n_ru2}  RU-3={n_ru3}  RU-6(instancias)={n_ru6}")
    print("="*55)

    ip_atacante = _ip_publica_demo()
    for _ in range(n_ru1):
        timestamp = obtener_timestamp_syslog()
        mensaje = f"{timestamp} victima_ssh sshd[1024]: Failed password for root from {ip_atacante} port 50234 ssh2\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.1)

    for _ in range(n_ru2):
        ip_admin = _ip_publica_demo()
        timestamp_nocturno = datetime.now().strftime("%b %d 03:15:00")
        mensaje = f"{timestamp_nocturno} victima_ssh sshd[1025]: Accepted password for admin from {ip_admin} port 50235 ssh2\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.05)

    for _ in range(n_ru3):
        cpu_usage = random.randint(95, 99)
        ip_servidor = f"192.168.1.{random.randint(20, 30)}"
        timestamp = obtener_timestamp_syslog()
        mensaje = f"{timestamp} victima_ssh systemd[1]: METRICA ANOMALA: SPIKE_CPU detectado al {cpu_usage}% (Desviacion > 3 sigma) en host {ip_servidor}\n"
        enviar_log(mensaje, verbose=verbose)
        time.sleep(0.05)

    eventos_ru6 = 0
    for _ in range(n_ru6):
        eventos_ru6 += ru6_movimiento_lateral(verbose=verbose, n_hosts=ru6_hosts)

    eventos_anomalos = n_ru1 + n_ru2 + n_ru3 + eventos_ru6
    eventos_normales = round(eventos_anomalos * 85 / 15)
    inyectar_trafico_organico(eventos_normales, verbose=False)

    total = eventos_anomalos + eventos_normales
    pct_anom = round(eventos_anomalos / total * 100, 1)
    pct_norm = round(eventos_normales / total * 100, 1)

    print("\n" + "="*55)
    print("  ✅ ESCENARIO GENERADO")
    print(f"  RU-1: {n_ru1}  RU-2: {n_ru2}  RU-3: {n_ru3}  RU-6: {n_ru6} instancia(s) ({eventos_ru6} eventos)")
    print(f"  Eventos anomalos:  {eventos_anomalos:>3} ({pct_anom}%)")
    print(f"  Eventos normales:  {eventos_normales:>3} ({pct_norm}%)")
    print(f"  Total dataset:     {total:>3}")
    print("="*55)


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
        print("8. Ejecutar RU-6: Movimiento Lateral SSH")

        opcion = input("\nElige una opcion (1-8): ")

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
        elif opcion == '8':
            ru6_movimiento_lateral()
        else:
            print("\n❌ Opcion no valida.")

if __name__ == "__main__":
    import argparse
    _parser = argparse.ArgumentParser(add_help=False)
    _parser.add_argument("--configurable", action="store_true",
                          help="Genera escenario_configurable(ru1, ru2, ru3, n_ru6) y termina, sin menu interactivo")
    _parser.add_argument("--ru1", type=int, default=15)
    _parser.add_argument("--ru2", type=int, default=1)
    _parser.add_argument("--ru3", type=int, default=1)
    _parser.add_argument("--ru6", type=int, default=0, help="cantidad de instancias RU-6 (movimiento lateral)")
    _parser.add_argument("--ru6-hosts", type=int, default=6, help="hosts distintos por instancia RU-6")
    _args, _ = _parser.parse_known_args()

    if _args.configurable:
        escenario_configurable(_args.ru1, _args.ru2, _args.ru3, n_ru6=_args.ru6, ru6_hosts=_args.ru6_hosts)
    else:
        menu()