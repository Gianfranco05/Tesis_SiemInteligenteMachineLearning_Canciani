# ══════════════════════════════════════════════════════════
# ⚠️  DEPRECADO — NO USAR
# Este script es un prototipo temprano y ya NO es compatible con
# config_logstash/logstash.conf actual: el formato de mensaje que
# envía no matchea los patrones Grok vigentes (falta timestamp
# syslog, falta 'sshd[pid]:', falta 'port N ssh2', etc), así que
# Logstash lo indexa en la rama CATCH-ALL sin extraer source_ip.
# Usá scripts_ml/simulador_ataques.py en su lugar (opción de menú
# 1, 2 o 3, o la opción 6 'ESCENARIO TESIS' para el dataset 85/15).
# Se conserva acá solo como registro histórico del proyecto.
# ══════════════════════════════════════════════════════════

import socket
import random

HOST = 'localhost'
PORT = 5044

def simular_pico_recursos():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        
        # Simulamos un consumo de CPU altísimo (95% a 99%)
        cpu_usage = random.randint(95, 99)
        ip_servidor = f"192.168.1.{random.randint(50, 60)}"
        
        # El log incluye la palabra clave "SPIKE_CPU" para que n8n lo encuentre fácil
        mensaje = f"METRICA ANOMALA: SPIKE_CPU detectado al {cpu_usage}% (Desviacion > 3 sigma) en host {ip_servidor}\n"
        
        sock.sendall(mensaje.encode('utf-8'))
        print(f"¡Pico de CPU simulado enviado! -> {mensaje.strip()}")
        
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Simulando pico de recursos (RU-3)...")
    simular_pico_recursos()