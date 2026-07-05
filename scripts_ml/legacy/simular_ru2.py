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
import time
import random

# Configuración de la conexión a Logstash
HOST = 'localhost'
PORT = 5044

def simular_acceso_nocturno():
    try:
        # Nos conectamos a Logstash
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        
        # Simulamos una IP interna de un empleado (ej: la de un administrador)
        ip_admin = f"192.168.1.{random.randint(10, 15)}"
        
        # Generamos el log de acceso EXITOSO
        mensaje = f"Inicio de sesion EXITOSO SSH del usuario root desde IP {ip_admin}\n"
        
        # Lo enviamos al SIEM
        sock.sendall(mensaje.encode('utf-8'))
        print(f"¡Alerta simulada enviada! -> {mensaje.strip()}")
        
        sock.close()
    except Exception as e:
        print(f"Error de conexión con Logstash: {e}")

if __name__ == "__main__":
    print("Simulando acceso exitoso (RU-2)...")
    simular_acceso_nocturno()