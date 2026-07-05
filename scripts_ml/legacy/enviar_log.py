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

print("Simulando ataque de fuerza bruta SSH (RU-1)...")

# Enviamos 15 intentos fallidos para disparar la anomalía
for i in range(15):
    ip_atacante = f"192.168.1.{random.randint(50, 60)}"
    mensaje = f"Fallo de inicio de sesion SSH desde IP {ip_atacante}\n"
    
    try:
        conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conexion.connect(('127.0.0.1', 5044))
        conexion.sendall(mensaje.encode('utf-8'))
        conexion.close()
        print(f"Log enviado: {mensaje.strip()}")
    except Exception as e:
        print(f"Error de conexión: {e} - ¿Están prendidos los contenedores?")
        
    time.sleep(0.5) # Pausa de medio segundo entre cada intento

print("¡Ataque simulado con éxito!")