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