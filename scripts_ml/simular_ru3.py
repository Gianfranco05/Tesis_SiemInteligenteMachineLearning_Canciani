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