# SIEM Inteligente con Machine Learning
**UTN Facultad Regional Mendoza — Tecnicatura Universitaria en Programación**  
**Autor:** Gianfranco Canciani | **Directores:** Alberto Cortez y Ariel Enferrel

---

## ¿Qué es este proyecto?

Sistema SIEM (Security Information and Event Management) de código abierto con detección de anomalías mediante Machine Learning no supervisado (Isolation Forest + DBSCAN) y orquestación de respuesta automatizada (SOAR) a través de n8n.

---

## Estructura del repositorio

```
Final_proyecto_siem/
├── docker-compose.yml          # Infraestructura completa como código
├── config_logstash/
│   └── logstash.conf           # Pipeline de ingesta y parsing de logs
├── scripts_ml/
│   ├── motor_ml.py             # Motor ML real (Isolation Forest + DBSCAN)
│   ├── simulador_ataques.py    # Simulador interactivo para demo y pruebas
│   ├── requirements.txt        # Dependencias Python
│   └── pruebas_unitarias/      # Scripts de desarrollo (legacy)
│       ├── enviar_log.py
│       ├── simular_ru2.py
│       └── simular_ru3.py
├── n8n_data/                   # Datos de n8n (workflows, base SQLite)
└── README.md                   # Este archivo
```

---

## Requisitos previos

- Docker Desktop instalado y corriendo
- Docker Compose v2+
- Python 3.10+ (para correr los scripts desde tu PC)
- Aproximadamente 4 GB de RAM disponibles para el stack

---

## Levantar el stack completo

```bash
# Clonar o descomprimir el proyecto
cd Final_proyecto_siem

# Levantar todos los contenedores en segundo plano
docker compose up -d

# Verificar que todos estén corriendo
docker compose ps
```

**Servicios disponibles:**

| Servicio | URL | Descripción |
|---|---|---|
| Elasticsearch | http://localhost:9200 | Motor de búsqueda de logs |
| Logstash | localhost:5044 (TCP) | Ingesta de logs |
| n8n | http://localhost:5678 | Orquestador SOAR |
| Grafana | http://localhost:3000 | Dashboards |
| PostgreSQL | localhost:5432 | Auditoría (user: admin / pass: 1234) |
| Víctima SSH | localhost:2222 | Servidor de pruebas RU-1 |

---

## Flujo de demostración paso a paso

### Paso 1 — Instalar dependencias Python (una sola vez)

```bash
pip install -r scripts_ml/requirements.txt
```

### Paso 2 — Inyectar logs de prueba con el simulador

```bash
python scripts_ml/simulador_ataques.py
```

El menú interactivo permite simular:
- **Opción 1:** RU-1 — Fuerza bruta SSH (15 intentos fallidos)
- **Opción 2:** RU-2 — Acceso exitoso en horario anómalo (madrugada)
- **Opción 3:** RU-3 — Pico de CPU (>3 sigma)
- **Opción 4:** RU-4 — Disparo directo del webhook ML (para demo SOAR)

Ejecutar las opciones 1, 2 y 3 para poblar Elasticsearch con datos reales.

### Paso 3 — Correr el motor ML real

```bash
python scripts_ml/motor_ml.py
```

El motor:
1. Extrae logs de Elasticsearch (últimos 30 minutos)
2. Construye features numéricas por evento
3. Corre Isolation Forest (contamination=0.05)
4. Corre DBSCAN (eps=0.5, min_samples=5)
5. Fusiona predicciones (lógica OR)
6. Calcula Precision, Recall y F1-Score reales
7. Envía la anomalía más severa al webhook de n8n

**Modo continuo (cada 60 segundos):**
```bash
python scripts_ml/motor_ml.py --loop
```

### Paso 4 — Verificar en n8n

1. Abrir http://localhost:5678
2. El workflow **RU-4: Machine Learning** debe estar activo
3. Cuando el motor ML detecta una anomalía, n8n la procesa y envía alerta a Telegram

---

## Activar los workflows en n8n

Por defecto los workflows están desactivados. Para activarlos:

1. Ir a http://localhost:5678
2. Entrar a cada workflow
3. Click en el toggle "Active" (arriba a la derecha)
4. Activar: RU-1, RU-2, RU-3, RU-4 y Reporte Matutino

---

## Correr el motor ML desde el contenedor Docker

Si preferís no instalar Python en tu PC:

```bash
# Entrar al contenedor
docker exec -it siem_ml bash

# Instalar dependencias dentro del contenedor
pip install -r /app/requirements.txt

# Correr el motor (dentro del contenedor, usar nombre de servicio Docker)
ES_HOST=http://elasticsearch:9200 WEBHOOK_URL=http://siem_n8n:5678/webhook/alerta-ml python /app/motor_ml.py
```

---

## Apagar el stack

```bash
docker compose down          # Apaga contenedores (los datos persisten en volumes)
docker compose down -v       # Apaga Y elimina todos los datos (reset total)
```

---

## Nota sobre credenciales

Este proyecto es una **Prueba de Concepto (PoC) académica**. Las credenciales están hardcodeadas en `docker-compose.yml` intencionalmente para facilitar la reproducibilidad del entorno de laboratorio. En un despliegue de producción se usaría un archivo `.env` excluido del repositorio.
