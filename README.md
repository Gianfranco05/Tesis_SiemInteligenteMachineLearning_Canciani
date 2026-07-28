# SIEM Inteligente con Machine Learning
**UTN Facultad Regional Mendoza — Tecnicatura Universitaria en Programación**
**Autor:** Gianfranco Canciani | **Directores:** Alberto Cortez y Ariel Enferrel

> ⚠️ Este proyecto fue corregido tras una revisión de código. Ver
> `CHANGELOG.md` para el detalle completo de qué cambió y por qué.

Esta guía cubre TODO el ciclo: levantar el stack, verificar que cada
pieza esté sana, probar cada regla de detección **por separado**, y
finalmente probar el sistema **completo, de punta a punta**, como lo
vería un tribunal en una demo en vivo.

---

## Índice

1. [Requisitos previos](#1-requisitos-previos)
2. [Configuración inicial](#2-configuración-inicial)
3. [Levantar el stack](#3-levantar-el-stack)
4. [Checklist de salud de cada servicio](#4-checklist-de-salud-de-cada-servicio)
5. [Importar y configurar los workflows en n8n](#5-importar-y-configurar-los-workflows-en-n8n)
6. [Probar cada componente por separado](#6-probar-cada-componente-por-separado)
7. [Prueba integral: todo el sistema funcionando junto](#7-prueba-integral-todo-el-sistema-funcionando-junto)
8. [Medir MTTD/MTTR reales (el experimento de la tesis)](#8-medir-mttdmttr-reales)
9. [Troubleshooting — errores comunes](#9-troubleshooting--errores-comunes)
10. [Apagar y resetear](#10-apagar-y-resetear)
11. [Día de la defensa — checklist final](#11-día-de-la-defensa--checklist-final)

---

## 1. Requisitos previos

- Docker Desktop instalado y corriendo (Docker Compose v2+)
- Python 3.10+ en tu PC
- ~4 GB de RAM libres para el stack completo
- Una API key gratuita de AbuseIPDB → https://www.abuseipdb.com/account/api
- Un bot de Telegram creado con @BotFather y tu `chat_id` (Anexo E de la tesis)
- Cliente de PostgreSQL (opcional pero recomendado): `psql` o DBeaver/pgAdmin

---

## 2. Configuración inicial

```bash
cd Final_proyecto_siem
cp .env.example .env
```

Editá `.env` y completá **como mínimo**:

| Variable | Cómo conseguirla |
|---|---|
| `ABUSEIPDB_KEY` | Panel de AbuseIPDB → API |
| `TELEGRAM_CHAT_ID_DEFAULT` | Hablale a tu bot, después `curl https://api.telegram.org/bot<TOKEN>/getUpdates` |
| `POSTGRES_PASSWORD` | Elegí una vos |
| `SSH_PASSWORD` | Elegí una vos |

`.env` está en `.gitignore` — nunca se sube al repo. Si en algún momento
tenías una key vieja circulando en un commit, rotala en AbuseIPDB antes
de seguir.

Instalá las dependencias de Python que vas a usar desde tu PC:

```bash
pip install -r scripts_ml/requirements.txt
```

---

## 3. Levantar el stack

```bash
docker compose up -d
```

La primera vez tarda unos minutos (descarga imágenes + PostgreSQL corre
los scripts de `init_db/`). El motor ML (`ml-python`) se instala solo y
arranca en modo `--loop` automáticamente — no hace falta entrar a mano.

Mirá que todo esté `Up` (o `Up (healthy)`):

```bash
docker compose ps
```

Salida esperada (nombres de contenedor, no de servicio):

```
NAME                 STATUS
siem_elasticsearch   Up (healthy)
siem_logstash        Up
siem_syslog          Up
siem_n8n             Up
siem_grafana         Up
siem_postgres        Up (healthy)
siem_ml              Up
victima_ssh          Up
```

Si algo no dice `Up`, andá directo a la sección [Troubleshooting](#9-troubleshooting--errores-comunes).

---

## 4. Checklist de salud de cada servicio

Antes de tocar workflows ni simular nada, confirmá que cada pieza de
infraestructura responde. Esto lleva 2 minutos y te ahorra confundir
"n8n no anda" con "todavía no importé el workflow".

### 4.1 Elasticsearch
```bash
curl -s http://localhost:9200 | python3 -m json.tool
```
✅ Esperado: JSON con `"cluster_name"` y `"status":"green"` o `"yellow"`.

### 4.2 Logstash (¿está escuchando en el 5044?)
```bash
nc -zv localhost 5044
```
✅ Esperado: `Connection to localhost 5044 port [tcp/*] succeeded!`

### 4.3 PostgreSQL — ¿existen las tablas?
```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem -c "\dt"
```
✅ Esperado: ver listadas `alertas_fuerza_bruta`, `alertas_accesos_nocturnos`,
`alertas_spikes_recursos`, `alertas_ml`, `analistas_registrados`,
`experimento_latencias`, `respuestas_aplicadas`.

*(Usá el usuario/base que hayas puesto en `.env`; el ejemplo asume los
valores por defecto.)*

### 4.4 n8n
Abrí http://localhost:5678 en el navegador — debería cargar la UI sin pedir login.

### 4.5 Grafana
Abrí http://localhost:3000 (usuario/clave por defecto: `admin`/`admin`,
te va a pedir cambiarla al entrar).

### 4.6 Motor ML — ¿está corriendo el loop?
```bash
docker compose logs -f ml-python
```
✅ Esperado, cada `LOOP_SECONDS` (5s por defecto), algo como:
```
[INFO] Ciclo ML completado exitosamente. Eventos analizados: 0
```
Si ves `NameResolutionError` o `ConnectionRefusedError` repetidas veces,
esperá un minuto más (Elasticsearch puede tardar en estar listo) y si
persiste, revisá la sección de Troubleshooting.
Salí con `Ctrl+C` (no apaga el contenedor, solo el `logs -f`).

### 4.7 Víctima SSH — ¿responde y puede correr iptables?
```bash
docker exec -it victima_ssh sh -c "sudo iptables -L INPUT -n"
```
✅ Esperado: una tabla vacía o con reglas previas, sin error de permisos.

---

## 5. Importar y configurar los workflows en n8n

1. Abrí http://localhost:5678
2. Para cada uno de los 7 archivos en `workflows/`: **Import from File**
3. La primera vez que abrís cada workflow, n8n te va a pedir que
   asignes credenciales en los nodos Postgres / SSH / Telegram (los
   `credentials.id` del JSON son de la instancia original de Gianfranco,
   no de la tuya). Configurá:
   - **Postgres account** → host `postgres` (nombre del servicio dentro
     de la red de Docker), usuario/clave/db según tu `.env`
   - **SSH Password account** → host `victima_ssh`, puerto `2222`,
     usuario/clave según tu `.env`
   - **Telegram account** → el token de tu bot (@BotFather)
4. Confirmá que los 7 workflows queden con el toggle **Active** en
   verde (ya vienen con `"active": true` en el JSON, pero conviene
   verificarlo con tus propios ojos):
   - `RU1 siem` — Schedule Trigger cada 1 minuto
   - `RU2 siem` — Schedule Trigger cada 1 minuto
   - `RU3 siem` — Schedule Trigger cada 1 minuto
   - `RU4: Deteccion ML` — Webhook
   - `RU4: Respuesta` — Telegram Trigger
   - `RU5 Reporte Ejecutivo Matutino` — Cron diario 08:00
   - `Registro siem` — Telegram Trigger

**Antes de seguir:** si tu n8n corre en Docker sin dominio público fijo,
necesitás exponerlo a internet para que Telegram le pueda mandar los
callbacks de los botones. La forma más simple para pruebas:

```bash
ngrok http 5678
```

Copiá la URL HTTPS que te da ngrok y actualizá `N8N_WEBHOOK_URL` en tu
`.env`, después:

```bash
docker compose restart n8n
```

*(Recordá que el plan gratuito de ngrok cambia la URL cada vez que lo
reiniciás — hay que repetir este paso.)*

---

## 6. Probar cada componente por separado

La idea de esta sección es aislar cada regla y confirmar, una por una,
que el camino completo "log → Logstash → Elasticsearch → n8n →
PostgreSQL (→ Telegram → SSH)" funciona antes de probar todo junto.

### 6.1 RU-1 — Fuerza bruta SSH

```bash
python scripts_ml/simulador_ataques.py
# elegí la opción 1 (Fuerza Bruta SSH)
```

Esperá hasta 1 minuto (el Schedule Trigger de RU-1 corre cada 60s) y
verificá:

```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM alertas_fuerza_bruta ORDER BY fecha DESC LIMIT 3;"
```
✅ Esperado: una fila nueva con fecha reciente.

```bash
docker exec -it victima_ssh sh -c "sudo iptables -L INPUT -n"
```
✅ Esperado: una regla `DROP` nueva con la IP que usó el simulador (por
defecto `203.0.113.66`, revisá `simulador_ataques.py` si la cambiaste).

### 6.2 RU-2 — Acceso nocturno

```bash
python scripts_ml/simulador_ataques.py
# opción 2 (Acceso Exitoso Fuera de Horario)
```

Esperá hasta 1 minuto y verificá:

```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM alertas_accesos_nocturnos ORDER BY fecha DESC LIMIT 3;"
```
✅ Esperado: una fila nueva. Si no aparece nada, revisá en Elasticsearch
que el campo `hora_evento` se haya extraído bien:

```bash
curl -s "http://localhost:9200/eventos-seguridad-*/_search?q=rule.name:RU-2&size=1&sort=@timestamp:desc" \
  | python3 -m json.tool | grep -A2 hora_evento
```
✅ Esperado: `"hora_evento": 3` (o la hora nocturna que haya generado el
simulador), **no** la hora actual del reloj.

### 6.3 RU-3 — Pico de CPU

```bash
python scripts_ml/simulador_ataques.py
# opción 3 (Pico de Consumo de CPU)
```

```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM alertas_spikes_recursos ORDER BY fecha DESC LIMIT 3;"
```
✅ Esperado: una fila nueva dentro del minuto.

### 6.4 RU-4 — Motor de Machine Learning + HITL (la más importante)

Esta es la que integra más piezas: motor ML → webhook → Postgres →
AbuseIPDB → Telegram → click del analista → SSH → auditoría.

**Paso A — Generar la ráfaga que dispara `freq_ip`:**
```bash
python scripts_ml/simulador_ataques.py
# opción 1 otra vez (15 eventos de la misma IP = freq_ip >= 5)
```

**Paso B — Esperar al motor ML** (corre cada `LOOP_SECONDS`, 5s por defecto — se optimizó de 30s a 5s tras el experimento inicial, ver `CHANGELOG.md`):
```bash
docker compose logs -f ml-python
```
✅ Esperado: una línea de log mencionando la IP y un score de riesgo,
y el envío del POST al webhook de n8n.

**Paso C — Confirmar el insert en `alertas_ml`:**
```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM alertas_ml ORDER BY fecha DESC LIMIT 3;"
```

**Paso D — Revisar Telegram.** Deberías recibir un mensaje con:
- Algoritmo, IP atacante, score de riesgo
- Datos de AbuseIPDB (país, score de abuso, ISP) — en IPs privadas
  (192.168.x.x) estos campos van a venir vacíos/null, es esperable
  (ver Anexo J.9 de la tesis)
- Dos botones: **🛑 Bloquear IP** / **✅ Ignorar**

**Paso E — Presioná "Bloquear IP".**

**Paso F — Confirmar el bloqueo real:**
```bash
docker exec -it victima_ssh sh -c "sudo iptables -L INPUT -n"
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM respuestas_aplicadas ORDER BY aplicada_en DESC LIMIT 3;"
```
✅ Esperado: la IP bloqueada en iptables **y** una fila nueva en
`respuestas_aplicadas` (esto es lo que antes no existía — ver
`CHANGELOG.md`). También deberías recibir un mensaje de confirmación
por Telegram.

**Paso G — Probar la rama "Ignorar":** repetí A-D con otra IP y esta
vez tocá "✅ Ignorar". Verificá que llega el mensaje "Alerta descartada"
y que **no** aparece ninguna fila nueva en `respuestas_aplicadas` ni
regla nueva en `iptables`.

### 6.5 Registro multiusuario (`/start`)

Desde OTRO usuario/celular de Telegram (o el mismo, para probar rápido),
mandale `/start` a tu bot.

```bash
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM analistas_registrados;"
```
✅ Esperado: fila nueva con el `chat_id` y el nombre de quien mandó `/start`,
y una respuesta de bienvenida en el chat.

### 6.6 RU-5 — Reporte Ejecutivo Matutino

Como corre a las 08:00 AM por cron, para probarlo sin esperar hasta
mañana: abrí el workflow `RU5 Reporte Ejecutivo Matutino` en n8n y
usá el botón **"Execute workflow"** manualmente (esto no rompe nada,
solo salta el disparador de horario).

✅ Esperado: mensaje HTML en Telegram con el resumen de las últimas 24hs
(conteo de RU-1 a RU-4), enviado a **todos** los `chat_id` que estén en
`analistas_registrados` (por eso conviene haber hecho la prueba 6.5
primero, así hay al menos un destinatario registrado).

---

## 7. Prueba integral: todo el sistema funcionando junto

Una vez que probaste cada regla por separado y anda, esta es la prueba
que deberías mostrar en la defensa: el "Escenario Tesis" completo, que
simula 96 eventos de tráfico orgánico + 17 eventos anómalos (15 fuerza
bruta, 1 acceso nocturno, 1 pico de CPU) en la proporción 85/15 que
describe la Sección 3.8 de la tesis.

```bash
python scripts_ml/simulador_ataques.py
# opción 6: ESCENARIO TESIS
```

**Qué deberías ver, en este orden, en los siguientes ~2 minutos:**

1. **Elasticsearch:** los 113 eventos indexados.
   ```bash
   curl -s "http://localhost:9200/eventos-seguridad-*/_count" | python3 -m json.tool
   ```
2. **PostgreSQL:** filas nuevas en `alertas_fuerza_bruta`,
   `alertas_accesos_nocturnos` y `alertas_spikes_recursos` (las reglas
   estáticas RU-1/2/3, corriendo cada 1 minuto).
3. **Motor ML:** en los logs de `ml-python`, un ciclo que reporta
   Precisión / Recall / F1 sobre el batch — comparalo contra lo
   documentado en el Anexo J.8 de la tesis (F1 ≈ 0.81–0.89).
4. **Telegram:** la alerta RU-4 con botones (para el evento de fuerza
   bruta que también dispara `freq_ip >= 5`).
5. **Grafana:** abrí un dashboard apuntando al índice
   `eventos-seguridad-*` y deberías ver el pico de eventos recién
   ingestados en el gráfico de series temporales.
6. **PostgreSQL de nuevo**, después de presionar "Bloquear IP" en el
   paso 4: fila nueva en `respuestas_aplicadas`.

Si los 6 puntos se cumplen, tenés el pipeline completo validado de
punta a punta: ingesta → parsing → detección estática → detección ML →
enriquecimiento OSINT → notificación → decisión humana → mitigación →
auditoría inmutable. Ese es el ciclo completo que describe el Capítulo 4
de la tesis.

### Guardá evidencia de esta corrida

Para la defensa conviene tener capturas/registros de esta prueba integral:

```bash
docker compose logs ml-python > evidencia_motor_ml.log
docker exec -it siem_postgres psql -U admin -d tesis_siem \
  -c "SELECT * FROM alertas_ml ORDER BY fecha DESC LIMIT 10;" > evidencia_alertas_ml.txt
```

Y una captura de pantalla de Telegram con la alerta y del dashboard de
Grafana con los datos recién ingestados.

---

## 8. Medir MTTD/MTTR reales

Esto ya es la validación estadística de la Sección 5.1.2 de la tesis
(30 iteraciones por grupo, prueba T de Student). Tiene su propia guía
detallada en **`README_experimento.md`** — hacé la prueba integral de
la Sección 7 de este documento primero, y cuando confirmes que todo el
pipeline funciona, pasá a esa guía para generar los números finales.

Resumen rápido:
```bash
python scripts_ml/medir_latencias.py --grupo automatizado --n 30
python scripts_ml/medir_latencias.py --grupo manual --n 30
python scripts_ml/analizar_experimento.py
```

---

## 9. Troubleshooting — errores comunes

| Síntoma | Causa probable | Solución |
|---|---|---|
| `docker compose ps` muestra `siem_postgres` reiniciando en loop | Puerto 5432 ocupado por otro Postgres en tu PC | Cambiar el mapeo de puerto en `docker-compose.yml` (ej. `"5433:5432"`) o parar el otro servicio |
| `ml-python` en loop de `NameResolutionError` | Corriste `motor_ml.py` desde tu PC sin exportar `ES_HOST` | Ver comando exacto en el Paso 4 del `README.md` original / usar `ES_HOST=http://localhost:9200` |
| Los botones de Telegram no responden nada | n8n no tiene una URL pública HTTPS válida | Levantar `ngrok http 5678`, actualizar `N8N_WEBHOOK_URL` en `.env`, `docker compose restart n8n` |
| RU-1/RU-2/RU-3 nunca insertan nada aunque simulaste el ataque | El workflow no está `Active`, o las credenciales de Postgres/SSH no están configuradas en n8n | Revisar el toggle Active y las credenciales de cada nodo (Sección 5) |
| RU-4 no llega nunca a Telegram | El motor ML no está corriendo, o `WEBHOOK_URL` del contenedor `ml-python` está mal | `docker compose logs ml-python`; confirmar variables en `docker-compose.yml` |
| AbuseIPDB devuelve todo `null` | Estás simulando con IPs privadas (192.168.x.x) | Esperado en laboratorio — ver Anexo J.9 de la tesis. Con IPs públicas reales sí trae datos. |
| El bloqueo SSH falla con "Permission denied" | Usuario/clave de SSH mal configurados en la credencial de n8n, o `SUDO_ACCESS` no está habilitado en `victima_ssh` | Revisar `.env` (`SSH_USER`/`SSH_PASSWORD`) y que la credencial en n8n coincida |
| `medir_latencias.py` da timeout siempre en la detección | El motor ML no está en `--loop`, o `LOGSTASH_HOST`/`PG_HOST` mal seteados en tu shell | Confirmar `docker compose logs ml-python`; exportar las variables como en el Paso 3 de `README_experimento.md` |

---

## 10. Apagar y resetear

```bash
docker compose down          # Apaga los contenedores, los datos persisten en los volumes
docker compose down -v       # Apaga Y borra todos los datos (reset total, incluye PostgreSQL)
```

Si hiciste `down -v`, la próxima vez que levantes el stack, PostgreSQL
va a volver a correr los scripts de `init_db/` desde cero (tablas
vacías) y vas a tener que volver a activar los workflows en n8n.

---

## 11. Día de la defensa — checklist final

Esto es lo que efectivamente ya está validado con evidencia real (no solo
simulada), y el orden recomendado para mostrarlo en vivo si el tribunal
pide una demo. No hace falta mostrar los 3 niveles — con el primero y el
Escenario Tesis alcanza; los otros son as respaldo si preguntan "¿esto solo
funciona con datos armados a medida?".

### 11.1 La noche/mañana anterior

```bash
docker compose up -d
docker compose ps          # todo Up/Up (healthy)
```

Dejalo levantado un rato antes de la defensa — Elasticsearch y el motor
ML tardan un par de minutos en estabilizarse la primera vez.

Confirmá credenciales de n8n (Postgres/SSH/Telegram) siguen configuradas
en los 7 workflows (Sección 5) y que `ngrok` (si lo usás) tiene una URL
activa reflejada en `N8N_WEBHOOK_URL` del `.env` — el plan gratuito la
cambia cada reinicio, es el error más tonto y más común el día de la
demo.

### 11.2 La demo principal: Escenario Tesis (Sección 7)

```bash
python scripts_ml/simulador_ataques.py
# opción 6: ESCENARIO TESIS
```

Mostrá en este orden: conteo en Elasticsearch → filas nuevas en
PostgreSQL (RU-1/2/3) → log del motor ML con Precisión/Recall/F1 →
alerta con botones en Telegram → apretás "Bloquear IP" → fila nueva en
`respuestas_aplicadas` → dashboard de Grafana con el pico de eventos.
Ver el detalle completo en la Sección 7 de arriba.

### 11.3 Si preguntan "¿y con tráfico real, no solo simulado?"

Tenés evidencia real de esto, documentada en `CHANGELOG.md`
("🟢 Validación con tráfico real"): se atacó el `sshd` **real** del
contenedor `victima_ssh` con un cliente SSH genuino (no el simulador),
y el ataque fue detectado y bloqueado de punta a punta. Para
reproducirlo en vivo (opcional, más impresionante pero más pasos):

```bash
docker exec -d victima_ssh sh -c "tail -F -n 0 /config/logs/openssh/current | nc logstash 5044"
ssh baduser@localhost -p 2222   # password incorrecta, repetir 3-4 veces
# esperar ~65s
docker exec -it siem_postgres psql -U admin -d tesis_siem -c "SELECT * FROM alertas_fuerza_bruta ORDER BY fecha DESC LIMIT 3;"
docker exec -it victima_ssh sh -c "iptables -L INPUT -n"
```

También se validó que tráfico de red real/orgánico (no ataques) **no**
dispara falsos positivos, vía `syslog-ng` (config en
`config_syslog-ng/syslog-ng.conf`) — recibe en `514/udp` y `601/tcp` y
reenvía a Logstash. Este nivel está funcional pero pendiente de una
prueba final con una máquina físicamente distinta de la red (ver
`CHANGELOG.md`, sección Nivel 2).

### 11.4 Los números que vas a citar (ya finales, no van a cambiar)

- **MTTD**: reducción del **85.7%** (24.85s manual → 3.56s automatizado)
- **MTTR**: reducción del **51.6%** (11.67s manual → 5.64s automatizado)
- Ambos con significancia estadística vía **Mann-Whitney U** (p<0.00001
  en ambos casos) — se usó esta prueba no paramétrica en vez de Student/
  Welch porque Shapiro-Wilk mostró no-normalidad en al menos un grupo
  para cada métrica. Ver Sección 5.1.2 de la tesis para el detalle
  completo (Welch se reporta como robustez adicional para MTTR).

### 11.5 Antes de salir de tu casa

- [ ] Rotaste la API key de AbuseIPDB (✅ ya hecho)
- [ ] El documento de la tesis tiene aplicados todos los reemplazos de
      `Correcciones_Pendientes_Tesis.docx` (abstract, objetivo específico,
      metodología, Sección 5.1.2, Tabla 1, conclusiones 6.1, Anexos C/D/G)
- [ ] Hiciste un Ctrl+F final en el documento buscando restos de números
      viejos: `38%`, `19.06`, `10.75`, `t = 8.10`, `df ≈ 29.7`,
      `período de dos semanas` — no debería aparecer ninguno
- [ ] `git push` hecho, el repo de GitHub refleja el estado actual
- [ ] Cargaste batería en el celular con Telegram — lo vas a necesitar
      para la demo de RU-4/HITL

---

## Estructura del repositorio

```
Final_proyecto_siem/
├── docker-compose.yml
├── .env.example
├── config_logstash/logstash.conf
├── init_db/
│   ├── 01_schema.sql
│   └── 01_schema_experimento.sql
├── scripts_ml/
│   ├── motor_ml.py
│   ├── simulador_ataques.py
│   ├── medir_latencias.py
│   ├── medir_grupo_manual.py
│   ├── analizar_experimento.py
│   ├── verificar_pg.py
│   ├── requirements.txt
│   └── legacy/            # scripts viejos, no usar
├── workflows/              # 7 workflows de n8n
├── CHANGELOG.md            # detalle de la corrección aplicada
├── README.md               # esta guía (setup + pruebas)
└── README_experimento.md   # guía específica del experimento MTTD/MTTR
```
