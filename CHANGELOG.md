# CHANGELOG — Corrección post-revisión de código

Resumen de todos los cambios aplicados al proyecto, archivo por archivo,
en respuesta a la revisión de código. Usalo como registro para la
defensa si te preguntan "¿qué corregiste y por qué?".

## 🔴 Críticos

### `workflows/RU4_ Deteccion ML.json`
- Se eliminó la API key de AbuseIPDB hardcodeada en texto plano.
  Ahora el nodo HTTP Request la lee de `{{ $env.ABUSEIPDB_KEY }}`.
- Se eliminó el `chatId` de Telegram hardcodeado (`7447493101`). Ahora
  usa `{{ $env.TELEGRAM_CHAT_ID_DEFAULT }}`.
- **Acción pendiente de tu parte:** rotar/regenerar la key vieja en el
  panel de AbuseIPDB, porque circuló en un commit local y en un zip.

### `workflows/RU4_ Respuesta.json`
- Se agregó el nodo **"Registrar Respuesta Real (T2)"** (Postgres
  Insert) inmediatamente después de "Execute a command" (el bloqueo
  SSH), que inserta en `respuestas_aplicadas` el momento exacto en que
  se ejecuta el bloqueo.
- Se agregó un nodo de confirmación por Telegram ("Send a text
  message3") que antes no existía: el flujo terminaba en silencio
  después de bloquear.

### `scripts_ml/medir_latencias.py`
- Se eliminó por completo `mttr_segundos = random.uniform(9.5, 12.0)`.
- `corrida_automatizada()` ahora hace polling real sobre
  `respuestas_aplicadas` para obtener el T2 verdadero (igual que ya
  hacía sobre `alertas_ml` para el T1).
- El polling de T1 y T2 ahora es por IP específica (antes era un
  conteo global de filas, menos preciso si corrían cosas en paralelo).
- La IP del ataque ahora es aleatoria en cada iteración (antes era fija:
  `203.0.113.66` en las 30 iteraciones), para no acumular `freq_ip`
  artificialmente entre iteraciones y preservar la independencia de las
  muestras que exige la prueba T de Student.
- Se agregaron timeouts explícitos y mensajes claros de qué está
  esperando el script en cada momento (detección del motor ML vs. tu
  click en Telegram).

## 🔵 Optimización post-experimento (ronda 2)

### `docker-compose.yml`
- `LOOP_SECONDS` del servicio `ml-python` pasó de `30` a `5`. La primera
  corrida completa del experimento MTTD/MTTR (30+30 iteraciones, motor
  ML con sondeo cada 30s) arrojó una mejora de solo 4.2% en MTTD —
  estadísticamente significativa por el tamaño de muestra (Mann-Whitney
  p=0.026) pero sin relevancia operativa. El análisis reveló que el
  cuello de botella no era el algoritmo de detección sino la cadencia
  de sondeo del motor: un evento podía esperar hasta 30s a que arrancara
  el próximo ciclo antes de ser evaluado. Al bajar el intervalo a 5s y
  remedir el grupo automatizado íntegramente, el MTTD cayó de 24.85s a
  3.56s (reducción del 85.7%, Mann-Whitney U=900.0, p<0.00001).

### `scripts_ml/analizar_experimento.py`
- Sin cambios de código, pero se corrió de nuevo sobre el dataset final
  (post-optimización de LOOP_SECONDS). Los números que reemplazan a los
  de la corrida anterior: MTTR 11.67s → 5.64s (−51.6%, Mann-Whitney
  U=849.0, p<0.00001, Welch t=6.67 df≈33 IC95%[4.19,7.86]s); MTTD 24.85s
  → 3.56s (−85.7%, Mann-Whitney U=900.0, p<0.00001). Shapiro-Wilk mostró
  no-normalidad en al menos un grupo para ambas métricas, por lo que el
  test primario reportado es Mann-Whitney U (no paramétrico), no Welch.

## 🟢 Validación con tráfico real (no simulado)

### `config_logstash/logstash.conf`
- El grok de RU-1 solo aceptaba el formato sintético que genera
  `simulador_ataques.py` (syslog clásico con hostname y `sshd[pid]:`).
  Se agregó un segundo patrón que además acepta el log NATIVO real de
  `sshd` tal como lo emite el contenedor `victima_ssh` vía `s6-log`
  (timestamp ISO de alta precisión, sin hostname ni pid, con "invalid
  user X" opcional cuando el usuario no existe).

### `victima_ssh/Dockerfile`, `victima_ssh/custom-cont-init.d/10-sudo-nopasswd.sh`
- Ambos archivos tenían terminadores CRLF (probablemente introducidos
  por Git en Windows sin `.gitattributes`), que rompían la ejecución
  del script de NOPASSWD dentro del contenedor Alpine
  (`$'\r': command not found`, `syntax error: unexpected end of
  file`). Esto dejaba `sudo` pidiendo contraseña de nuevo — el mismo
  bug que ya se había corregido antes — y habría hecho fallar
  silenciosamente el bloqueo por iptables de RU-1 y RU-4. Se
  convirtieron a LF y se agregó `.gitattributes` (`eol=lf` para
  `*.sh`, `Dockerfile`, `*.conf`) para que no vuelva a pasar.

### Validación end-to-end con ataque SSH real
- Se ejecutó un ataque de fuerza bruta SSH **real** (no el simulador)
  contra `victima_ssh:2222` usando `paramiko`, generando intentos
  fallidos genuinos de `sshd`.
- Se armó un reenviador (`tail -F /config/logs/openssh/current | nc
  logstash 5044`) para llevar el log real, sin modificar, hasta
  Logstash.
- Cadena verificada de punta a punta con timestamps frescos: log real
  de sshd → Logstash (grok matcheó como RU-1, no cayó en CATCH-ALL) →
  Elasticsearch → n8n (Schedule Trigger detectó y consultó) →
  PostgreSQL (`alertas_fuerza_bruta`, filas nuevas) → bloqueo real en
  `iptables` de la IP de origen genuina (la del gateway de Docker,
  `172.19.0.1`, vista por el contenedor).
- Esto confirma que el pipeline no depende de las particularidades del
  formato sintético del simulador: reconoce y responde a tráfico SSH
  real de la misma manera.

### `config_syslog-ng/syslog-ng.conf` (NUEVO) + `docker-compose.yml` — Nivel 2
- El servicio `syslog-ng` existía pero estaba **huérfano**: sin config
  propia y con un mapeo de puertos roto. La imagen `linuxserver/syslog-ng`
  corre como usuario no-root y escucha internamente en `5514/udp` y
  `6601/tcp`, pero el compose mapeaba `514:514` y `601:601` — es decir,
  hacia puertos donde **nada escuchaba**.
- Se creó `config_syslog-ng/syslog-ng.conf` (montada como volumen `:ro`)
  que recibe syslog de red y lo **reenvía a `logstash:5044`** (TCP plano,
  una línea por evento, template que reconstruye la línea syslog clásica
  con `$ISODATE $HOST programa[pid]: mensaje`).
- Se corrigió el mapeo del compose a `514:5514/udp` y `601:6601/tcp` (los
  equipos de la red siguen apuntando a los puertos estándar 514/601) y se
  agregó `depends_on: logstash`.
- `keep-hostname(yes)` en las fuentes de red: conserva el hostname que la
  máquina emisora pone en el mensaje (workstation01, router-borde, ...) en
  vez de sobrescribirlo con la IP del emisor.
- **Validación (paso 1, tráfico sintético):** se enviaron 6 mensajes syslog
  orgánicos benignos (systemd, dhcpd, sudo, nginx, CRON, kernel) por
  TCP/601 y UDP/514. Los 6 llegaron a Elasticsearch y **todos cayeron en
  CATCH-ALL** — cero falsos positivos de RU-1/RU-2/RU-3 con tráfico
  sintético no malicioso.
- **Validación (paso 2, máquina físicamente separada — cierre del Nivel 2):**
  se creó una VM Ubuntu Server 24.04 en VirtualBox (red NAT), independiente
  del stack Docker del SIEM, con `rsyslog` configurado para reenviar todo
  su tráfico (`/etc/rsyslog.d/60-forward-to-siem.conf`, regla
  `*.* @10.0.2.2:514`) al host donde corre `syslog-ng` en el puerto
  514/UDP. Se generó un evento real con `logger` desde la VM y se verificó
  en Kibana (Discover, índice `eventos-seguridad-*`) que llegó correctamente
  a Elasticsearch: `rule.name: CATCH-ALL`, `event.category: unknown`,
  `message` con el hostname real de la VM (`siem-cliente-real`). Esto
  confirma que el pipeline de ingesta funciona con tráfico de red genuino,
  originado en un sistema operativo separado del stack Docker, no solo con
  datos inyectados por scripts dentro del mismo host — y sin generar
  falsos positivos.
- **Validación (paso 3, ataque real desde máquina externa):** usando la
  misma VM, se lanzó un ataque de fuerza bruta SSH real (`sshpass` + `ssh`,
  5 intentos con contraseña incorrecta) contra `victima_ssh:2222` a través
  del reenviador de logs (`tail -F /config/logs/openssh/current | nc
  logstash 5044`, ya validado en el Nivel 1). Cadena verificada de punta a
  punta: intentos reales de `sshd` → Logstash (grok RU-1) → Elasticsearch
  (5 hits, `rule.name: RU-1`, `source_ip: 172.19.0.1` — la IP del gateway
  de Docker, esperable por el doble NAT VirtualBox+Docker) → n8n (Schedule
  Trigger, alerta por Telegram recibida) → bloqueo real y automático
  (`iptables -L INPUT` mostró `DROP` para `172.19.0.1`). A diferencia del
  Nivel 1 (atacante = script corriendo en el mismo host Windows), acá el
  atacante es un sistema operativo distinto en una red separada — el
  escenario más realista validado en todo el proyecto.

## 🟠 Graves

### `workflows/RU1 siem.json`, `RU2 siem.json`, `RU3 siem.json`
- El disparador manual (`manualTrigger`) se reemplazó por un
  **Schedule Trigger cada 1 minuto**, así las reglas corren solas en
  vez de depender de que alguien las ejecute a mano en la UI de n8n.
- La query a Elasticsearch pasó de una búsqueda de texto libre rota
  (`q="Fallo"`, `q="EXITOSO"`, que no matcheaban los logs reales) a una
  query estructurada `POST /_search` sobre el campo `rule.name`
  (`"RU-1"`, `"RU-2"`, `"RU-3"`), que Logstash ya etiqueta en cada
  evento. RU-3 ya buscaba el término correcto (`SPIKE_CPU`) pero se
  migró igual por consistencia y para agregar la ventana temporal.
- Se agregó una ventana temporal (`@timestamp >= now-1m`) para que,
  corriendo cada 1 minuto, no se vuelva a alertar sobre el mismo evento
  viejo una y otra vez.
- Se agregó un nodo IF ("¿Hay resultados?") que corta el flujo si la
  búsqueda no devolvió hits, evitando errores/bloqueos sobre una IP
  `undefined` cuando no hay ninguna anomalía en la ventana.

### `workflows/RU2 siem.json` (además de lo anterior)
- Se corrigió el nodo IF que evalúa si el acceso es nocturno: antes
  usaba `DateTime.fromISO(@timestamp).hour` (la hora de **ingesta** en
  Elasticsearch), el mismo bug que el Anexo J.4 de la tesis dice haber
  corregido — pero esa corrección solo se había aplicado en
  `motor_ml.py`, no acá. Ahora usa `hora_evento` (ver cambio en
  `logstash.conf` más abajo), que es la hora real extraída del texto
  del mensaje.

### `config_logstash/logstash.conf`
- Se agregó un filtro `ruby` que extrae la hora real del evento
  (`hora_evento`) desde el texto del mensaje mediante regex, para
  TODOS los eventos, no solo para el motor ML. Esto es lo que permite
  el fix de RU-2 de arriba.

### `scripts_ml/enviar_log.py`, `simular_ru2.py`, `simular_ru3.py`
- Movidos a `scripts_ml/legacy/` con un aviso de deprecación al inicio
  de cada archivo. No son compatibles con el `logstash.conf` actual
  (formato de mensaje incompleto: falta timestamp syslog, falta
  `sshd[pid]:`, falta `port N ssh2`, etc.) — usar
  `simulador_ataques.py` en su lugar.

### `scripts_ml/motor_ml.py`
- Los defaults de `ES_HOST` y `WEBHOOK_URL` pasaron de apuntar a
  nombres de contenedor Docker (`siem_elasticsearch`, `siem_n8n`, que
  no resuelven desde tu PC) a `localhost`, pensado para ejecución
  directa desde el host. `docker-compose.yml` le sigue pasando los
  nombres de contenedor correctos cuando corre adentro del stack.

### `docker-compose.yml`
- El contenedor `ml-python` ya no queda en `tail -f /dev/null`: instala
  dependencias y arranca `motor_ml.py --loop` automáticamente al
  levantar el stack, para que la detección de anomalías sea realmente
  continua sin pasos manuales.
- Se agregó `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` y las variables
  `ABUSEIPDB_KEY` / `TELEGRAM_CHAT_ID_DEFAULT`, necesarias para que los
  workflows puedan leer esos secretos con `{{ $env.NOMBRE }}` en vez de
  tenerlos hardcodeados.
- Se agregaron healthchecks a Elasticsearch y PostgreSQL para evitar
  condiciones de carrera al levantar el stack por primera vez.

## 🟡 Menores

### `scripts_ml/verificar_pg.py`
- Sacadas las credenciales hardcodeadas (`host='siem_postgres',
  user='admin', password='1234'`); ahora usa las mismas variables de
  entorno que el resto de los scripts. También ahora reporta cuántas
  filas reales hay en `respuestas_aplicadas`.

### `scripts_ml/medir_grupo_manual.py`
- Se agregó una nota aclarando que `medir_latencias.py` es el script
  oficial para generar los datos finales de ambos grupos, y que este
  queda como alternativa opcional solo para el grupo manual.

### `scripts_ml/requirements.txt`
- Se agregaron `psycopg2-binary`, `scipy` y `matplotlib`, que antes
  había que instalar a mano por fuera de este archivo (ver
  `README_experimento.md` original).

### `init_db/01_schema_experimento.sql`
- Se agregaron índices sobre `alertas_ml(ip_origen, fecha)` y
  `respuestas_aplicadas(ip_origen, aplicada_en)` para que el polling de
  `medir_latencias.py` sea eficiente.

### `README.md` / `README_experimento.md`
- Reescritos para reflejar el setup automático real: motor ML en loop
  por defecto, workflows activos por defecto, instrucciones de
  variables de entorno correctas, y explicación de por qué los números
  de MTTR del grupo automatizado van a cambiar (ahora incluyen tiempo
  de reacción humano real vía HITL, en vez de un rango fijo inventado).

## Lo que NO se tocó (ya estaba bien)

- `init_db/01_schema.sql` — coincide con el Anexo B, sin cambios.
- `scripts_ml/simulador_ataques.py` — ya generaba logs con el formato
  correcto, sin cambios.
- `scripts_ml/analizar_experimento.py` — ya calculaba todo sobre datos
  reales de PostgreSQL, sin cambios.
- La lógica HITL de `RU4_ Respuesta.json` (Switch, extracción de IP,
  registro de analista) y `Registro siem.json` — ya estaban bien
  implementadas, solo se activaron.

## Qué tenés que hacer vos ahora (no se puede automatizar desde acá)

1. **Rotar la API key de AbuseIPDB** en su panel de control.
2. Completar `.env` con la key nueva y tu `TELEGRAM_CHAT_ID_DEFAULT`.
3. `docker compose up -d` y esperar a que todo levante sano
   (`docker compose ps`).
4. Importar los 7 workflows corregidos en n8n y configurar las
   credenciales de Postgres/SSH/Telegram en cada nodo que las pida.
5. Correr `scripts_ml/medir_latencias.py` para ambos grupos (30
   iteraciones cada uno) y `scripts_ml/analizar_experimento.py` para
   regenerar la Tabla 1, la Sección 5.1.2 y las Figuras 1 y 2 con datos
   reales.
6. Actualizar el cuerpo de la tesis con los números nuevos.
