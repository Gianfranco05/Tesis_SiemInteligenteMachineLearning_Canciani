# Registro de trabajo — M-24 (repetir ataque SSH real n=10)

## 2026-08-08 — Preparacion inicial

- Se reviso el docker-compose.yml y workflows/RU1 siem.json para confirmar
  como se aplica el bloqueo real:
  - El nodo `Execute a command` (tipo `n8n-nodes-base.ssh`) del workflow
    RU-1 corre `sudo iptables -A INPUT -s <ip_origen> -j DROP` via una
    credencial SSH guardada en n8n ("SSH Password account"), NO contra un
    "host_victima" separado como asumia la nota original: en este proyecto
    la victima (`victima_ssh`, puerto 2222, user `admin`/`1234` segun
    `.env`) es el mismo host que se bloquea a si mismo. Falta confirmar con
    el usuario si esa credencial apunta efectivamente a `victima_ssh:2222`.
  - La tabla `alertas_fuerza_bruta` (init_db/00_schema.sql) tiene columnas
    `id, fecha (default now), detalle` — `fecha` es el T2 (registro del
    bloqueo) que pide el plan original.
- Docker Desktop no esta corriendo en este momento en la maquina donde
  vive el repo (falla `docker ps`). Hay que levantarlo antes de correr
  cualquier prueba real.
- Se creo `scripts_ml/medir_ataque_real_10x.sh`: script pensado para
  correr DESDE LA VM DE ATAQUE (no desde este host), que:
  1. Limpia la regla iptables de la corrida anterior (via SSH a
     victima_ssh, puerto 2222).
  2. Lanza el loop de fuerza bruta real (sshpass con 6 passwords
     incorrectas) y registra T0.
  3. Poll a Elasticsearch (`rule.name: RU-1`, filtrado por `@timestamp >=
     T0`) para T1 (deteccion).
  4. Poll a PostgreSQL (`alertas_fuerza_bruta.fecha >= T0`) para T2
     (bloqueo aplicado).
  5. Calcula MTTD = T1-T0, MTTR = T2-T0 y escribe una fila en
     `resultados_ataque_real_10x.csv`.
  - Placeholders sin confirmar: `VICTIMA_HOST` (IP/hostname del stack
    Docker alcanzable desde la VM), y si la VM tiene alcance de red directo
    a los puertos 9200 (Elasticsearch) y 5433 (Postgres) ademas del 2222
    (SSH) que ya se uso en el Nivel 2.
  - Nota: `Engram` (memoria persistente entre sesiones) no esta conectado
    en esta sesion de Claude Code (no aparece como herramienta disponible),
    asi que el registro de este trabajo se esta llevando en este archivo
    en vez de vía `mem_save`. Si se reconecta Engram, migrar este resumen
    ahi.

## 2026-08-09 — Conectividad OK, primera corrida real y hallazgo importante

- Usuario confirmo desde la VM: `curl http://10.0.2.2:9200` y
  `nc -zv 10.0.2.2 5433` responden bien. No hizo falta tocar el Firewall
  de Windows — la regla existente "Docker Desktop Backend" (permite todo
  TCP/UDP entrante hacia `com.docker.backend.exe`) ya cubria estos puertos,
  igual que el 2222 usado en el Nivel 2.
- Docker Desktop se levanto solo (ya estaba instalado); se inicio el
  forwarder de logs en `victima_ssh` manualmente
  (`tail -F /config/logs/openssh/current | nc logstash 5044`).
- **Hallazgo (corrige un bug del script inicial):** el script v1 calculaba
  `MY_IP` con `curl ifconfig.me` (IP publica/real de la VM) para poder
  borrar la regla iptables de la corrida anterior. Eso estaba MAL: como el
  ataque entra por el puerto publicado de Docker (`0.0.0.0:2222->2222` en
  `victima_ssh`), Docker hace NAT/masquerade sobre esa conexion, y sshd
  DENTRO del contenedor ve como IP origen la gateway del bridge de Docker
  (`172.19.0.1` en este proyecto), no la IP real de la VM. Por lo tanto
  RU-1 lee ese `source_ip` desde el log y termina bloqueando
  `172.19.0.1`, no la VM. Con `MY_IP=ifconfig.me` la limpieza entre
  corridas no borraba nada (fallaba en silencio, `2>/dev/null`), la regla
  vieja quedaba puesta, y la Repeticion 2 en adelante se hubiera colgado
  sin generar ni siquiera el "Failed password" (paquetes dropeados a
  nivel de red, como preveia la nota original del plan M-24, solo que por
  la IP equivocada).
  - Implicancia para la tesis: como TODO el trafico que entra por el
    puerto publicado de Docker se ve, desde adentro del contenedor, como
    si viniera de `172.19.0.1`, el bloqueo real de RU-1 en este entorno de
    laboratorio no aisla la IP real del atacante — aisla la ruta NAT de
    Docker completa. Vale la pena mencionarlo como limitacion conocida del
    entorno de pruebas (Anexo F), no invalida la medicion de MTTD/MTTR
    pero si el alcance real del bloqueo de iptables tal como esta
    configurado hoy.
  - Fix aplicado en `scripts_ml/medir_ataque_real_10x.sh`: `MY_IP` ahora
    esta hardcodeado a `"172.19.0.1"` en vez de resolverse con
    `ifconfig.me`/`icanhazip.com`.
- El usuario corto la Repeticion 1 con Ctrl+C tras notar el problema (sin
  perdida real, ya que la corrida 1 no dependia de la limpieza previa) y
  va a re-lanzar el script completo desde cero con el fix aplicado.

## 2026-08-09 (cont.) — Bug critico encontrado en RU-1: falso positivo por analizador de texto

- Al investigar por que `alertas_fuerza_bruta` tenia 138 filas con una
  insercion cada ~60s (incluso sin ataque en curso) se encontro la causa
  raiz: el campo `rule.name` en Elasticsearch es `text` (analizado), con
  un sub-campo `rule.name.keyword` para matching exacto. La query del
  workflow real de n8n (`workflows/RU1 siem.json`, nodo "HTTP Request")
  usaba `{"match": {"rule.name": "RU-1"}}`. El analizador estandar parte
  "RU-1" en los tokens `"ru"` y `"1"`, y `match` hace OR entre tokens por
  default — por lo tanto la query tambien matcheaba `RU-2`, `RU-3`, etc.
  (todos comparten el token "ru").
  - Verificado en vivo: `match` sobre `rule.name` = 2765 hits; `term`
    sobre `rule.name.keyword` = 1972 hits. La diferencia (~800 eventos)
    son falsos positivos.
  - Consecuencia real observada: cada evento RU-2 ("Accepted password...",
    login SSH exitoso normal) disparaba el workflow de RU-1 completo:
    insertaba una fila falsa en `alertas_fuerza_bruta` Y ejecutaba
    `sudo iptables -A INPUT -s <ip> -j DROP` sobre quien se acababa de
    loguear bien. Asi es como la gateway del bridge Docker (172.19.0.1)
    volvio a quedar bloqueada sin que hubiera ningun ataque de fuerza
    bruta real corriendo.
  - Mismo patron de bug encontrado tambien en `workflows/RU2 siem.json` y
    `workflows/RU3 siem.json` (no corregidos todavia — fuera de alcance de
    este pedido puntual, el usuario solo pidio arreglar RU-1 por ahora).
    **Pendiente de decision del usuario**: si corregir tambien RU-2 y RU-3.
- **Fix aplicado** (decision del usuario: arreglar el workflow real, no
  solo el script):
  - `workflows/RU1 siem.json`: query cambiada de
    `{"match": {"rule.name": "RU-1"}}` a
    `{"term": {"rule.name.keyword": "RU-1"}}`. Falta reimportar este
    workflow en n8n (el archivo en disco no se auto-recarga; hay que
    subirlo a mano en la UI de n8n o via su API/CLI).
  - `scripts_ml/medir_ataque_real_10x.sh`: mismo cambio en el polling de
    T1 (usaba la query calcada del workflow con el mismo bug).
  - Se removio la regla `iptables -D INPUT -s 172.19.0.1 -j DROP` que
    habia quedado puesta por el falso positivo (verificado con
    `iptables -L INPUT` que la cadena INPUT quedo limpia).
  - Las 138 filas previas en `alertas_fuerza_bruta` NO se borraron (la
    tabla es de auditoria inmutable, asi la describe el docker-compose).
    Quedan como registro historico pero son en su mayoria falsos
    positivos — no usar ese rango de timestamps (~2026-08-08 tarde en
    adelante, hasta este fix) como evidencia de deteccion real de fuerza
    bruta en la tesis.
- **Redisenio de la orquestacion (pedido del usuario):** la limpieza de
  iptables y el sondeo de ES/Postgres se mueven a un script que corre del
  lado Windows (acceso directo a `docker exec` y a `localhost:9200/5433`),
  que dispara el ataque en la VM via SSH en cada repeticion en vez de que
  el loop completo corra dentro de la VM. Motivo: la limpieza fallaba
  porque la propia conexion SSH desde la VM estaba bloqueada por la regla
  que se intentaba borrar (mismo canal usado para limpiar y para atacar).
  - Se genero un par de claves SSH dedicado en Windows
    (`~/.ssh/vm_ataque_siem`) y se autorizo en la VM
    (`~/.ssh/authorized_keys` de `admin@siem-cliente-real`, puerto 2200)
    para que Windows pueda disparar el ataque sin password interactiva.
    Verificado con `BatchMode=yes` — conexion sin password OK.
  - Confirmado que Windows tiene acceso directo (sin pasar por la VM) a:
    `docker exec victima_ssh sudo iptables ...` (limpieza), `curl
    localhost:9200` (ES), `docker exec siem_postgres psql ...` (Postgres,
    ya que no hay cliente `psql` nativo instalado en Windows).
  - Las Repeticiones 2 a 4 de la corrida abortada anterior quedan
    descartadas (contaminadas por el bug de matching, no por ataques
    reales). Se arranca de cero.
- Se escribio `scripts_ml/medir_ataque_windows.sh` (corre en Windows,
  dispara el ataque en la VM por SSH con clave, limpia iptables y sondea
  ES/Postgres localmente via docker exec/curl).
- **Smoke test de 1 repeticion, exitoso:** T0=01:37:01Z, T1 (deteccion,
  query corregida term/keyword)=01:37:02Z (~1s), T2 (bloqueo en
  Postgres + regla iptables aplicada)=01:37:12Z (~11s). Confirma que el
  pipeline completo (disparo remoto por SSH con clave, limpieza directa
  por docker exec, polling ES/PG) funciona de punta a punta con el fix
  del bug de matching. Se limpio la regla de este smoke test antes de
  lanzar la corrida real de 10 repeticiones.
- Lanzando corrida real de N=10 con `medir_ataque_windows.sh`
  (~15-20 min, 90s de espera entre repeticiones).

## 2026-08-09 (cont.) — Corrida real de 10 repeticiones completada

- Las 10 repeticiones corrieron sin errores. CSV final:
  `scripts_ml/resultados_ataque_real_10x.csv`.
- **MTTD (deteccion, T1-T0):** media 1.5s, desvio estandar (muestral) 0.53s,
  rango 1-2s.
- **MTTR (bloqueo aplicado, T2-T0):** media 27.0s, desvio estandar
  (muestral) 6.04s, rango 10-30s.
- **Hallazgo metodologico importante:** los 10 valores de T2 caen
  exactamente sobre el segundo `:12` de cada minuto
  (`01:38:12, 01:40:12, ..., 01:56:12`). Confirma que el workflow RU-1 en
  n8n usa un Schedule Trigger fijo cada 60s (no reacciona evento a
  evento). La deteccion (T1, via Logstash/ES) es casi instantanea; el
  MTTR esta dominado por la espera al proximo tick del schedule, no por
  tiempo de computo real. Documentar esto en el Anexo F como
  caracteristica de diseno (deteccion event-driven + respuesta por
  polling de 60s), no como limitacion oculta.
## 2026-08-09 (cont.) — RU-2 corregido; RU-3 revisado, mismo bug confirmado pero SIN aplicar fix

- `workflows/RU2 siem.json`: mismo bug que RU-1 (`{"match": {"rule.name":
  "RU-2"}}` matcheaba cualquier evento con token "ru"). **Corregido** a
  `{"term": {"rule.name.keyword": "RU-2"}}` (se preservo el resto de la
  query, incluyendo el filtro `hora_evento` 0-6). Falta reimportar en n8n,
  igual que RU-1.
- `workflows/RU3 siem.json`: revisado el workflow completo antes de tocar
  nada, a pedido del usuario (la hipotesis era que RU-3 filtra por
  contenido del mensaje "SPIKE_CPU" en vez de por `rule.name`, segun el
  Anexo D). Se leyeron los 3 nodos completos:
  `Schedule Trigger (cada 1 min) -> HTTP Request -> ¿Hay resultados?
  (hits.total.value > 0) -> Insert rows in a table`.
  **Resultado de la revision: NO hay ningun filtro de contenido en el
  workflow real.** La query del HTTP Request es identica en estructura a
  la de RU-1/RU-2 (`{"match": {"rule.name": "RU-3"}}`), y el unico chequeo
  posterior es sobre la cantidad de resultados, no sobre el mensaje. Es
  decir, el mismo bug de tokenizacion aplica: "RU-3" se parte en tokens
  "ru"+"3", y "ru" matchea cualquier otra regla. El supuesto del Anexo D
  (que RU-3 filtra por contenido) no se corresponde con lo que el
  workflow realmente hace hoy.
  - Usuario confirmo el mismo fix tras ver el hallazgo. **Aplicado**:
    `{"match": {"rule.name": "RU-3"}}` -> `{"term": {"rule.name.keyword":
    "RU-3"}}` en `workflows/RU3 siem.json`.
- **Estado final de archivos:** RU1, RU2 y RU3 (`workflows/*.json`)
  corregidos en disco. Ninguno tiene efecto real todavia — n8n no
  recarga los workflows automaticamente desde archivo. Pendiente:
  reimportar los 3 a mano en la UI de n8n (http://localhost:5678 -> abrir
  el workflow -> menu "..." -> "Import from File" -> seleccionar el JSON
  corregido -> guardar -> confirmar que quede "Active"). Esto es tarea del
  usuario (acceso a la UI web), Claude Code no puede hacerlo.

## Pendiente (bloqueado en info del usuario)
- Confirmar VICTIMA_HOST y alcance de red de la VM a puertos 9200/5433.
- Confirmar que el stack Docker este levantado y el forwarder de logs
  activo en victima_ssh antes de la primera corrida.
- Confirmar que la credencial SSH de n8n para el nodo "Execute a command"
  efectivamente apunta a victima_ssh:2222 (para saber que se puede limpiar
  con el mismo acceso).
