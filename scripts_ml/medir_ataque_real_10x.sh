#!/bin/bash
# M-24: repite el ataque SSH REAL (Nivel 2) N veces y mide MTTD/MTTR reales
# sobre trafico real (no simulado).
#
# CORRER DESDE LA VM DE ATAQUE (la misma que usaste para el Nivel 2, paso 3),
# NO desde el host donde corre Docker.
#
# Requiere en la VM: sshpass, curl, psql (paquete postgresql-client), bash.

set -uo pipefail

# ====== CONFIGURAR ANTES DE CORRER (ver checklist en el chat) ======
VICTIMA_HOST="10.0.2.2"   # gateway NAT de VirtualBox hacia el host Windows (mismo usado en Nivel 2)
VICTIMA_SSH_PORT=2222
VICTIMA_SSH_USER=admin
VICTIMA_SSH_PASS=1234
ES_URL="http://${VICTIMA_HOST}:9200"
PG_HOST="${VICTIMA_HOST}"
PG_PORT=5433
PG_USER=admin
PG_PASS=1234
PG_DB=tesis_siem
PASSWORDS=(pass1 pass2 pass3 pass4 pass5)   # 5 intentos, igual que el ataque real n=1 ya documentado en el CHANGELOG
N=10
ESPERA_ENTRE_CORRIDAS=90
CSV_OUT="resultados_ataque_real_10x.csv"
# =====================================================================

echo "repeticion,T0,T1_deteccion,T2_bloqueo,mttd_seg,mttr_seg" > "$CSV_OUT"

for i in $(seq 1 "$N"); do
  echo "=== Repeticion $i/$N ==="

  # 1) limpiar el bloqueo iptables que haya dejado la corrida anterior
  # OJO: NO es la IP publica/real de la VM (ifconfig.me). Docker hace NAT
  # sobre las conexiones que entran por el puerto publicado 2222, asi que
  # sshd DENTRO de victima_ssh ve como origen la gateway del bridge de
  # Docker, no la IP real del atacante. Por eso RU-1 termina bloqueando
  # esa gateway (172.19.0.1 en este proyecto) y no la IP de la VM.
  MY_IP="172.19.0.1"
  echo "  IP a limpiar (gateway del bridge Docker, no la IP real de la VM): $MY_IP"
  sshpass -p "$VICTIMA_SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$VICTIMA_SSH_PORT" \
    "$VICTIMA_SSH_USER@$VICTIMA_HOST" "sudo iptables -D INPUT -s $MY_IP -j DROP" 2>/dev/null
  echo "  (regla anterior removida si existia)"

  # 2) lanzar el ataque de fuerza bruta real
  T0_EPOCH=$(date -u +%s)
  T0_ISO=$(date -u -d "@$T0_EPOCH" +%Y-%m-%dT%H:%M:%S.000Z)
  echo "  T0 = $T0_ISO"
  for pass in "${PASSWORDS[@]}"; do
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      -p "$VICTIMA_SSH_PORT" "$VICTIMA_SSH_USER@$VICTIMA_HOST" exit
  done

  # 3) esperar el evento RU-1 en Elasticsearch (T1 = deteccion)
  T1=""
  for s in $(seq 1 30); do
    # term sobre rule.name.keyword (NO match sobre rule.name): rule.name es
    # texto analizado y el analizador estandar parte "RU-1" en tokens "ru"/"1",
    # asi que un match hace OR y tambien matchea RU-2, RU-3, etc. Ver log_M24.md.
    RESP=$(curl -s -X POST "$ES_URL/eventos-seguridad-*/_search" \
      -H 'Content-Type: application/json' \
      -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"rule.name.keyword\":\"RU-1\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$T0_ISO\"}}}]}},\"size\":1,\"sort\":[{\"@timestamp\":{\"order\":\"asc\"}}]}")
    T1=$(echo "$RESP" | grep -o '"@timestamp":"[^"]*"' | head -1 | cut -d'"' -f4)
    [ -n "$T1" ] && break
    sleep 2
  done

  # 4) esperar el registro del bloqueo en PostgreSQL (T2 = respuesta aplicada)
  T2=""
  for s in $(seq 1 30); do
    T2=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -t -A \
      -c "SELECT fecha FROM alertas_fuerza_bruta WHERE fecha >= TIMESTAMP '$T0_ISO' ORDER BY fecha ASC LIMIT 1;" 2>/dev/null)
    T2=$(echo "$T2" | xargs)
    [ -n "$T2" ] && break
    sleep 2
  done

  MTTD="N/A"
  MTTR="N/A"
  if [ -n "$T1" ]; then
    T1_EPOCH=$(date -u -d "$T1" +%s 2>/dev/null)
    [ -n "$T1_EPOCH" ] && MTTD=$((T1_EPOCH - T0_EPOCH))
  fi
  if [ -n "$T2" ]; then
    T2_EPOCH=$(date -u -d "$T2" +%s 2>/dev/null)
    [ -n "$T2_EPOCH" ] && MTTR=$((T2_EPOCH - T0_EPOCH))
  fi

  echo "  T1 (deteccion) = $T1   ->  MTTD = ${MTTD}s"
  echo "  T2 (bloqueo)    = $T2   ->  MTTR = ${MTTR}s"
  echo "$i,$T0_ISO,$T1,$T2,$MTTD,$MTTR" >> "$CSV_OUT"

  if [ "$T1" = "" ] || [ "$T2" = "" ]; then
    echo "  [ADVERTENCIA] esta corrida no completo deteccion y/o bloqueo dentro del timeout (60s de polling)."
  fi

  if [ "$i" -lt "$N" ]; then
    echo "  esperando ${ESPERA_ENTRE_CORRIDAS}s antes de la proxima corrida..."
    sleep "$ESPERA_ENTRE_CORRIDAS"
  fi
done

echo ""
echo "Listo. Resultados en $CSV_OUT"
