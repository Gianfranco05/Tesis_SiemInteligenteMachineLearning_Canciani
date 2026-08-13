#!/bin/bash
# M-24 v2: repite el ataque SSH REAL n veces, orquestado DESDE WINDOWS
# (donde corre Docker), no desde la VM. La VM solo dispara el ataque via
# SSH con clave (sin password); la limpieza de iptables y el sondeo de
# Elasticsearch/PostgreSQL se hacen con docker exec / curl locales, para
# no depender del mismo canal de red que el ataque bloquea.
#
# CORRER DESDE WINDOWS (Git Bash), con el stack Docker levantado y el
# forwarder de logs activo en victima_ssh.

set -uo pipefail

# ====== CONFIGURAR ANTES DE CORRER ======
VM_SSH_KEY="$HOME/.ssh/vm_ataque_siem"
VM_SSH_PORT=2200
VM_SSH_USER=admin
VM_SSH_HOST=127.0.0.1

VICTIMA_HOST="10.0.2.2"   # como la ve la VM (gateway NAT de VirtualBox)
VICTIMA_SSH_PORT=2222
PASSWORDS=(pass1 pass2 pass3 pass4 pass5)

DOCKER_GATEWAY_IP="172.19.0.1"   # gateway del bridge final_proyecto_siem_default (verificado con docker inspect)

ES_URL="http://localhost:9200"
PG_CONTAINER="siem_postgres"
PG_USER=admin
PG_DB=tesis_siem

N=10
ESPERA_ENTRE_CORRIDAS=90
CSV_OUT="resultados_ataque_real_10x.csv"
# =========================================

echo "repeticion,T0,T1_deteccion,T2_bloqueo,mttd_seg,mttr_seg" > "$CSV_OUT"

for i in $(seq 1 "$N"); do
  echo "=== Repeticion $i/$N ==="

  # 1) limpiar el bloqueo iptables de la corrida anterior (directo por
  #    docker exec, sin depender de la red que el bloqueo podria cortar)
  docker exec victima_ssh sudo iptables -D INPUT -s "$DOCKER_GATEWAY_IP" -j DROP 2>/dev/null
  echo "  (regla iptables anterior removida si existia)"

  # 2) lanzar el ataque real, disparado por SSH con clave hacia la VM
  T0_EPOCH=$(date -u +%s)
  T0_ISO=$(date -u -d "@$T0_EPOCH" +%Y-%m-%dT%H:%M:%S.000Z)
  echo "  T0 = $T0_ISO"

  REMOTE_CMD="for pass in ${PASSWORDS[*]}; do sshpass -p \"\$pass\" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p $VICTIMA_SSH_PORT admin@$VICTIMA_HOST exit; done"
  ssh -i "$VM_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -p "$VM_SSH_PORT" "$VM_SSH_USER@$VM_SSH_HOST" "$REMOTE_CMD"

  # 3) esperar el evento RU-1 en Elasticsearch (T1 = deteccion)
  #    term sobre rule.name.keyword (match exacto, ver log_M24.md sobre el
  #    bug de falsos positivos con "match" sobre rule.name analizado)
  T1=""
  for s in $(seq 1 30); do
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
    T2=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -A \
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
