#!/usr/bin/with-contenv bash
# custom-cont-init.d/10-sudo-nopasswd.sh
#
# CORREGIDO (segunda vuelta): la primera versión de este script agregaba
# una regla NOPASSWD nueva en /etc/sudoers.d/, pero no tenía ningún
# efecto. La causa: en /etc/sudoers, DESPUÉS de la línea
# "@includedir /etc/sudoers.d" (que es la que lee nuestro archivo nuevo),
# la propia imagen base agrega su propia línea:
#   admin ALL=(ALL) ALL
# En sudoers, cuando varias reglas matchean para el mismo usuario, GANA
# LA ÚLTIMA que aparece en el archivo — y esa línea de la imagen base
# queda físicamente más abajo que nuestro include, así que siempre
# terminaba ganando ella (con contraseña), tapando nuestra regla nueva.
#
# La solución correcta es modificar esa línea puntual, convirtiéndola
# en su versión NOPASSWD, en vez de intentar competir con una regla
# aparte.

USUARIO="${USER_NAME:-admin}"
LINEA_ORIGINAL="${USUARIO} ALL=(ALL) ALL"
LINEA_NUEVA="${USUARIO} ALL=(ALL) NOPASSWD: ALL"

if grep -qxF "${LINEA_ORIGINAL}" /etc/sudoers; then
  sed -i "s/^${USUARIO} ALL=(ALL) ALL\$/${USUARIO} ALL=(ALL) NOPASSWD: ALL/" /etc/sudoers
  echo "[custom-init] Linea de sudo para '${USUARIO}' actualizada a NOPASSWD."
else
  echo "[custom-init] ADVERTENCIA: no se encontro la linea '${LINEA_ORIGINAL}' en /etc/sudoers."
  echo "[custom-init] Puede que la imagen base haya cambiado su formato. Revisar /etc/sudoers manualmente."
fi

# Verificación de sintaxis, para detectar cualquier problema de inmediato
# en los logs en vez de fallar en silencio la próxima vez que se use sudo.
if ! visudo -c > /tmp/visudo-check.log 2>&1; then
  echo "[custom-init] ERROR: la sintaxis de /etc/sudoers quedo invalida despues del cambio:"
  cat /tmp/visudo-check.log
fi
