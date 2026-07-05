# victima_ssh/Dockerfile
# CORREGIDO (2 problemas encontrados en la imagen base):
#   1. linuxserver/openssh-server no trae iptables instalado.
#   2. sudo pide contraseña por defecto, y el nodo SSH de n8n no asigna
#      una TTY al ejecutar comandos remotos, así que sudo no puede
#      pedirla ni recibirla → todo comando con sudo lanzado desde n8n
#      fallaba con "sudo: a password is required".
FROM lscr.io/linuxserver/openssh-server:latest

# 1) iptables (imagen base es Alpine)
RUN apk add --no-cache iptables

# 2) Script que configura sudo sin contraseña, ejecutado por el propio
#    init de la imagen (s6-overlay) DESPUÉS de crear el usuario en
#    tiempo de ejecución (no se puede hacer esto en el build, porque el
#    usuario todavía no existe en este momento).
COPY custom-cont-init.d/10-sudo-nopasswd.sh /custom-cont-init.d/10-sudo-nopasswd.sh
RUN chmod +x /custom-cont-init.d/10-sudo-nopasswd.sh
