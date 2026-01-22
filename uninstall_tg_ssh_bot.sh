
#!/usr/bin/env bash
# uninstall_tg_ssh_bot.sh
# Elimina completamente el bot Telegram SSH Multi-Server
# Incluye servicio systemd, usuario, claves, archivos y directorios.

set -euo pipefail

SERVICE_NAME="tg-ssh-multi"
BOT_USER="tg-bot"
BOT_HOME="/opt/tg-bot"

echo "==============================="
echo "   DESINSTALANDO TG SSH BOT"
echo "==============================="

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root."
  exit 1
fi

echo "➤ Deteniendo servicio systemd (si existe)…"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

echo "➤ Eliminando archivo de servicio…"
/bin/rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload || true

echo "➤ Eliminando usuario y grupo '${BOT_USER}' (si existen)…"
if id "$BOT_USER" >/dev/null 2>&1; then
  userdel -r "$BOT_USER" 2>/dev/null || true
fi
groupdel "$BOT_USER" 2>/dev/null || true

echo "➤ Eliminando directorio ${BOT_HOME}…"
/bin/rm -rf "${BOT_HOME}"

echo "➤ Eliminando archivos residuales…"
rm -f /var/log/${SERVICE_NAME}.log 2>/dev/null || true
rm -rf /tmp/${SERVICE_NAME}* 2>/dev/null || true

echo "➤ Verificando que todo fue eliminado…"
if [[ ! -d "$BOT_HOME" ]]; then
  echo "✔ Carpeta eliminada"
else
  echo "⚠ Carpeta sigue existiendo: $BOT_HOME"
fi

if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
  echo "⚠ Servicio sigue existiendo"
else
  echo "✔ Servicio eliminado correctamente"
fi

echo
echo "==============================="
echo "  DESINSTALACIÓN COMPLETADA"
echo "==============================="
echo "Si deseas reinstalar, ejecuta el script install_tg_ssh_bot_envfirst.sh"
