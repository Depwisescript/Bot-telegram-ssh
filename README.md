# Bot-telegram-ssh

curl -L -o install.sh "https://raw.githubusercontent.com/Depwisescript/Bot-telegram-ssh/refs/heads/main/install.sh" && chmod +x install.sh && sudo ./install.sh && rm install.sh

agregar cambiar bot token y id
Edita nano /opt/tg-bot/.env
sudo systemctl restart tg-ssh-multi





DESINTALAR 


curl -L -o uninstall_tg_ssh_bot.sh "https://raw.githubusercontent.com/Depwisescript/Bot-telegram-ssh/refs/heads/main/uninstall_tg_ssh_bot.sh" && chmod +x uninstall_tg_ssh_bot.sh && sudo bash ./uninstall_tg_ssh_bot.sh && rm uninstall_tg_ssh_bot.sh


🧠 ¿Qué puede hacer el bot?
Comandos soportados (sólo admins)

/start y /help → ayuda del bot.
/servers → lista tus servidores registrados.
/addserver <alias> <host> <port> <user> <auth:key|password> <cred>

Si auth=key, <cred>=nombre_de_clave (que subes con /uploadkey).
Si auth=password, luego configuras con /setpass <alias> <password>.


/delserver <alias> → elimina un servidor.
Subir clave: Adjunta un documento (tu clave privada) con el caption:
/uploadkey NOMBRE

Se guarda en /opt/ssh-tg-bot/keys/NOMBRE con permisos 600.
Guardar password (cifrado):
/setpass <alias> <password>

⚠️ Recomendación: usa claves mejor que contraseñas.
Ejecutar comando:
/sh <alias> <comando>

Devuelve exit code, STDOUT y STDERR. Si la salida es grande, te la envía como archivo.


Ejemplo de flujo (con claves):

En Telegram: envías tu clave privada como documento con caption /uploadkey id_rsa_web1
Agregas servidor:
/addserver web1 10.0.0.10 22 ubuntu key id_rsa_web1
Pruebas comando:
/sh web1 'uname -a'



🔐 Detalles de seguridad y buenas prácticas

Restringe acceso: Sólo responde a los IDs de ADMIN_USER_IDS.
Claves privadas: se guardan con permisos 600; el servicio corre como usuario sshbot (no root).
Contraseñas: si decides usarlas, se almacenan con Fernet (cifrado simétrico) usando ENCRYPTION_KEY del .env. Aun así, es menos seguro que usar claves.
Host key checking:

Por defecto OFF (conexiones sin verificación de huella).
Puedes activarlo: STRICT_HOST_KEY_CHECKING=true en /opt/ssh-tg-bot/.env y gestionar /opt/ssh-tg-bot/known_hosts manualmente (recomendado en producción).


Evita root: usa cuentas dedicadas con sudo para lo necesario y limita comandos.
Registros: monitorea journalctl -u ssh-telegram-bot.


🧩 ¿Qué instaló exactamente el script?

Código del bot en: /opt/ssh-tg-bot/bot.py (usa python-telegram-bot 21.*, asyncssh, cryptography).
Entorno virtual: /opt/ssh-tg-bot/.venv
Archivos:

/opt/ssh-tg-bot/.env
/opt/ssh-tg-bot/keys/ (para claves privadas)
/opt/ssh-tg-bot/inventory.json (alias/hosts/usuarios/credenciales)


Servicio: /etc/systemd/system/ssh-telegram-bot.service
