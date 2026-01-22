#!/usr/bin/env bash
# setup_ssh_tg_bot.sh - Instalador automático de un bot de Telegram que ejecuta comandos SSH
# Probado en Ubuntu 24.04 LTS
# Uso:
#   sudo bash setup_ssh_tg_bot.sh

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Ejecuta como root: sudo bash setup_ssh_tg_bot.sh"
  exit 1
fi

# === Preguntas interactivas ===
read -rp "Pega tu TELEGRAM_TOKEN (de BotFather): " TELEGRAM_TOKEN
if [[ -z "${TELEGRAM_TOKEN}" ]]; then
  echo "Token vacío. Abortando."; exit 1
fi

read -rp "IDs de admins (separados por coma, ej: 12345,67890): " ADMIN_IDS
if [[ -z "${ADMIN_IDS}" ]]; then
  echo "Debes indicar al menos un ID de admin."; exit 1
fi

read -rp "¿Habilitar verificación estricta de host key SSH? (y/N): " STRICT
STRICT=${STRICT:-N}
if [[ "${STRICT}" =~ ^[Yy]$ ]]; then
  STRICT_HOST_KEY_CHECKING=true
else
  STRICT_HOST_KEY_CHECKING=false
fi

# === Paquetes del sistema ===
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y python3 python3-venv python3-pip ufw \
  build-essential python3-dev libffi-dev libssl-dev

# Firewall básico
ufw allow OpenSSH || true
ufw --force enable || true

# === Estructura de directorios ===
APP_DIR=/opt/ssh-tg-bot
KEYS_DIR="$APP_DIR/keys"
TMP_DIR="$APP_DIR/tmp"
mkdir -p "$APP_DIR" "$KEYS_DIR" "$TMP_DIR"

# Usuario de sistema no-login
id -u sshbot &>/dev/null || useradd -r -s /usr/sbin/nologin sshbot
chown -R sshbot:sshbot "$APP_DIR"
chmod 700 "$KEYS_DIR"
chmod 700 "$TMP_DIR"

# === Virtualenv y dependencias ===
python3 -m venv "$APP_DIR/.venv"
source "$APP_DIR/.venv/bin/activate"
python -m pip install --upgrade pip

# requirements.txt
cat > "$APP_DIR/requirements.txt" << 'REQ'
python-telegram-bot[rate-limiter]==21.*
asyncssh>=2.14.0
cryptography>=41.0.0
python-dotenv>=1.0.0
REQ

pip install -r "$APP_DIR/requirements.txt"

# === Bot (código Python) ===
cat > "$APP_DIR/bot.py" << 'PY'
#!/usr/bin/env python3
"""
Bot de Telegram para ejecutar comandos SSH en servidores remotos.
- Autenticación por lista de IDs de Telegram (admins) desde .env
- Inventario de servidores administrados (JSON)
- Credenciales:
    * Claves privadas: subir con /uploadkey <nombre> como caption del documento
    * Passwords: se guardan encriptados (Fernet) [no recomendado].
- Comandos:
    /start, /help
    /servers                      -> lista servidores
    /addserver <alias> <host> <port> <user> <auth:key|password> <cred>
    /delserver <alias>
    /uploadkey <nombre> (en caption del documento de la clave privada)
    /setpass <alias> <password>   -> guarda password (encriptado)
    /sh <alias> <cmd>             -> ejecuta comando puntual

Seguridad:
- Restringe a admins por ID.
- Evita usar root; prefiere usuarios con sudo controlado.
- known_hosts deshabilitado por defecto (para simplicidad). Actívalo con STRICT_HOST_KEY_CHECKING=true en .env y gestiona known_hosts manualmente.
"""
import os
import json
import asyncio
import logging
import base64
import tempfile
from pathlib import Path

import asyncssh
from cryptography.fernet import Fernet
from telegram import Update, InputFile
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)
from dotenv import load_dotenv

# === Logging ===
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger('ssh-tg-bot')

# === Carga .env ===
load_dotenv()
TOKEN = os.getenv('TELEGRAM_TOKEN')
ADMIN_IDS = {
    int(x.strip()) for x in os.getenv('ADMIN_USER_IDS', '').split(',') if x.strip().isdigit()
}
DATA_DIR = Path(os.getenv('DATA_DIR', '/opt/ssh-tg-bot'))
KEYS_DIR = Path(os.getenv('KEYS_DIR', str(DATA_DIR / 'keys')))
TMP_DIR = Path(os.getenv('TMP_DIR', str(DATA_DIR / 'tmp')))
INVENTORY_FILE = DATA_DIR / 'inventory.json'
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
STRICT_HOST_KEY_CHECKING = os.getenv('STRICT_HOST_KEY_CHECKING', 'false').lower() == 'true'
KNOWN_HOSTS_FILE = DATA_DIR / 'known_hosts'

if not TOKEN:
    raise SystemExit('Falta TELEGRAM_TOKEN en .env')
if not ADMIN_IDS:
    raise SystemExit('Falta ADMIN_USER_IDS en .env')

# === Cifrado para passwords ===
if not ENCRYPTION_KEY:
    raise SystemExit('Falta ENCRYPTION_KEY en .env')
try:
    fernet = Fernet(ENCRYPTION_KEY.encode())
except Exception as e:
    raise SystemExit(f'ENCRYPTION_KEY inválida: {e}')

# === Estructuras ===
INV_LOCK = asyncio.Lock()

def load_inventory():
    if not INVENTORY_FILE.exists():
        return {"servers": {}}
    try:
        with INVENTORY_FILE.open('r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        logger.exception('No se pudo leer inventory.json; usando estructura vacía')
        return {"servers": {}}

async def save_inventory(inv: dict):
    tmp = INVENTORY_FILE.with_suffix('.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(inv, f, indent=2, ensure_ascii=False)
    os.replace(tmp, INVENTORY_FILE)

# === Helpers ===

def is_admin(update: Update) -> bool:
    user = update.effective_user
    return bool(user and user.id in ADMIN_IDS)

async def ensure_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not is_admin(update):
        await update.effective_chat.send_message('⛔️ No autorizado.')
        return False
    return True

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    text = (
        '🤖 *SSH Bot listo*\n\n'
        'Usa /help para ver comandos.\n\n'
        '*Aviso de seguridad:*\n'
        '• Evita usar *root* directamente; usa usuarios con *sudo* limitado.\n'
        '• Las *contraseñas* se guardan encriptadas, pero es mejor usar *claves*.\n'
        '• Host key checking está *desactivado* por defecto; actívalo en *.env*.\n'
    )
    await update.effective_chat.send_message(text, parse_mode=ParseMode.MARKDOWN)

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    text = (
        '*Comandos disponibles*\n'
        '/servers - Lista servidores\n'
        '/addserver <alias> <host> <port> <user> <auth:key|password> <cred>\n'
        '   - Si auth=key, <cred>=nombre_de_clave (de /uploadkey)\n'
        '   - Si auth=password, usa luego /setpass <alias> <password>\n'
        '/delserver <alias> - Elimina servidor\n'
        '/uploadkey <nombre> (como caption del *documento* con la clave privada)\n'
        '/setpass <alias> <password> - (⚠️ Riesgoso) Guarda password (cifrado)\n'
        '/sh <alias> <comando> - Ejecuta un comando puntual\n'
    )
    await update.effective_chat.send_message(text, parse_mode=ParseMode.MARKDOWN)

async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    async with INV_LOCK:
        inv = load_inventory()
    if not inv['servers']:
        await update.effective_chat.send_message('No hay servidores registrados. Usa /addserver')
        return
    lines = ['*Servidores:*']
    for alias, s in inv['servers'].items():
        auth = s.get('auth')
        detail = s.get('key_name') if auth == 'key' else ('password✔️' if s.get('password') else 'password❌')
        lines.append(f"- `{alias}` → {s.get('user')}@{s.get('host')}:{s.get('port')}  auth={auth}({detail})")
    await update.effective_chat.send_message('\n'.join(lines), parse_mode=ParseMode.MARKDOWN)

async def cmd_addserver(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    args = context.args
    if len(args) != 6:
        await update.effective_chat.send_message(
            'Uso: /addserver <alias> <host> <port> <user> <auth:key|password> <cred>\n'
            'Ej.: /addserver web1 10.0.0.10 22 ubuntu key id_rsa_web1')
        return
    alias, host, port, user, auth, cred = args
    try:
        port = int(port)
        assert 1 <= port <= 65535
    except Exception:
        await update.effective_chat.send_message('Port inválido')
        return
    if auth not in ('key', 'password'):
        await update.effective_chat.send_message('auth debe ser key o password')
        return

    async with INV_LOCK:
        inv = load_inventory()
        if alias in inv['servers']:
            await update.effective_chat.send_message('Alias ya existe.')
            return
        entry = {"host": host, "port": port, "user": user, "auth": auth}
        if auth == 'key':
            entry['key_name'] = cred
        else:
            # password se establece con /setpass
            entry['password'] = None
        inv['servers'][alias] = entry
        await save_inventory(inv)
    await update.effective_chat.send_message(f'Servidor `{alias}` agregado.', parse_mode=ParseMode.MARKDOWN)

async def cmd_delserver(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    if len(context.args) != 1:
        await update.effective_chat.send_message('Uso: /delserver <alias>')
        return
    alias = context.args[0]
    async with INV_LOCK:
        inv = load_inventory()
        if alias not in inv['servers']:
            await update.effective_chat.send_message('Alias no encontrado')
            return
        del inv['servers'][alias]
        await save_inventory(inv)
    await update.effective_chat.send_message(f'Servidor `{alias}` eliminado.', parse_mode=ParseMode.MARKDOWN)

async def cmd_setpass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    if len(context.args) < 2:
        await update.effective_chat.send_message('Uso: /setpass <alias> <password>')
        return
    alias = context.args[0]
    password = ' '.join(context.args[1:])
    async with INV_LOCK:
        inv = load_inventory()
        s = inv['servers'].get(alias)
        if not s:
            await update.effective_chat.send_message('Alias no encontrado')
            return
        token = fernet.encrypt(password.encode()).decode()
        s['password'] = token
        s['auth'] = 'password'
        await save_inventory(inv)
    await update.effective_chat.send_message('Password guardado (cifrado). ⚠️ Considera usar claves en su lugar.')

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    doc = update.message.document
    if not doc:
        return
    caption = (doc.caption or '').strip()
    if not caption.startswith('/uploadkey'):
        await update.effective_chat.send_message('Para subir una clave usa el caption: /uploadkey <nombre>')
        return
    parts = caption.split(maxsplit=1)
    if len(parts) != 2:
        await update.effective_chat.send_message('Uso: /uploadkey <nombre> (en caption)')
        return
    key_name = parts[1].strip()
    if not key_name:
        await update.effective_chat.send_message('Nombre de clave inválido')
        return

    file = await context.bot.get_file(doc.file_id)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    dest = KEYS_DIR / key_name
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        await file.download_to_drive(custom_path=tmp.name)
        tmp_path = Path(tmp.name)
    tmp_path.replace(dest)
    os.chown(dest, os.getuid(), os.getgid())
    os.chmod(dest, 0o600)
    await update.effective_chat.send_message(f'Clave guardada como `{key_name}`', parse_mode=ParseMode.MARKDOWN)

async def run_ssh_command(server: dict, command: str, timeout: int = 60):
    host = server['host']
    port = server['port']
    user = server['user']
    auth = server['auth']

    client_keys = None
    password = None

    if auth == 'key':
        key_name = server.get('key_name')
        key_path = KEYS_DIR / key_name
        if not key_path.exists():
            return 1, '', f'Clave no encontrada: {key_path}'
        client_keys = [str(key_path)]
    else:
        token = server.get('password')
        if not token:
            return 1, '', 'No hay password configurado. Usa /setpass.'
        try:
            password = fernet.decrypt(token.encode()).decode()
        except Exception:
            return 1, '', 'No se pudo descifrar el password.'

    known_hosts = None
    if STRICT_HOST_KEY_CHECKING:
        known_hosts = str(KNOWN_HOSTS_FILE)

    try:
        async with asyncssh.connect(
            host=host,
            port=port,
            username=user,
            client_keys=client_keys,
            password=password,
            known_hosts=known_hosts,
        ) as conn:
            # Ejecutar bajo bash -lc para permitir expansión, PATH, etc.
            result = await asyncio.wait_for(
                conn.run(f"bash -lc {json.dumps(command)}", check=False),
                timeout=timeout,
            )
            stdout = result.stdout or ''
            stderr = result.stderr or ''
            return result.exit_status, stdout, stderr
    except asyncio.TimeoutError:
        return 124, '', 'Tiempo de espera agotado.'
    except Exception as e:
        logger.exception('Fallo SSH')
        return 255, '', f'Error SSH: {e}'

async def cmd_sh(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update, context):
        return
    if len(context.args) < 2:
        await update.effective_chat.send_message('Uso: /sh <alias> <comando>')
        return
    alias = context.args[0]
    command = ' '.join(context.args[1:])

    async with INV_LOCK:
        inv = load_inventory()
        server = inv['servers'].get(alias)
    if not server:
        await update.effective_chat.send_message('Alias no encontrado')
        return

    await update.effective_chat.send_message(f'Ejecutando en `{alias}`: \n```\n{command}\n```', parse_mode=ParseMode.MARKDOWN)
    code, out, err = await run_ssh_command(server, command)

    text = f"*Exit:* {code}\n"
    if out:
        text += f"\n*STDOUT:*\n```
{out[:3500]}
```\n"
    if err:
        text += f"\n*STDERR:*\n```
{err[:3500]}
```"

    # Si el output es muy grande, enviarlo como archivo
    if (out and len(out) > 3500) or (err and len(err) > 3500):
        # Guardar a archivo temporal y adjuntar
        TMP_DIR.mkdir(parents=True, exist_ok=True)
        tmp_file = TMP_DIR / f"out_{alias}_{int(asyncio.get_event_loop().time())}.txt"
        with tmp_file.open('w', encoding='utf-8') as f:
            if out:
                f.write('--- STDOUT ---\n')
                f.write(out)
                f.write('\n')
            if err:
                f.write('--- STDERR ---\n')
                f.write(err)
                f.write('\n')
        try:
            await update.effective_chat.send_document(InputFile(str(tmp_file), filename=tmp_file.name))
        except Exception:
            logger.exception('No se pudo enviar el archivo de salida')

    await update.effective_chat.send_message(text, parse_mode=ParseMode.MARKDOWN)


def build_app() -> Application:
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler('start', cmd_start))
    app.add_handler(CommandHandler('help', cmd_help))
    app.add_handler(CommandHandler('servers', cmd_servers))
    app.add_handler(CommandHandler('addserver', cmd_addserver))
    app.add_handler(CommandHandler('delserver', cmd_delserver))
    app.add_handler(CommandHandler('setpass', cmd_setpass))
    app.add_handler(CommandHandler('sh', cmd_sh))

    # Documentos (para /uploadkey con caption)
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    return app


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    app = build_app()
    logger.info('Iniciando bot (long polling)...')
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
PY

chmod +x "$APP_DIR/bot.py"
chown -R sshbot:sshbot "$APP_DIR"

# === .env ===
# Generar ENCRYPTION_KEY (32 bytes base64 urlsafe)
ENC_KEY=$(python3 - << 'PY'
import os, base64
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)

cat > "$APP_DIR/.env" << EOF
TELEGRAM_TOKEN=$TELEGRAM_TOKEN
ADMIN_USER_IDS=$ADMIN_IDS
DATA_DIR=$APP_DIR
KEYS_DIR=$KEYS_DIR
TMP_DIR=$TMP_DIR
ENCRYPTION_KEY=$ENC_KEY
STRICT_HOST_KEY_CHECKING=$STRICT_HOST_KEY_CHECKING
EOF

chmod 600 "$APP_DIR/.env"
chown sshbot:sshbot "$APP_DIR/.env"

# === systemd unit ===
cat > /etc/systemd/system/ssh-telegram-bot.service << 'UNIT'
[Unit]
Description=SSH Telegram Bot (long polling)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sshbot
WorkingDirectory=/opt/ssh-tg-bot
EnvironmentFile=/opt/ssh-tg-bot/.env
ExecStart=/opt/ssh-tg-bot/.venv/bin/python /opt/ssh-tg-bot/bot.py
Restart=always
RestartSec=5s
# Endurece el servicio (permitir escritura solo a /opt/ssh-tg-bot)
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/ssh-tg-bot
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ssh-telegram-bot
sleep 1
systemctl --no-pager --full status ssh-telegram-bot || true

echo
echo "============================================================"
echo "✅ Instalación completada."
echo "- Archivos en: /opt/ssh-tg-bot"
echo "- Logs: journalctl -u ssh-telegram-bot -f"
echo "- Comandos útiles:"
echo "    sudo systemctl restart ssh-telegram-bot"
echo "    sudo systemctl stop ssh-telegram-bot"
echo "- Sube claves con: enviar *documento* a tu bot con caption: /uploadkey NOMBRE"
echo "- Agrega servidor con: /addserver alias host 22 usuario key NOMBRE"
echo "- Ejecuta comando: /sh alias 'uname -a'"
echo "============================================================"
