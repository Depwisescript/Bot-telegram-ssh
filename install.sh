#!/usr/bin/env bash
# setup_ssh_tg_bot_v2.sh - Instalador seguro (no rompe acceso SSH) para el bot de Telegram + SSH
# - No habilita UFW sin tu confirmación
# - Si UFW ya está habilitado, agrega reglas para *todos* los puertos de sshd detectados
# - Incluye bot.py corregido (sin f-strings problemáticas)

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Ejecuta como root: sudo bash setup_ssh_tg_bot_v2.sh" >&2
  exit 1
fi

read -rp "Pega tu TELEGRAM_TOKEN: " TELEGRAM_TOKEN
[[ -n "$TELEGRAM_TOKEN" ]] || { echo "Token vacío"; exit 1; }
read -rp "IDs de admins (separados por coma): " ADMIN_IDS
[[ -n "$ADMIN_IDS" ]] || { echo "Debes indicar al menos un ID"; exit 1; }
read -rp "¿Habilitar verificación estricta de host key SSH? (y/N): " STRICT
STRICT=${STRICT:-N}
[[ "$STRICT" =~ ^[Yy]$ ]] && STRICT_HOST_KEY_CHECKING=true || STRICT_HOST_KEY_CHECKING=false

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y python3 python3-venv python3-pip ufw \
  build-essential python3-dev libffi-dev libssl-dev

APP_DIR=/opt/ssh-tg-bot
KEYS_DIR="$APP_DIR/keys"
TMP_DIR="$APP_DIR/tmp"
mkdir -p "$APP_DIR" "$KEYS_DIR" "$TMP_DIR"

id -u sshbot &>/dev/null || useradd -r -s /usr/sbin/nologin sshbot
chown -R sshbot:sshbot "$APP_DIR"
chmod 700 "$KEYS_DIR" "$TMP_DIR"

python3 -m venv "$APP_DIR/.venv"
source "$APP_DIR/.venv/bin/activate"
python -m pip install --upgrade pip
cat > "$APP_DIR/requirements.txt" << 'REQ'
python-telegram-bot[rate-limiter]==21.*
asyncssh>=2.14.0
cryptography>=41.0.0
python-dotenv>=1.0.0
REQ
pip install -r "$APP_DIR/requirements.txt"

# Escribir bot.py corregido
cat > "$APP_DIR/bot.py" << 'PY'
#!/usr/bin/env python3
"""
SSH Telegram Bot (long polling)
- Admins por ID (ENV ADMIN_USER_IDS)
- Inventario de servidores en JSON
- Claves privadas via /uploadkey (como documento con caption)
- Passwords cifrados con Fernet (opcional)
- Ejecuta comandos con /sh <alias> <comando>

Nota: Evita usar root; prefiere usuarios con sudo limitado.
"""
import os
import json
import asyncio
import logging
import tempfile
from pathlib import Path

import asyncssh
from cryptography.fernet import Fernet
from telegram import Update, InputFile
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
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
ADMIN_IDS = {int(x.strip()) for x in os.getenv('ADMIN_USER_IDS', '').split(',') if x.strip().isdigit()}
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
if not ENCRYPTION_KEY:
    raise SystemExit('Falta ENCRYPTION_KEY en .env')

try:
    fernet = Fernet(ENCRYPTION_KEY.encode())
except Exception as e:
    raise SystemExit(f'ENCRYPTION_KEY inválida: {e}')

INV_LOCK = asyncio.Lock()

# === Inventario ===

def load_inventory() -> dict:
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

async def ensure_admin(update: Update) -> bool:
    if not is_admin(update):
        await update.effective_chat.send_message('⛔️ No autorizado.')
        return False
    return True

# === Comandos ===

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
        return
    text = (
        '🤖 *SSH Bot listo*\n\n'
        'Usa /help para ver comandos.\n\n'
        '*Seguridad:*\n'
        '• Evita usar *root*; usa cuentas con *sudo* limitado.\n'
        '• Prefiere *claves* en lugar de *passwords*.\n'
        '• Host key checking está desactivado por defecto; puedes activarlo en .env.\n'
    )
    await update.effective_chat.send_message(text, parse_mode=ParseMode.MARKDOWN)

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
        return
    text = (
        '*Comandos*\n'
        '/servers - Lista servidores\n'
        '/addserver <alias> <host> <port> <user> <auth:key|password> <cred>\n'
        '   - Si auth=key, <cred>=nombre_de_clave (subida con /uploadkey)\n'
        '   - Si auth=password, usa luego /setpass <alias> <password>\n'
        '/delserver <alias>\n'
        '/uploadkey <nombre> (como caption del *documento* con la clave privada)\n'
        '/setpass <alias> <password> (⚠️ menos seguro que claves)\n'
        '/sh <alias> <comando>\n'
    )
    await update.effective_chat.send_message(text, parse_mode=ParseMode.MARKDOWN)

async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
        return
    async with INV_LOCK:
        inv = load_inventory()
    if not inv['servers']:
        await update.effective_chat.send_message('No hay servidores. Usa /addserver')
        return
    lines = ['*Servidores:*']
    for alias, s in inv['servers'].items():
        user = s.get('user')
        host = s.get('host')
        port = s.get('port')
        auth = s.get('auth')
        detail = s.get('key_name') if auth == 'key' else ('password✔️' if s.get('password') else 'password❌')
        lines.append(f"- `{alias}` → {user}@{host}:{port}  auth={auth}({detail})")
    await update.effective_chat.send_message('\n'.join(lines), parse_mode=ParseMode.MARKDOWN)

async def cmd_addserver(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
        return
    args = context.args
    if len(args) != 6:
        await update.effective_chat.send_message(
            'Uso: /addserver <alias> <host> <port> <user> <auth:key|password> <cred>\n'
            'Ej.: /addserver web1 10.0.0.10 22 ubuntu key id_rsa_web1'
        )
        return
    alias, host, port_s, user, auth, cred = args
    try:
        port = int(port_s)
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
            await update.effective_chat.send_message('Alias ya existe')
            return
        entry = {"host": host, "port": port, "user": user, "auth": auth}
        if auth == 'key':
            entry['key_name'] = cred
        else:
            entry['password'] = None
        inv['servers'][alias] = entry
        await save_inventory(inv)
    await update.effective_chat.send_message(f'Servidor `{alias}` agregado.', parse_mode=ParseMode.MARKDOWN)

async def cmd_delserver(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
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
    if not await ensure_admin(update):
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
    await update.effective_chat.send_message('Password guardado (cifrado). Considera usar claves.')

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_admin(update):
        return
    doc = update.message.document
    if not doc:
        return
    caption = (doc.caption or '').strip()
    if not caption.startswith('/uploadkey'):
        await update.effective_chat.send_message('Para subir una clave usa caption: /uploadkey <nombre>')
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
            # Ejecutar bajo bash -lc para permitir expansión/variables
            cmd_json = json.dumps(command)
            result = await asyncio.wait_for(
                conn.run(f"bash -lc {cmd_json}", check=False),
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
    if not await ensure_admin(update):
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

    msg_exec = f'Ejecutando en `{alias}`:\n```\n{command}\n```'
    await update.effective_chat.send_message(msg_exec, parse_mode=ParseMode.MARKDOWN)

    code, out, err = await run_ssh_command(server, command)

    parts = [f"*Exit:* {code}"]
    if out:
        parts.append("\n*STDOUT:*\n```\n" + out[:3500] + "\n```")
    if err:
        parts.append("\n*STDERR:*\n```\n" + err[:3500] + "\n```")
    text = ''.join(parts)

    if (out and len(out) > 3500) or (err and len(err) > 3500):
        TMP_DIR.mkdir(parents=True, exist_ok=True)
        tmp_file = TMP_DIR / f"out_{alias}_{int(asyncio.get_event_loop().time())}.txt"
        with tmp_file.open('w', encoding='utf-8') as f:
            if out:
                f.write('--- STDOUT ---\n')
                f.write(out)
            if err:
                f.write('\n--- STDERR ---\n')
                f.write(err)
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

# Generar ENCRYPTION_KEY
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

# Crear servicio systemd
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

# ===== Manejo UFW seguro =====
# Detectar puertos SSH y asegurarlos en UFW si ya está habilitado o si el usuario decide habilitarlo

# Detectar puertos de sshd
ports=()
if command -v ss >/dev/null 2>&1; then
  while IFS= read -r line; do
    p=${line##*:}
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  done < <(ss -tlnp 2>/dev/null | awk '/sshd/ {print $4}')
fi
if [[ ${#ports[@]} -eq 0 && -r /etc/ssh/sshd_config ]]; then
  while IFS= read -r p; do
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  done < <(awk '/^\s*Port\s+/ {print $2}' /etc/ssh/sshd_config)
fi
[[ ${#ports[@]} -eq 0 ]] && ports=(22)

# Unicos
uniq_ports=()
for p in "${ports[@]}"; do
  skip=false
  for q in "${uniq_ports[@]}"; do
    if [[ "$p" == "$q" ]]; then skip=true; break; fi
  done
  $skip || uniq_ports+=("$p")
done

ufw_enabled=$(ufw status | head -n1 | grep -qi active && echo yes || echo no)

if [[ "$ufw_enabled" == "yes" ]]; then
  echo "[INFO] UFW ya está habilitado. Asegurando puertos SSH: ${uniq_ports[*]}"
  for p in "${uniq_ports[@]}"; do ufw allow ${p}/tcp || true; done
  ufw status numbered || true
else
  read -rp "¿Deseas habilitar UFW ahora y permitir SSH en puertos ${uniq_ports[*]}? (y/N): " ENABLE_UFW
  ENABLE_UFW=${ENABLE_UFW:-N}
  if [[ "$ENABLE_UFW" =~ ^[Yy]$ ]]; then
    for p in "${uniq_ports[@]}"; do ufw allow ${p}/tcp || true; done
    ufw --force enable || true
    ufw status numbered || true
  else
    echo "[INFO] UFW permanece deshabilitado. Puedes habilitar luego manualmente."
  fi
fi

echo "\n============================================================"
echo "✅ Instalación completada (v2)."
echo "- Archivos en: /opt/ssh-tg-bot"
echo "- Servicio: ssh-telegram-bot (journalctl -u ssh-telegram-bot -f)"
echo "- UFW: configurado de forma segura (sin bloquear tu SSH)"
echo "- Para recuperar SSH en caso de emergencia: ufw_ssh_recovery.sh --disable"
echo "============================================================"
