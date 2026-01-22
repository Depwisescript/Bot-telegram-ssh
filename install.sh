#!/usr/bin/env bash
# install_tg_ssh_bot_envfirst.sh
# Instala/actualiza un bot de Telegram para administrar varios servidores vía SSH (Ubuntu 24.04)
# Habilita por defecto /custom y modo shell, y permite agregar hosts desde Telegram.
# *** Esta variante CARGA un .env existente ANTES de verificar el token/IDs ***

set -euo pipefail

########################
# CONFIGURACIÓN RÁPIDA #
########################

# Valores por defecto (se pueden sobrescribir desde .env si ya existe)
TELEGRAM_BOT_TOKEN="PON_AQUI_TU_TOKEN"     # BotFather token (obligatorio si no hay .env)
ALLOWED_USER_IDS="123456789"               # IDs permitidos (coma-separados)
BOT_USER="tg-bot"                          # usuario linux del bot
BOT_HOME="/opt/tg-bot"
HOSTS_FILE="${BOT_HOME}/hosts.yaml"
ENV_FILE="${BOT_HOME}/.env"
PY_SCRIPT="${BOT_HOME}/bot_ssh_multi.py"
SERVICE_NAME="tg-ssh-multi"
VENV_PATH="${BOT_HOME}/venv"
SSH_DIR="${BOT_HOME}/.ssh"
BOT_SSH_KEY="${SSH_DIR}/id_ed25519"

# Opciones por defecto (puedes cambiarlas luego en .env)
ALLOW_SHELL="true"        # habilitado por defecto ⚠️
ALLOW_CUSTOM="true"       # habilitado por defecto ⚠️
RATE_LIMIT="10"
RATE_WINDOW_SEC="60"
MAX_REPLY_CHARS="3500"

# Seguridad SSH (por defecto más permisivo para usabilidad)
# Si lo pones en "true", el bot sólo conectará a hosts cuya clave esté en known_hosts
STRICT_HOST_KEY="false"   # true = verifica host keys (recomendado), false = auto-acepta

###################################
# CARGA .env ANTES DE VERIFICAR   #
###################################

# Si ya existe un despliegue anterior, intenta cargarlo para no exigir edición del script
if [[ -f "${ENV_FILE}" ]]; then
  echo "==> Cargando variables desde ${ENV_FILE}"
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
fi

###################################
# VERIFICACIONES Y PREPARATIVOS   #
###################################

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

# Validar token tras posible carga del .env
if [[ -z "${TELEGRAM_BOT_TOKEN}" || "${TELEGRAM_BOT_TOKEN}" == "PON_AQUI_TU_TOKEN" ]]; then
  echo "❌ Debes configurar TELEGRAM_BOT_TOKEN (en el script o en ${ENV_FILE})." >&2
  exit 1
fi

if [[ -z "${ALLOWED_USER_IDS}" || "${ALLOWED_USER_IDS}" == "123456789" ]]; then
  echo "⚠️ AVISO: ALLOWED_USER_IDS no parece configurado con tu(s) ID(s) reales." >&2
  echo "   Puedes continuar, pero el bot no funcionará para ti si no coincide." >&2
fi

echo "==> Instalación/Actualización del bot en ${BOT_HOME} (usuario: ${BOT_USER})"

#############################
# PAQUETES Y USUARIO SISTEMA
#############################

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  python3-venv python3-pip python3-dev gcc \
  openssh-client ca-certificates

# Crear usuario de sistema para el bot (si no existe)
if ! id -u "${BOT_USER}" >/dev/null 2>&1; then
  adduser --system --group --home "${BOT_HOME}" "${BOT_USER}"
fi

mkdir -p "${BOT_HOME}"
chown -R "${BOT_USER}:${BOT_USER}" "${BOT_HOME}"
chmod 0755 "${BOT_HOME}"

########################################
# MODO ACTUALIZACIÓN SEGURA (BACKUP)
########################################

BACKUP_DIR="${BOT_HOME}/.backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${BACKUP_DIR}"

# Si existe un despliegue previo, respáldalo
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
  echo "==> Detectado servicio previo. Parando para actualizar…"
  systemctl stop "${SERVICE_NAME}" || true
fi

# Respaldos de archivos clave si existen
for f in "${HOSTS_FILE}" "${ENV_FILE}" "${PY_SCRIPT}" \
         "/etc/systemd/system/${SERVICE_NAME}.service"; do
  if [[ -f "$f" ]]; then
    cp -a "$f" "${BACKUP_DIR}/" || true
  fi
done
if [[ -d "${SSH_DIR}" ]]; then
  mkdir -p "${BACKUP_DIR}/.ssh"
  cp -a "${SSH_DIR}"/* "${BACKUP_DIR}/.ssh/" 2>/dev/null || true
fi

##################################
# ENTORNO PYTHON Y DEPENDENCIAS  #
##################################

sudo -u "${BOT_USER}" python3 -m venv "${VENV_PATH}"
sudo -u "${BOT_USER}" "${VENV_PATH}/bin/pip" install --upgrade pip
# Librerías necesarias
sudo -u "${BOT_USER}" "${VENV_PATH}/bin/pip" install \
  "python-telegram-bot==20.*" paramiko pyyaml

#############################
# CLAVES SSH DEL BOT (LOCAL)
#############################

sudo -u "${BOT_USER}" mkdir -p "${SSH_DIR}"
chmod 0700 "${SSH_DIR}"
if [[ ! -f "${BOT_SSH_KEY}" ]]; then
  sudo -u "${BOT_USER}" ssh-keygen -t ed25519 -f "${BOT_SSH_KEY}" -N '' -C "${BOT_USER}@bot"
fi
chmod 0600 "${BOT_SSH_KEY}"

PUBKEY_CONTENT="$(sudo -u "${BOT_USER}" cat "${BOT_SSH_KEY}.pub")"

#############################
# ARCHIVO hosts.yaml (si no existe, plantilla)
#############################

if [[ ! -f "${HOSTS_FILE}" ]]; then
  sudo -u "${BOT_USER}" tee "${HOSTS_FILE}" >/dev/null <<'YAML'
# hosts.yaml: Define alias, destino SSH y whitelist de comandos por servidor.
# Puedes añadir/editar hosts desde Telegram con /addhost o /menu.

# Ejemplos:

prod1:
  host: 10.0.0.10
  port: 22
  user: tgadmin
  key_path: /opt/tg-bot/.ssh/id_ed25519
  whitelist:
    status: "uptime && who && uname -a"
    disco: "df -h"
    memoria: "free -h"

# db:
#   host: 10.0.0.20
#   port: 22
#   user: tgadmin
#   key_path: /opt/tg-bot/.ssh/id_ed25519
#   whitelist:
#     status: "uptime && uname -a"
YAML
  chown "${BOT_USER}:${BOT_USER}" "${HOSTS_FILE}"
  chmod 0600 "${HOSTS_FILE}"
fi

#############################
# ARCHIVO .env (crea si no existe)
#############################

if [[ ! -f "${ENV_FILE}" ]]; then
  sudo -u "${BOT_USER}" tee "${ENV_FILE}" >/dev/null <<ENV
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
ALLOWED_USER_IDS=${ALLOWED_USER_IDS}
BOT_HOME=${BOT_HOME}
HOSTS_FILE=${HOSTS_FILE}
ALLOW_SHELL=${ALLOW_SHELL}
ALLOW_CUSTOM=${ALLOW_CUSTOM}
STRICT_HOST_KEY=${STRICT_HOST_KEY}
RATE_LIMIT=${RATE_LIMIT}
RATE_WINDOW_SEC=${RATE_WINDOW_SEC}
MAX_REPLY_CHARS=${MAX_REPLY_CHARS}
ENV
  chown "${BOT_USER}:${BOT_USER}" "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
else
  echo "==> Conservando configuración existente en ${ENV_FILE} (no sobrescrito)."
fi

#############################
# SCRIPT PRINCIPAL PYTHON
#############################

sudo -u "${BOT_USER}" tee "${PY_SCRIPT}" >/dev/null <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import html
import yaml
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, Tuple

import paramiko
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, ContextTypes, MessageHandler, filters,
    ConversationHandler, CallbackQueryHandler
)

# ================== ENTORNO ==================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ALLOWED_USER_IDS = {int(x) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x.strip().isdigit()}
BOT_HOME = os.getenv("BOT_HOME", "/opt/tg-bot")
HOSTS_FILE = os.getenv("HOSTS_FILE", f"{BOT_HOME}/hosts.yaml")
ALLOW_SHELL = os.getenv("ALLOW_SHELL", "false").lower() == "true"
ALLOW_CUSTOM = os.getenv("ALLOW_CUSTOM", "false").lower() == "true"
STRICT_HOST_KEY = os.getenv("STRICT_HOST_KEY", "false").lower() == "true"
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))
RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
MAX_REPLY_CHARS = int(os.getenv("MAX_REPLY_CHARS", "3500"))
RATE_WINDOW = timedelta(seconds=RATE_WINDOW_SEC)

BLOCKED_SUBSTR = [
    " shutdown", "reboot", "halt", "poweroff", "init 0", ":(){:|:&};:",
    " mkfs", " dd if=", " rm -rf /", "userdel ", " groupdel ", " visudo",
    " --no-preserve-root"
]

DANGEROUS_TOKENS = [';', '&&', '||', '|', '`', '$(', ')', '>', '<', '*', '{', '}', '&', '\n']

hosts: Dict[str, Dict[str, Any]] = {}
rate_buckets = defaultdict(lambda: deque())
shell_sessions: Dict[int, Dict[str, Any]] = {}  # chat_id -> session dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tg-ssh-multi")

# ================== UTILIDADES ==================

def is_authorized(update: Update) -> bool:
    user = update.effective_user
    chat = update.effective_chat
    return bool(user and chat and chat.type == "private" and user.id in ALLOWED_USER_IDS)

def check_rate_limit(user_id: int) -> bool:
    dq = rate_buckets[user_id]
    now = datetime.utcnow()
    while dq and now - dq[0] > RATE_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT:
        return False
    dq.append(now)
    return True

def load_hosts() -> None:
    global hosts
    if not os.path.exists(HOSTS_FILE):
        raise RuntimeError(f"No existe {HOSTS_FILE}")
    with open(HOSTS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    norm = {}
    for alias, cfg in data.items():
        if not isinstance(cfg, dict):
            continue
        alias_l = str(alias).strip().lower()
        norm[alias_l] = {
            "host": cfg.get("host"),
            "port": int(cfg.get("port", 22)),
            "user": cfg.get("user", "tgadmin"),
            "key_path": cfg.get("key_path", f"{BOT_HOME}/.ssh/id_ed25519"),
            "whitelist": cfg.get("whitelist", {}) or {}
        }
    hosts = norm
    logger.info("Cargados %d hosts desde %s", len(hosts), HOSTS_FILE)

def save_hosts() -> None:
    # Escritura atómica con permisos seguros
    tmp_path = HOSTS_FILE + ".tmp"
    with open(HOSTS_FILE, "r", encoding="utf-8") as f:
        current = yaml.safe_load(f) or {}
    # Reconstruye con el mismo contenido normalizado de 'hosts'
    out = {}
    for alias, cfg in hosts.items():
        out[alias] = {
            "host": cfg.get("host"),
            "port": int(cfg.get("port", 22)),
            "user": cfg.get("user", "tgadmin"),
            "key_path": cfg.get("key_path", f"{BOT_HOME}/.ssh/id_ed25519"),
            "whitelist": cfg.get("whitelist", {}) or {}
        }
    with open(tmp_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, allow_unicode=True, sort_keys=True)
    os.replace(tmp_path, HOSTS_FILE)
    try:
        os.chmod(HOSTS_FILE, 0o600)
    except Exception:
        pass


def get_host_cfg(alias: str) -> Dict[str, Any]:
    a = alias.strip().lower()
    if a not in hosts:
        raise KeyError(f"Alias no encontrado: {alias}")
    cfg = hosts[a]
    for k in ("host", "port", "user", "key_path"):
        if not cfg.get(k):
            raise RuntimeError(f"Configuración incompleta para {alias}: falta '{k}'")
    return cfg


def get_ssh_client_for(alias: str) -> paramiko.SSHClient:
    cfg = get_host_cfg(alias)
    key_path = cfg["key_path"]
    pkey = None
    last_ex = None
    for loader in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            pkey = loader.from_private_key_file(key_path)
            break
        except Exception as e:
            last_ex = e
    if pkey is None:
        raise RuntimeError(f"No se pudo cargar la clave {key_path}: {last_ex}")
    cli = paramiko.SSHClient()
    if STRICT_HOST_KEY:
        # Verificación estricta de host keys usando known_hosts del bot
        kh_path = os.path.join(BOT_HOME, ".ssh", "known_hosts")
        if os.path.exists(kh_path):
            cli.load_host_keys(kh_path)
        cli.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(
        hostname=cfg["host"], port=cfg["port"], username=cfg["user"],
        pkey=pkey, look_for_keys=False, allow_agent=False,
        timeout=10, banner_timeout=10, auth_timeout=10
    )
    return cli


def run_cmd_ssh(alias: str, command: str, timeout: int = 25) -> Tuple[str, str, int]:
    cli = None
    try:
        cli = get_ssh_client_for(alias)
        stdin, stdout, stderr = cli.exec_command(command, timeout=timeout, get_pty=True)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        return out, err, code
    finally:
        try:
            if cli: cli.close()
        except Exception:
            pass


async def reply_pre(update: Update, text: str):
    if len(text) > MAX_REPLY_CHARS:
        text = "…(truncado)…\n" + text[-MAX_REPLY_CHARS:]
    esc = html.escape(text)
    await update.effective_message.reply_text(f"<pre>{esc}</pre>", parse_mode=ParseMode.HTML, disable_web_page_preview=True)

async def reply_html(update: Update, html_text: str):
    await update.effective_message.reply_text(html_text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

async def reply_text(update: Update, text: str):
    await update.effective_message.reply_text(text, disable_web_page_preview=True)


def contains_blocked(cmd: str) -> bool:
    c = f" {cmd.strip()} ".lower()
    if any(tok in cmd for tok in DANGEROUS_TOKENS):
        return True
    return any(b in c for b in BLOCKED_SUBSTR)

# ================== COMANDOS ==================

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    text = (
        "🤖 <b>Bot SSH multi-servidor</b>\n\n"
        "• /hosts — listar servidores\n"
        "• /run &lt;alias&gt; &lt;nombre&gt; — ejecutar un comando permitido\n"
        f"• /custom &lt;alias&gt; &lt;cmd&gt; — {'(habilitado ⚠️)' if ALLOW_CUSTOM else '(deshabilitado)'}\n"
        "• /reload — recargar hosts.yaml\n"
        "• /addhost — asistente para agregar un host\n"
        "• /trust &lt;alias&gt; — registrar host key en known_hosts (si STRICT_HOST_KEY=true)\n\n"
        f"<b>Modo consola</b> {'(habilitado ⚠️)' if ALLOW_SHELL else '(deshabilitado)'}\n"
        "• /connect &lt;alias&gt; — abrir sesión\n"
        "• /sh &lt;cmd&gt; — ejecutar comando\n"
        "• /close — cerrar sesión\n\n"
        "• /menu — abrir menú\n"
        "⚠️ Recomendado: usar whitelist y evitar secretos por Telegram."
    )
    await reply_html(update, text)

async def cmd_hosts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    rows = []
    for alias, cfg in hosts.items():
        wl = cfg.get("whitelist", {})
        rows.append(f"- {alias}: {cfg.get('host')}:{cfg.get('port')} (user={cfg.get('user')}) | whitelist={len(wl)} cmds")
    await reply_pre(update, "\n".join(rows) if rows else "No hay hosts configurados.")

async def cmd_reload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    try:
        load_hosts()
        await reply_text(update, "✅ hosts.yaml recargado.")
    except Exception as e:
        await reply_text(update, f"❌ Error recargando: {e}")

async def cmd_run(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await reply_text(update, "⏳ Demasiadas solicitudes.")
        return
    if len(context.args) < 2:
        await reply_text(update, "Uso: /run <alias> <nombre_whitelist>")
        return
    alias = context.args[0].strip().lower()
    name = context.args[1].strip().lower()
    try:
        cfg = get_host_cfg(alias)
        wl = cfg.get("whitelist", {})
        if name not in wl:
            await reply_text(update, f"❌ No permitido en '{alias}': {name}")
            return
        command = wl[name]
        await reply_text(update, f"▶️ {alias}$ {name} …")
        out, err, code = await asyncio.to_thread(run_cmd_ssh, alias, command)
        msg = out.strip() or "(sin salida)"
        if err.strip():
            msg += f"\n--- STDERR ---\n{err.strip()}"
        msg += f"\n\n[exit={code}]"
        await reply_pre(update, msg)
    except Exception as e:
        await reply_text(update, f"❌ Error: {e}")

async def cmd_custom(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    if not ALLOW_CUSTOM:
        await reply_text(update, "🚫 /custom deshabilitado.")
        return
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await reply_text(update, "⏳ Demasiadas solicitudes.")
        return
    if len(context.args) < 2:
        await reply_text(update, "Uso: /custom <alias> <comando>")
        return
    alias = context.args[0].strip().lower()
    command = " ".join(context.args[1:])
    if contains_blocked(command):
        await reply_text(update, "🚫 Comando bloqueado por seguridad.")
        return
    try:
        await reply_text(update, f"▶️ {alias}$ {html.escape(command)}")
        out, err, code = await asyncio.to_thread(run_cmd_ssh, alias, command)
        msg = out.strip() or "(sin salida)"
        if err.strip():
            msg += f"\n--- STDERR ---\n{err.strip()}"
        msg += f"\n\n[exit={code}]"
        await reply_pre(update, msg)
    except Exception as e:
        await reply_text(update, f"❌ Error: {e}")

async def cmd_connect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    if not ALLOW_SHELL:
        await reply_text(update, "🚫 Modo consola deshabilitado.")
        return
    if not context.args:
        await reply_text(update, "Uso: /connect <alias>")
        return
    alias = context.args[0].strip().lower()
    chat_id = update.effective_chat.id
    if chat_id in shell_sessions:
        await reply_text(update, f"Ya hay una sesión abierta ({shell_sessions[chat_id]['alias']}). Usa /close.")
        return
    try:
        client = get_ssh_client_for(alias)
        chan = client.invoke_shell(term="xterm", width=120, height=32)
        chan.settimeout(1.0)
        await asyncio.sleep(0.5)
        _ = chan.recv(1024) if chan.recv_ready() else b""
        shell_sessions[chat_id] = {"alias": alias, "client": client, "chan": chan, "last": datetime.utcnow()}
        await reply_html(update, f"✅ Sesión abierta en <b>{html.escape(alias)}</b>. Usa /sh &lt;cmd&gt;.")
    except Exception as e:
        await reply_text(update, f"❌ No se pudo abrir la sesión: {e}")

async def cmd_sh(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    if not ALLOW_SHELL:
        await reply_text(update, "🚫 Modo consola deshabilitado.")
        return
    chat_id = update.effective_chat.id
    sess = shell_sessions.get(chat_id)
    if not sess:
        await reply_text(update, "No hay sesión abierta. Usa /connect <alias>.")
        return
    if not context.args:
        await reply_text(update, "Uso: /sh <comando>")
        return
    cmd = " ".join(context.args)
    if contains_blocked(cmd):
        await reply_text(update, "🚫 Comando bloqueado por seguridad.")
        return
    try:
        chan = sess["chan"]
        chan.send(cmd + "\n")
        output = []
        for _ in range(16):
            await asyncio.sleep(0.6)
            if chan.recv_ready():
                output.append(chan.recv(4096).decode(errors="replace"))
            else:
                break
        text = "".join(output).strip() or "(sin salida)"
        sess["last"] = datetime.utcnow()
        await reply_pre(update, text)
    except Exception as e:
        await reply_text(update, f"❌ Error ejecutando: {e}")

async def cmd_close(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    chat_id = update.effective_chat.id
    sess = shell_sessions.pop(chat_id, None)
    try:
        if sess:
            try: sess["chan"].close()
            except Exception: pass
            try: sess["client"].close()
            except Exception: pass
        await reply_text(update, "🔒 Sesión cerrada.")
    except Exception:
        await reply_text(update, "Sesión cerrada.")

# ====== TRUST HOST KEY ======
async def cmd_trust(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    if not context.args:
        return await reply_text(update, "Uso: /trust <alias>")
    alias = context.args[0].strip().lower()
    try:
        cfg = get_host_cfg(alias)
        host = cfg['host']
        port = int(cfg.get('port', 22))
        kh_dir = os.path.join(BOT_HOME, ".ssh")
        os.makedirs(kh_dir, exist_ok=True)
        kh_path = os.path.join(kh_dir, "known_hosts")
        cmd = ["ssh-keyscan", "-p", str(port), host]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0 or not res.stdout.strip():
            return await reply_text(update, f"❌ ssh-keyscan falló para {host}:{port}: {res.stderr.strip()}")
        with open(kh_path, "a", encoding="utf-8") as f:
            f.write(res.stdout)
        try:
            os.chmod(kh_path, 0o644)
        except Exception:
            pass
        await reply_text(update, f"✅ Host key agregada a known_hosts para {alias} ({host}:{port}).")
    except Exception as e:
        await reply_text(update, f"❌ Error: {e}")

# ====== MENÚ E INTERFAZ PARA AGREGAR HOST ======
AH_ALIAS, AH_HOST, AH_PORT, AH_USER, AH_KEY_PATH, AH_CONFIRM = range(6)

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    kb = [
        [InlineKeyboardButton("➕ Añadir host", callback_data="menu_addhost")],
        [InlineKeyboardButton("📋 Hosts", callback_data="menu_hosts"), InlineKeyboardButton("🔄 Recargar", callback_data="menu_reload")]
    ]
    await update.effective_message.reply_text(
        "Elige una opción:", reply_markup=InlineKeyboardMarkup(kb)
    )

async def on_menu_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    q = update.callback_query
    await q.answer()
    if q.data == "menu_addhost":
        # inicia asistente
        return await addhost_start(update, context, via_callback=True)
    elif q.data == "menu_hosts":
        # muestra hosts
        rows = []
        for alias, cfg in hosts.items():
            wl = cfg.get("whitelist", {})
            rows.append(f"- {alias}: {cfg.get('host')}:{cfg.get('port')} (user={cfg.get('user')}) | whitelist={len(wl)} cmds")
        return await q.edit_message_text("No hay hosts configurados." if not rows else "\n".join(rows))
    elif q.data == "menu_reload":
        try:
            load_hosts()
            return await q.edit_message_text("✅ hosts.yaml recargado.")
        except Exception as e:
            return await q.edit_message_text(f"❌ Error recargando: {e}")

async def addhost_start(update: Update, context: ContextTypes.DEFAULT_TYPE, via_callback: bool=False):
    if not is_authorized(update):
        return ConversationHandler.END
    context.user_data.clear()
    msg = "Vamos a agregar un host.\nIngresa <b>alias</b> (sin espacios):"
    if via_callback:
        await update.callback_query.edit_message_text(msg, parse_mode=ParseMode.HTML)
    else:
        await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)
    return AH_ALIAS

async def ah_alias(update: Update, context: ContextTypes.DEFAULT_TYPE):
    alias = update.effective_message.text.strip().lower()
    if not alias or ' ' in alias or ':' in alias:
        await reply_text(update, "Alias inválido. Intenta de nuevo (sin espacios).")
        return AH_ALIAS
    context.user_data['alias'] = alias
    await reply_text(update, "Ingresa <b>host</b> o IP:")
    return AH_HOST

async def ah_host(update: Update, context: ContextTypes.DEFAULT_TYPE):
    host = update.effective_message.text.strip()
    if not host:
        await reply_text(update, "Host inválido. Intenta de nuevo.")
        return AH_HOST
    context.user_data['host'] = host
    await reply_text(update, "Ingresa <b>puerto</b> (por defecto 22):")
    return AH_PORT

async def ah_port(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.effective_message.text.strip()
    if not txt:
        port = 22
    else:
        if not txt.isdigit():
            await reply_text(update, "Debe ser numérico. Escribe el puerto (ej. 22).")
            return AH_PORT
        port = int(txt)
        if not (1 <= port <= 65535):
            await reply_text(update, "Puerto fuera de rango. Intenta de nuevo.")
            return AH_PORT
    context.user_data['port'] = port
    await reply_text(update, "Ingresa <b>usuario</b> SSH (por defecto tgadmin):")
    return AH_USER

async def ah_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_message.text.strip() or 'tgadmin'
    context.user_data['user'] = user
    default_key = f"{BOT_HOME}/.ssh/id_ed25519"
    await reply_text(update, f"Ruta de clave privada (por defecto {default_key}):")
    return AH_KEY_PATH

async def ah_key_path(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key_path = update.effective_message.text.strip() or f"{BOT_HOME}/.ssh/id_ed25519"
    context.user_data['key_path'] = key_path
    alias = context.user_data['alias']
    host = context.user_data['host']
    port = context.user_data['port']
    user = context.user_data['user']
    text = (
        "<b>Confirmar nuevo host</b>\n"
        f"alias: <code>{html.escape(alias)}</code>\n"
        f"host: <code>{html.escape(host)}</code>\n"
        f"port: <code>{port}</code>\n"
        f"user: <code>{html.escape(user)}</code>\n"
        f"key: <code>{html.escape(key_path)}</code>\n\n"
        "Se creará una whitelist base (status, disco, memoria). ¿Confirmas?"
    )
    kb = [[InlineKeyboardButton("✅ Confirmar", callback_data="ah_ok"), InlineKeyboardButton("❌ Cancelar", callback_data="ah_cancel")]]
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(kb))
    return AH_CONFIRM

async def ah_confirm_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return ConversationHandler.END
    q = update.callback_query
    await q.answer()
    if q.data == 'ah_cancel':
        await q.edit_message_text("Operación cancelada.")
        return ConversationHandler.END
    data = context.user_data
    alias = data['alias']
    hosts[alias] = {
        'host': data['host'],
        'port': data['port'],
        'user': data['user'],
        'key_path': data['key_path'],
        'whitelist': {
            'status': 'uptime && uname -a',
            'disco': 'df -h',
            'memoria': 'free -h'
        }
    }
    try:
        save_hosts()
        load_hosts()
        await q.edit_message_text(f"✅ Host '{alias}' agregado. Usa /reload si es necesario.")
    except Exception as e:
        await q.edit_message_text(f"❌ Error guardando: {e}")
    return ConversationHandler.END

async def ah_cancel_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await reply_text(update, "Operación cancelada.")
    return ConversationHandler.END

# Fallback genérico
async def fallback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_authorized(update):
        await reply_text(update, "Usa /menu, /hosts, /run, /custom, /connect, /close, /help.")

# Limpieza periódica de sesiones inactivas
IDLE_MAX = 180  # segundos
async def idle_cleaner(app: Application):
    while True:
        try:
            for chat_id, sess in list(shell_sessions.items()):
                if (datetime.utcnow() - sess['last']).total_seconds() > IDLE_MAX:
                    try:
                        sess['chan'].close()
                        sess['client'].close()
                    except Exception:
                        pass
                    shell_sessions.pop(chat_id, None)
        except Exception:
            pass
        await asyncio.sleep(30)

async def post_init(app: Application):
    cmds = [
        BotCommand("start", "Ayuda y comandos"),
        BotCommand("menu", "Abrir menú"),
        BotCommand("hosts", "Listar hosts"),
        BotCommand("addhost", "Asistente para agregar host"),
        BotCommand("reload", "Recargar hosts.yaml"),
        BotCommand("run", "Ejecutar comando whitelisted"),
        BotCommand("custom", "Ejecutar comando libre (⚠️)"),
        BotCommand("connect", "Abrir sesión de shell (⚠️)"),
        BotCommand("sh", "Ejecutar en sesión abierta (⚠️)"),
        BotCommand("close", "Cerrar sesión"),
        BotCommand("trust", "Registrar host key en known_hosts")
    ]
    await app.bot.set_my_commands(cmds)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("Falta TELEGRAM_BOT_TOKEN")
    if not ALLOWED_USER_IDS:
        raise RuntimeError("Configura ALLOWED_USER_IDS con tus IDs (numéricos).")
    load_hosts()
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    # Comandos principales
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("menu", menu))
    app.add_handler(CallbackQueryHandler(on_menu_button, pattern=r"^menu_"))

    app.add_handler(CommandHandler("hosts", cmd_hosts))
    app.add_handler(CommandHandler("reload", cmd_reload))
    app.add_handler(CommandHandler("run", cmd_run))
    app.add_handler(CommandHandler("custom", cmd_custom))

    app.add_handler(CommandHandler("connect", cmd_connect))
    app.add_handler(CommandHandler("sh", cmd_sh))
    app.add_handler(CommandHandler("close", cmd_close))
    app.add_handler(CommandHandler("trust", cmd_trust))

    # Conversación para /addhost
    conv = ConversationHandler(
        entry_points=[CommandHandler("addhost", addhost_start)],
        states={
            AH_ALIAS: [MessageHandler(filters.TEXT & ~filters.COMMAND, ah_alias)],
            AH_HOST: [MessageHandler(filters.TEXT & ~filters.COMMAND, ah_host)],
            AH_PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, ah_port)],
            AH_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, ah_user)],
            AH_KEY_PATH: [MessageHandler(filters.TEXT & ~filters.COMMAND, ah_key_path)],
            AH_CONFIRM: [CallbackQueryHandler(ah_confirm_cb, pattern=r"^ah_(ok|cancel)$")],
        },
        fallbacks=[CommandHandler("cancel", ah_cancel_text)],
        name="addhost",
        persistent=False,
        allow_reentry=True,
    )
    app.add_handler(conv)

    # Fallback para texto suelto
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback))

    # Tarea de limpieza de sesiones inactivas
    app.job_queue.run_repeating(lambda *_: None, interval=3600, first=0)  # placeholder
    asyncio.create_task(idle_cleaner(app))

    app.run_polling(close_loop=False)

if __name__ == "__main__":
    main()
PY

chmod +x "${PY_SCRIPT}"

#############################
# SERVICIO SYSTEMD
#############################

tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<UNIT
[Unit]
Description=Telegram SSH Multi-Server Bot
After=network-online.target
Wants=network-online.target

[Service]
User=${BOT_USER}
Group=${BOT_USER}
WorkingDirectory=${BOT_HOME}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_PATH}/bin/python ${PY_SCRIPT}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateDevices=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
sleep 1
systemctl status "${SERVICE_NAME}" --no-pager || true

##########################################
# RESUMEN Y SIGUIENTES PASOS PARA TI
##########################################

echo
echo "================= INSTALACIÓN/ACTUALIZACIÓN COMPLETA ================="
echo "1) Agrega la clave pública del BOT en cada servidor destino (usuario remoto, ej. tgadmin):"
echo "   ---- CLAVE PÚBLICA ----"
echo "${PUBKEY_CONTENT}"
echo "   -----------------------"
echo "   Pasos en cada servidor destino:"
echo "     sudo adduser --disabled-password --gecos \"\" tgadmin"
echo "     sudo -u tgadmin mkdir -p /home/tgadmin/.ssh"
echo "     echo \"${PUBKEY_CONTENT}\" | sudo tee -a /home/tgadmin/.ssh/authorized_keys >/dev/null"
echo "     sudo chown -R tgadmin:tgadmin /home/tgadmin/.ssh"
echo "     sudo chmod 700 /home/tgadmin/.ssh"
echo "     sudo chmod 600 /home/tgadmin/.ssh/authorized_keys"
echo "     # Endurece SSH (opcional y recomendado):"
echo "     sudo sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config"
echo "     sudo sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config"
echo "     sudo systemctl reload ssh"
echo
if [[ "${STRICT_HOST_KEY}" == "true" ]]; then
  echo "2) (STRICT_HOST_KEY=true) Registra las host keys en el bot:"
  echo "   En Telegram: /trust <alias>  (usa ssh-keyscan y añade a known_hosts)"
fi
echo "2) Edita ${HOSTS_FILE} o usa /addhost o /menu para añadir alias/hosts."
echo "   Luego, desde Telegram, usa /reload para recargar si editaste el archivo."
echo
echo "3) (Opcional) Sudo muy acotado en destino (ejemplo):"
echo "     echo \"tgadmin ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx, /usr/bin/journalctl\" | sudo EDITOR='tee -a' visudo"
echo
echo "4) Ver logs del bot:   sudo journalctl -u ${SERVICE_NAME} -f"
echo "5) Reiniciar el bot:   sudo systemctl restart ${SERVICE_NAME}"
echo
if [[ "${ALLOW_SHELL}" == "true" || "${ALLOW_CUSTOM}" == "true" ]]; then
  echo "⚠️ Aviso: /custom y/o modo shell están ACTIVOS por defecto. Usa ALLOWED_USER_IDS correctamente."
fi
echo
echo "Hecho. Abre Telegram y envía /start o /menu a tu bot."
