#!/usr/bin/env bash
# install_tg_ssh_bot.sh
# Instala un bot de Telegram para administrar varios servidores vía SSH (Ubuntu 24.04)
# Crea usuario de sistema, entorno Python, claves SSH, archivos, servicio systemd y arranca.

set -euo pipefail

########################
# CONFIGURACIÓN RÁPIDA #
########################

# 👉 EDITA ESTAS VARIABLES ANTES DE EJECUTAR
TELEGRAM_BOT_TOKEN="8209886235:AAFEygF89KrKYGx06gqY0MKYGpyQXwU8kHY"          # BotFather token
ALLOWED_USER_IDS="1594636958"                     # IDs de Telegram permitidos (coma-separados)
BOT_USER="tg-bot"                                # usuario linux del bot
BOT_HOME="/opt/tg-bot"
HOSTS_FILE="${BOT_HOME}/hosts.yaml"
ENV_FILE="${BOT_HOME}/.env"
PY_SCRIPT="${BOT_HOME}/bot_ssh_multi.py"
SERVICE_NAME="tg-ssh-multi"
VENV_PATH="${BOT_HOME}/venv"
SSH_DIR="${BOT_HOME}/.ssh"
BOT_SSH_KEY="${SSH_DIR}/id_ed25519"

# Opciones por defecto (puedes cambiarlas luego en .env)
ALLOW_SHELL="false"      # true para habilitar /connect, /sh, /close (⚠️)
ALLOW_CUSTOM="false"     # true para /custom <alias> <cmd> (⚠️)
RATE_LIMIT="10"
RATE_WINDOW_SEC="60"
MAX_REPLY_CHARS="3500"

###################################
# VERIFICACIONES Y PREPARATIVOS   #
###################################

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

if [[ -z "${TELEGRAM_BOT_TOKEN}" || "${TELEGRAM_BOT_TOKEN}" == "PON_AQUI_TU_TOKEN" ]]; then
  echo "❌ Debes configurar TELEGRAM_BOT_TOKEN al inicio del script." >&2
  exit 1
fi

if [[ -z "${ALLOWED_USER_IDS}" || "${ALLOWED_USER_IDS}" == "123456789" ]]; then
  echo "⚠️ AVISO: ALLOWED_USER_IDS no parece configurado con tu(s) ID(s) reales." >&2
  echo "   Puedes continuar, pero el bot no funcionará para ti si no coincide." >&2
fi

echo "==> Preparando instalación del bot en ${BOT_HOME} (usuario: ${BOT_USER})"

#############################
# PAQUETES Y USUARIO SISTEMA
#############################

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  python3-venv python3-pip python3-dev gcc \
  openssh-client ca-certificates

# Crear usuario de sistema para el bot
if ! id -u "${BOT_USER}" >/dev/null 2>&1; then
  adduser --system --group --home "${BOT_HOME}" "${BOT_USER}"
fi

mkdir -p "${BOT_HOME}"
chown -R "${BOT_USER}:${BOT_USER}" "${BOT_HOME}"
chmod 0755 "${BOT_HOME}"

##################################
# ENTORNO PYTHON Y DEPENDENCIAS  #
##################################

sudo -u "${BOT_USER}" python3 -m venv "${VENV_PATH}"
sudo -u "${BOT_USER}" "${VENV_PATH}/bin/pip" install --upgrade pip
# Librerías necesarias
sudo -u "${BOT_USER}" "${VENV_PATH}/bin/pip" install \
  python-telegram-bot==20.* paramiko pyyaml

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
# ARCHIVO hosts.yaml (plantilla)
#############################

sudo -u "${BOT_USER}" tee "${HOSTS_FILE}" >/dev/null <<'YAML'
# hosts.yaml: Define alias, destino SSH y whitelist de comandos por servidor.
# Rellena con tus servidores. Ejemplos:

prod1:
  host: 10.0.0.10
  port: 22
  user: tgadmin
  key_path: /opt/tg-bot/.ssh/id_ed25519
  whitelist:
    status: "uptime && who && uname -a"
    disco: "df -h"
    memoria: "free -h"
    nginx_reload: "sudo systemctl reload nginx"

db:
  host: 10.0.0.20
  port: 22
  user: tgadmin
  key_path: /opt/tg-bot/.ssh/id_ed25519
  whitelist:
    status: "uptime && uname -a"
    pg_stat: "sudo -u postgres psql -c \"select now(), count(*) from pg_stat_activity;\""

# web2:
#   host: web2.mi-dominio.local
#   port: 22
#   user: tgadmin
#   key_path: /opt/tg-bot/.ssh/id_ed25519
#   whitelist: {}
YAML

chmod 0644 "${HOSTS_FILE}"

#############################
# ARCHIVO .env
#############################

sudo -u "${BOT_USER}" tee "${ENV_FILE}" >/dev/null <<ENV
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
ALLOWED_USER_IDS=${ALLOWED_USER_IDS}
HOSTS_FILE=${HOSTS_FILE}
ALLOW_SHELL=${ALLOW_SHELL}
ALLOW_CUSTOM=${ALLOW_CUSTOM}
RATE_LIMIT=${RATE_LIMIT}
RATE_WINDOW_SEC=${RATE_WINDOW_SEC}
MAX_REPLY_CHARS=${MAX_REPLY_CHARS}
ENV

chmod 0600 "${ENV_FILE}"

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
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, Tuple

import paramiko
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# ================== ENTORNO ==================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ALLOWED_USER_IDS = {int(x) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x.strip().isdigit()}
HOSTS_FILE = os.getenv("HOSTS_FILE", "/opt/tg-bot/hosts.yaml")
ALLOW_SHELL = os.getenv("ALLOW_SHELL", "false").lower() == "true"
ALLOW_CUSTOM = os.getenv("ALLOW_CUSTOM", "false").lower() == "true"
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))
RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
MAX_REPLY_CHARS = int(os.getenv("MAX_REPLY_CHARS", "3500"))
RATE_WINDOW = timedelta(seconds=RATE_WINDOW_SEC)

BLOCKED_SUBSTR = [
    " shutdown", "reboot", "halt", "poweroff", "init 0", ":(){:|:&};:",
    " mkfs", " dd if=", " rm -rf /", "userdel ", " groupdel ", " visudo"
]

hosts: Dict[str, Dict[str, Any]] = {}
rate_buckets = defaultdict(lambda: deque())
shell_sessions: Dict[int, Dict[str, Any]] = {}  # chat_id -> session dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tg-ssh-multi")

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
            "key_path": cfg.get("key_path"),
            "whitelist": cfg.get("whitelist", {}) or {}
        }
    hosts = norm
    logger.info("Cargados %d hosts desde %s", len(hosts), HOSTS_FILE)

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

async def reply_text(update: Update, text: str):
    await update.effective_message.reply_text(text, disable_web_page_preview=True)

def contains_blocked(cmd: str) -> bool:
    c = f" {cmd.strip()} ".lower()
    return any(b in c for b in BLOCKED_SUBSTR)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        return
    text = (
        "🤖 <b>Bot SSH multi-servidor</b>\n\n"
        "• /hosts — listar servidores\n"
        "• /run &lt;alias&gt; &lt;nombre&gt; — ejecutar un comando permitido\n"
        f"• /custom &lt;alias&gt; &lt;cmd&gt; — {'(deshabilitado)' if not ALLOW_CUSTOM else '(habilitado ⚠️)'}\n"
        "• /reload — recargar hosts.yaml\n\n"
        f"<b>Modo consola</b> {'(deshabilitado)' if not ALLOW_SHELL else '(habilitado ⚠️)'}\n"
        "• /connect &lt;alias&gt; — abrir sesión\n"
        "• /sh &lt;cmd&gt; — ejecutar comando\n"
        "• /close — cerrar sesión\n"
        "⚠️ Recomendado: usar whitelist y evitar secretos por Telegram."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)

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
        await reply_text(update, f"✅ Sesión abierta en <b>{alias}</b>. Usa /sh <cmd>.",)
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

async def fallback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_authorized(update):
        await reply_text(update, "Usa /hosts, /run, /connect, /close, /help.")

def main():
    if not BOT_TOKEN:
        raise RuntimeError("Falta TELEGRAM_BOT_TOKEN")
    if not ALLOWED_USER_IDS:
        raise RuntimeError("Configura ALLOWED_USER_IDS con tus IDs (numéricos).")
    load_hosts()
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("hosts", cmd_hosts))
    app.add_handler(CommandHandler("reload", cmd_reload))
    app.add_handler(CommandHandler("run", cmd_run))
    app.add_handler(CommandHandler("custom", cmd_custom))

    app.add_handler(CommandHandler("connect", cmd_connect))
    app.add_handler(CommandHandler("sh", cmd_sh))
    app.add_handler(CommandHandler("close", cmd_close))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback))
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
echo "================= INSTALACIÓN COMPLETA ================="
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
echo "2) Edita ${HOSTS_FILE} para añadir tus alias/hosts y comandos whitelist."
echo "   Luego, desde Telegram, usa /reload para recargar."
echo
echo "3) (Opcional) Sudo muy acotado en destino (ejemplo):"
echo "     echo \"tgadmin ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx, /usr/bin/journalctl\" | sudo EDITOR='tee -a' visudo"
echo
echo "4) Ver logs del bot:   sudo journalctl -u ${SERVICE_NAME} -f"
echo "5) Reiniciar el bot:   sudo systemctl restart ${SERVICE_NAME}"
echo
echo "⚠️ Modo consola está DESHABILITADO por defecto. Para activarlo:"
echo "   - Edita ${ENV_FILE} y cambia ALLOW_SHELL=true"
echo "   - sudo systemctl restart ${SERVICE_NAME}"
echo
echo "Hecho. Abre Telegram y envía /start a tu bot."
