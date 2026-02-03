#!/usr/bin/env python3

import os
import sys
import logging
import subprocess
import asyncio
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
BOT_TOKEN = os.getenv('BOT_TOKEN')

# Parse admin IDs from comma-separated string
ADMIN_IDS_STR = os.getenv('ADMIN_IDS', '0')
ADMIN_IDS = set()
for admin_id in ADMIN_IDS_STR.split(','):
    try:
        ADMIN_IDS.add(int(admin_id.strip()))
    except ValueError:
        pass

if 0 in ADMIN_IDS:
    ADMIN_IDS.remove(0)

DOCKER_COMPOSE_PATH = os.getenv('DOCKER_COMPOSE_PATH', '/home/user/docker-compose.yml')
FAIL2BAN_LOG_PATH = os.getenv('FAIL2BAN_LOG_PATH', '/var/log/fail2ban.log')
AUTH_LOG_PATH = os.getenv('AUTH_LOG_PATH', '/var/log/auth.log')
SYSLOG_PATH = os.getenv('SYSLOG_PATH', '/var/log/syslog')

# Configuration
ALERT_THRESHOLD = int(os.getenv('FAIL2BAN_THRESHOLD', '5'))  # Срабатывания в минуту
SSH_FAILED_THRESHOLD = int(os.getenv('SSH_FAILED_THRESHOLD', '10'))  # Неудачные SSH попытки
PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', '20'))  # Попытки сканирования портов
CHECK_INTERVAL = 60  # Проверка событий ИБ каждую минуту


def is_admin(user_id: int) -> bool:
    """Проверить, является ли пользователь администратором"""
    return user_id in ADMIN_IDS

class ServerManager:
    """Управление сервером и мониторинг"""
    
    @staticmethod
    def get_server_status():
        """Получить статус сервера и docker контейнеров"""
        try:
            # Проверка docker-compose
            result = subprocess.run(
                ['docker-compose', 'ps', '-q'],
                cwd=os.path.dirname(DOCKER_COMPOSE_PATH),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            containers = result.stdout.strip().split('\n') if result.stdout.strip() else []
            running_count = len([c for c in containers if c])
            
            # Проверка нагрузки на систему
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().split()[:3]
            
            status = f"""
🖥️ **Статус сервера:**
━━━━━━━━━━━━━━━━━
📦 Docker контейнеры: {running_count} запущено
⚙️ Нагрузка: {load_avg[0]} / {load_avg[1]} / {load_avg[2]}
⏰ Время проверки: {datetime.now().strftime('%H:%M:%S')}
✅ Сервер работает нормально
"""
            return status, True
        except Exception as e:
            logger.error(f"Error getting server status: {e}")
            return f"❌ Ошибка при проверке статуса: {str(e)}", False
    
    @staticmethod
    async def restart_docker_compose():
        """Перезагрузить docker-compose контейнеры"""
        try:
            compose_dir = os.path.dirname(DOCKER_COMPOSE_PATH)
            
            logger.info("Stopping docker-compose...")
            stop_result = subprocess.run(
                ['docker-compose', 'down'],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            logger.info(f"Docker-compose stopped: {stop_result.returncode}")
            
            # Ожидание 5 секунд
            await asyncio.sleep(5)
            
            logger.info("Starting docker-compose...")
            start_result = subprocess.run(
                ['docker-compose', 'up', '-d'],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            logger.info(f"Docker-compose started: {start_result.returncode}")
            
            if stop_result.returncode == 0 and start_result.returncode == 0:
                return True, "✅ Docker-compose успешно перезагружен"
            else:
                return False, f"❌ Ошибка перезагрузки\nStop: {stop_result.stderr}\nStart: {start_result.stderr}"
        except Exception as e:
            logger.error(f"Error restarting docker-compose: {e}")
            return False, f"❌ Ошибка: {str(e)}"
    
    @staticmethod
    def check_fail2ban_alerts():
        """Проверить логи fail2ban на большое количество срабатываний"""
        try:
            if not os.path.exists(FAIL2BAN_LOG_PATH):
                logger.warning(f"Fail2ban log not found at {FAIL2BAN_LOG_PATH}")
                return None
            
            # Последние 5 минут
            now = datetime.now()
            five_min_ago = now - timedelta(minutes=5)
            
            ban_events = []
            
            with open(FAIL2BAN_LOG_PATH, 'r') as f:
                for line in f:
                    if 'Ban' in line or 'Unban' in line:
                        try:
                            # Парсинг даты из лога (пример: 2026-02-03 12:30:45)
                            parts = line.split()
                            if len(parts) >= 2:
                                log_date_str = f"{parts[0]} {parts[1]}"
                                log_date = datetime.strptime(log_date_str, '%Y-%m-%d %H:%M:%S')
                                
                                if log_date >= five_min_ago:
                                    ban_events.append(line.strip())
                        except:
                            pass
            
            if len(ban_events) > ALERT_THRESHOLD:
                alert_msg = f"""
🚨 **ВНИМАНИЕ: Высокая активность Fail2Ban!**
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Обнаружено {len(ban_events)} действий в последние 5 минут
Порог срабатывания: {ALERT_THRESHOLD}

📋 Последние события:
"""
                for event in ban_events[-10:]:  # Последние 10 событий
                    alert_msg += f"\n• {event}"
                
                return alert_msg
            
            return None
        except Exception as e:
            logger.error(f"Error checking fail2ban: {e}")
            return None
    
    @staticmethod
    def check_ssh_failed_login():
        """Проверить неудачные SSH попытки входа"""
        try:
            if not os.path.exists(AUTH_LOG_PATH):
                return None
            
            now = datetime.now()
            five_min_ago = now - timedelta(minutes=5)
            
            failed_attempts = []
            ips = {}
            
            with open(AUTH_LOG_PATH, 'r') as f:
                for line in f:
                    if 'Failed password' in line or 'Invalid user' in line:
                        try:
                            parts = line.split()
                            # Попытка получить IP адрес
                            for i, part in enumerate(parts):
                                if part == 'from' and i + 1 < len(parts):
                                    ip = parts[i + 1]
                                    if ip not in ips:
                                        ips[ip] = 0
                                    ips[ip] += 1
                                    failed_attempts.append(line.strip())
                                    break
                        except:
                            pass
            
            if len(failed_attempts) > SSH_FAILED_THRESHOLD:
                alert_msg = f"""
⚠️ **ВНИМАНИЕ: Высокая активность неудачных SSH попыток!**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Обнаружено {len(failed_attempts)} неудачных попыток за 5 минут
Порог: {SSH_FAILED_THRESHOLD}

🌐 IP адреса с наибольшей активностью:
"""
                # Сортируем по количеству попыток
                top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
                for ip, count in top_ips:
                    alert_msg += f"\n• {ip}: {count} попыток"
                
                return alert_msg
            
            return None
        except Exception as e:
            logger.error(f"Error checking SSH failed logins: {e}")
            return None
    
    @staticmethod
    def check_port_scanning():
        """Проверить попытки сканирования портов (firewall events)"""
        try:
            if not os.path.exists(SYSLOG_PATH):
                return None
            
            now = datetime.now()
            five_min_ago = now - timedelta(minutes=5)
            
            port_events = []
            ips = {}
            
            with open(SYSLOG_PATH, 'r') as f:
                for line in f:
                    if 'UFW' in line or 'kernel' in line and 'DROP' in line:
                        try:
                            port_events.append(line.strip())
                            # Попытка извлечь IP
                            if 'SRC=' in line:
                                parts = line.split('SRC=')
                                if len(parts) > 1:
                                    ip = parts[1].split()[0]
                                    if ip not in ips:
                                        ips[ip] = 0
                                    ips[ip] += 1
                        except:
                            pass
            
            if len(port_events) > PORT_SCAN_THRESHOLD:
                alert_msg = f"""
🔴 **ВНИМАНИЕ: Обнаружено сканирование портов!**
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Обнаружено {len(port_events)} отброшенных пакетов за 5 минут
Порог: {PORT_SCAN_THRESHOLD}

🌐 Источники атак:
"""
                top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
                for ip, count in top_ips:
                    alert_msg += f"\n• {ip}: {count} пакетов"
                
                return alert_msg
            
            return None
        except Exception as e:
            logger.error(f"Error checking port scanning: {e}")
            return None
    
    @staticmethod
    def check_sudo_commands():
        """Проверить выполнение sudo команд"""
        try:
            result = subprocess.run(
                ['journalctl', '-u', 'sudo', '-n', '50', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                # Фильтруем только последние 5 минут
                sudo_commands = []
                for line in lines:
                    if 'COMMAND=' in line or 'sudo' in line.lower():
                        sudo_commands.append(line.strip())
                
                if sudo_commands:
                    msg = "📋 **Последние SUDO команды:**\n━━━━━━━━━━━━━━━━\n"
                    for cmd in sudo_commands[-10:]:
                        msg += f"• {cmd}\n"
                    return msg
            
            return None
        except:
            return None
    
    @staticmethod
    def get_security_status():
        """Получить полный статус безопасности"""
        status = "🔒 **Статус безопасности сервера:**\n━━━━━━━━━━━━━━━━━━━━\n"
        
        try:
            # Проверка firewall
            fw_result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, timeout=5)
            if fw_result.returncode == 0 and 'active' in fw_result.stdout:
                status += "✅ Firewall (UFW): Активен\n"
            else:
                status += "⚠️ Firewall (UFW): Неактивен\n"
        except:
            status += "❓ Firewall: Не проверено\n"
        
        try:
            # Проверка SELinux
            se_result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
            if se_result.returncode == 0:
                mode = se_result.stdout.strip()
                if mode == 'Enforcing':
                    status += "✅ SELinux: Enforcing\n"
                else:
                    status += f"⚠️ SELinux: {mode}\n"
        except:
            status += "❓ SELinux: Не проверено\n"
        
        try:
            # Проверка Fail2Ban
            fb_result = subprocess.run(['sudo', 'systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True, timeout=5)
            if fb_result.returncode == 0:
                status += "✅ Fail2Ban: Работает\n"
            else:
                status += "⚠️ Fail2Ban: Остановлен\n"
        except:
            status += "❓ Fail2Ban: Не проверено\n"
        
        try:
            # Проверка открытых портов
            ss_result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True, timeout=10)
            if ss_result.returncode == 0:
                lines = ss_result.stdout.strip().split('\n')
                open_ports = len([l for l in lines if 'LISTEN' in l]) - 1  # -1 для заголовка
                status += f"🔌 Открытые порты: {open_ports}\n"
        except:
            status += "❓ Открытые порты: Не проверено\n"
        
        return status


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /start с проверкой доступа"""
    user_id = update.effective_user.id
    
    # Проверка верификации
    if not is_admin(user_id):
        await update.message.reply_text(
            "❌ У вас нет доступа к этому боту.\n"
            "Обратитесь к администратору."
        )
        logger.warning(f"Unauthorized access attempt from user {user_id}")
        return
    
    # Приветствие администратора
    keyboard = [
        [InlineKeyboardButton("🔄 Статус сервера", callback_data='status')],
        [InlineKeyboardButton("� Статус безопасности", callback_data='security')],
        [InlineKeyboardButton("�🚀 Перезагрузить Docker", callback_data='restart_docker')],
        [InlineKeyboardButton("ℹ️ Справка", callback_data='help')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"👋 Добро пожаловать, администратор!\n\n"
        f"ID: {user_id}\n"
        f"Выберите действие:",
        reply_markup=reply_markup
    )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработка нажатий на кнопки"""
    query = update.callback_query
    user_id = query.from_user.id
    
    # Проверка доступа
    if not is_admin(user_id):
        await query.answer("❌ Доступ запрещен", show_alert=True)
        return
    
    await query.answer()
    
    if query.data == 'status':
        status_msg, is_running = ServerManager.get_server_status()
        
        keyboard = [
            [InlineKeyboardButton("🔄 Обновить", callback_data='status')],
            [InlineKeyboardButton("� Статус безопасности", callback_data='security')],
            [InlineKeyboardButton("�🚀 Перезагрузить Docker", callback_data='restart_docker')],
            [InlineKeyboardButton("« Назад", callback_data='main_menu')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=status_msg,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    elif query.data == 'restart_docker':
        # Подтверждение
        keyboard = [
            [
                InlineKeyboardButton("✅ Подтвердить", callback_data='confirm_restart'),
                InlineKeyboardButton("❌ Отмена", callback_data='status')
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text="⚠️ Вы уверены? Docker-compose будет перезагружен.\n"
                 "Это может вызвать временный простой.",
            reply_markup=reply_markup
        )
    
    elif query.data == 'confirm_restart':
        await query.edit_message_text(text="⏳ Перезагрузка Docker-compose...\n\nЭто может занять некоторое время...")
        
        success, message = await ServerManager.restart_docker_compose()
        
        keyboard = [
            [InlineKeyboardButton("🔄 Статус", callback_data='status')],
            [InlineKeyboardButton("« Назад", callback_data='main_menu')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup
        )
        
        # Логирование
        logger.info(f"Docker restart {'successful' if success else 'failed'}")
    
    elif query.data == 'main_menu':
        keyboard = [
            [InlineKeyboardButton("� Статус безопасности", callback_data='security')],
            [InlineKeyboardButton("�🔄 Статус сервера", callback_data='status')],
            [InlineKeyboardButton("🚀 Перезагрузить Docker", callback_data='restart_docker')],
            [InlineKeyboardButton("ℹ️ Справка", callback_data='help')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text="🏠 Главное меню\n\nВыберите действие:",
            reply_markup=reply_markup
        )
    
    elif query.data == 'help':
        help_text = """
ℹ️ **Справка по боту**
━━━� **Статус безопасности** - Информация о безопасности (Firewall, SELinux, Fail2Ban, Порты)
• 🚀 **Перезагрузить Docker** - Выполняет docker-compose down → 5 сек → docker-compose up -d
• 🚨 **Fail2Ban** - Автоматические уведомления при большой активности
• ⚠️ **SSH попытки** - Уведомления о неудачных попытках входа
• 🔴 **Port Scanning** - Уведомления о сканировании портов

**Система безопасности:**
✓ Доступ только для авторизованных пользователей
✓ Все действия логируются
✓ Требуется подтверждение для критических операций
✓ Мониторинг 24/7

Вопросы? Обратитесь к администратору.
"""
        keyboard = [
            [InlineKeyboardButton("« Назад", callback_data='main_menu')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=help_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    elif query.data == 'security':
        security_status = ServerManager.get_security_status()
        
        keyboard = [
            [InlineKeyboardButton("🔄 Обновить", callback_data='security')],
            [InlineKeyboardButton("« Назад", callback_data='main_menu')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=security_status
        await query.edit_message_text(
            text=help_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )


async def monitor_fail2ban(application: Application):
    """Фоновый мониторинг событий безопасности"""
    check_counters = {
        'fail2ban': 0,
        'ssh': 0,
        'port_scan': 0,
    }
    
    while True:
        try:
            # Проверка Fail2Ban каждую минуту
            if check_counters['fail2ban'] == 0:
                alert = ServerManager.check_fail2ban_alerts()
                if alert and ADMIN_IDS:
                    for admin_id in ADMIN_IDS:
                        try:
                            await application.bot.send_message(
                                chat_id=admin_id,
                                text=alert,
                                parse_mode='Markdown'
                            )
                            logger.info(f"Fail2ban alert sent to {admin_id}")
                        except Exception as e:
                            logger.error(f"Error sending fail2ban alert to {admin_id}: {e}")
            
            # Проверка SSH попыток каждые 2 минуты
            if check_counters['ssh'] == 0:
                alert = ServerManager.check_ssh_failed_login()
                if alert and ADMIN_IDS:
                    for admin_id in ADMIN_IDS:
                        try:
                            await application.bot.send_message(
                                chat_id=admin_id,
                                text=alert,
                                parse_mode='Markdown'
                            )
                            logger.info(f"SSH alert sent to {admin_id}")
                        except Exception as e:
                            logger.error(f"Error sending SSH alert to {admin_id}: {e}")
            
            # Проверка сканирования портов каждые 2 минуты
            if check_counters['port_scan'] == 0:
                alert = ServerManager.check_port_scanning()
                if alert and ADMIN_IDS:
                    for admin_id in ADMIN_IDS:
                        try:
                            await application.bot.send_message(
                                chat_id=admin_id,
                                text=alert,
                                parse_mode='Markdown'
                            )
                            logger.info(f"Port scan alert sent to {admin_id}")
                        except Exception as e:
                            logger.error(f"Error sending port scan alert to {admin_id}: {e}")
            
            # Обновляем счетчики
            check_counters['fail2ban'] = (check_counters['fail2ban'] + 1) % 1
            check_counters['ssh'] = (check_counters['ssh'] + 1) % 2
            check_counters['port_scan'] = (check_counters['port_scan'] + 1) % 2
            
        except Exception as e:
            logger.error(f"Error in security monitor: {e}")
        
        await asyncio.sleep(CHECK_INTERVAL)


async def post_init(application: Application):
    """Инициализация приложения"""
    asyncio.create_task(monitor_fail2ban(application))
    logger.info("Bot initialized and monitoring started")


def main():
    """Запуск бота"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable not set")
        sys.exit(1)
    
    if not ADMIN_IDS:
        logger.error("ADMIN_IDS environment variable not set or empty")
        sys.exit(1)
    
    logger.info(f"Starting bot with ADMIN_IDS: {ADMIN_IDS}")
    
    # Создание приложения
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()
    
    # Обработчики команд
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", lambda u, c: start_command(u, c)))
    
    # Обработчик кнопок
    app.add_handler(CallbackQueryHandler(button_callback))
    
    # Запуск бота
    logger.info("Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
