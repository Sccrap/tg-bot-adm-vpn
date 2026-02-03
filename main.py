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

# Configuration
ALERT_THRESHOLD = int(os.getenv('FAIL2BAN_THRESHOLD', '5'))  # Срабатывания в минуту
CHECK_INTERVAL = 60  # Проверка fail2ban каждую минуту


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
        [InlineKeyboardButton("🚀 Перезагрузить Docker", callback_data='restart_docker')],
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
            [InlineKeyboardButton("🚀 Перезагрузить Docker", callback_data='restart_docker')],
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
            [InlineKeyboardButton("🔄 Статус сервера", callback_data='status')],
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
━━━━━━━━━━━━━━━━━━━━━━
• 🔄 **Статус сервера** - Показывает текущее состояние
• 🚀 **Перезагрузить Docker** - Выполняет docker-compose down → 5 сек → docker-compose up -d
• 🚨 **Fail2Ban** - Автоматические уведомления при большой активности

**Система безопасности:**
✓ Доступ только для авторизованных пользователей
✓ Все действия логируются
✓ Требуется подтверждение для критических операций

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


async def monitor_fail2ban(application: Application):
    """Фоновый мониторинг Fail2Ban"""
    while True:
        try:
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
                        logger.error(f"Error sending alert to {admin_id}: {e}")
        except Exception as e:
            logger.error(f"Error in fail2ban monitor: {e}")
        
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
