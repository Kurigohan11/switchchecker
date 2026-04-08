#!/usr/bin/env bash
# SwitchPro — запуск
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PYTHON=python3
VENV="$DIR/venv"
PID_FILE="$DIR/switchpro.pid"

echo "=== SwitchPro ==="

# Проверить не запущен ли уже
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "SwitchPro уже запущен (PID=$OLD_PID)."
        echo "Открываем браузер..."
        xdg-open "http://localhost:5000" 2>/dev/null || open "http://localhost:5000" 2>/dev/null || true
        exit 0
    fi
    rm -f "$PID_FILE"
fi

# Создать venv если нет
if [ ! -f "$VENV/bin/python" ]; then
    echo "Создание виртуального окружения..."
    $PYTHON -m venv venv
fi

source "$VENV/bin/activate"

echo "Проверка зависимостей..."
pip install -q -r requirements.txt

# Открыть браузер через 1.5 сек
(sleep 1.5 && xdg-open "http://localhost:5000" 2>/dev/null || \
              open "http://localhost:5000" 2>/dev/null || true) &

echo "Запуск на http://localhost:5000"
echo "Остановить: bash stop.sh  или  Ctrl+C"
echo ""

# Запускаем и сохраняем PID
python app.py &
APP_PID=$!
echo $APP_PID > "$PID_FILE"
echo "PID: $APP_PID"

# Ждём завершения
wait $APP_PID
rm -f "$PID_FILE"
