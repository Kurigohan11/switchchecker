#!/usr/bin/env bash
# SwitchPro — остановка

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$DIR/switchpro.pid"

echo "=== SwitchPro — остановка ==="

# Метод 1: по PID-файлу
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Останавливаем процесс PID=$PID..."
        kill "$PID"
        sleep 1
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID"
        fi
        rm -f "$PID_FILE"
        echo "✅ SwitchPro остановлен."
    else
        echo "Процесс PID=$PID уже не запущен."
        rm -f "$PID_FILE"
    fi
    exit 0
fi

# Метод 2: найти по порту 5000
PID=$(lsof -ti tcp:5000 2>/dev/null | head -1)
if [ -n "$PID" ]; then
    echo "Найден процесс на порту 5000: PID=$PID"
    kill "$PID"
    sleep 1
    if kill -0 "$PID" 2>/dev/null; then
        kill -9 "$PID"
    fi
    echo "✅ SwitchPro остановлен."
    exit 0
fi

# Метод 3: найти по имени процесса
PID=$(pgrep -f "python.*app.py" 2>/dev/null | head -1)
if [ -n "$PID" ]; then
    echo "Найден процесс app.py: PID=$PID"
    kill "$PID"
    sleep 1
    echo "✅ SwitchPro остановлен."
    exit 0
fi

echo "SwitchPro не запущен (процесс не найден)."
