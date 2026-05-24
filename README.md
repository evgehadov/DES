# DES Cipher — Реализация Data Encryption Standard

**Полноценная реализация алгоритма DES с веб-интерфейсом и визуализацией раундов**

---

## Что реализовано в проекте

- Полная реализация алгоритма **DES** с нуля (сеть Фейстеля, 16 раундов)
- Поддержка двух режимов шифрования: **ECB** и **CBC**
- Корректная работа с **PKCS7 Padding**
- Генерация 16 подключей (Key Schedule)
- Визуализация раундов шифрования (L, R и подключ для первого блока)
- Удобный и красивый веб-интерфейс на Flask
- Валидация ввода, обработка ошибок и подсказки
- Полный набор юнит-тестов (включая NIST known-answer vectors)
- Чистая модульная структура проекта

---

## Как запустить проект
### 1. Перейдите по ссылке на GitHub (https://github.com/evgehadov/DES/edit/main/README.md) и скачайте все файлы. 
### 2. Создайте директорию с названием "des_progect" и переместите все файлы туда.
### 3. Откройте в PyCharm (или любом другом приложении) дирректорию. 
### 4. Автоматически настройте структуру:

Откройте терминал в папке проекта и выполните:

```bash
# Создаём нужные папки
mkdir -p des_impl web/templates tests

# Раскидываем файлы по папкам
mv des_core.py feistel.py keyschedule.py modes.py tables.py __init__.py des_impl/ 2>/dev/null || true
mv test_des.py tests/ 2>/dev/null || true
mv app.py web/ 2>/dev/null || true
mv index.html web/templates/ 2>/dev/null || true

echo "✅ Структура проекта настроена"
ls -la

2. Запуск приложения
Bash# Создаём виртуальное окружение
python -m venv venv
source venv/bin/activate          # Mac / Linux
# venv\Scripts\activate           # Windows

# Устанавливаем Flask
pip install flask

# Запускаем сервер
cd web
python app.py
После запуска откройте в браузере:
http://127.0.0.1:5000

Альтернативный быстрый запуск (если структура уже правильная)
Bashcd web && python app.py

🧪 Запуск тестов
Bashpython -m pytest tests/test_des.py -v

📁 Структура проекта после настройки
textdes_project/
├── des_impl/              # Ядро алгоритма DES
│   ├── __init__.py
│   ├── des_core.py
│   ├── feistel.py
│   ├── keyschedule.py
│   ├── modes.py
│   └── tables.py
├── tests/
│   └── test_des.py
├── web/
│   ├── app.py
│   └── templates/
│       └── index.html
├── README.md
├── requirements.txt
└── .gitignore








