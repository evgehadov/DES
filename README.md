# DES Cipher — Реализация Data Encryption Standard

**Полноценная реализация алгоритма DES с веб-интерфейсом и визуализацией раундов**

Проект представляет собой полную реализацию алгоритма Data Encryption Standard (DES) с поддержкой режимов ECB и CBC, включая визуализацию раундов сети Фейстеля и удобный веб-интерфейс.

---

## Возможности

- Полная реализация алгоритма **DES** с нуля (сеть Фейстеля, 16 раундов)
- Поддержка двух режимов шифрования: **ECB** и **CBC**
- Корректная работа с **PKCS7 Padding**
- Генерация 16 подключей (Key Schedule)
- Визуализация раундов шифрования (L, R и подключ для первого блока)
- Удобный и красивый веб-интерфейс на Flask
- Валидация ввода, обработка ошибок и подсказки пользователю
- Полный набор юнит-тестов (включая NIST known-answer vectors)
- Чистая модульная структура проекта

---

## Структура проекта

| Файл / Папка                | Назначение |
|-----------------------------|----------|
| `des_impl/`                 | Основной пакет с реализацией DES |
| `des_impl/des_core.py`      | Ядро алгоритма (Feistel Network, S-boxes) |
| `des_impl/modes.py`         | Режимы ECB и CBC + PKCS7 Padding |
| `des_impl/keyschedule.py`   | Генерация подключей |
| `des_impl/feistel.py`       | Функция Фейстеля |
| `des_impl/tables.py`        | Таблицы DES (IP, PC1, PC2, S-boxes и др.) |
| `web/app.py`                | Flask-сервер и API |
| `web/templates/index.html`  | Веб-интерфейс |
| `tests/test_des.py`         |  Полный набор юнит-тестов |


## Как запустить проект
### 1. Перейдите по ссылке на GitHub и скачайте все файлы. 
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








