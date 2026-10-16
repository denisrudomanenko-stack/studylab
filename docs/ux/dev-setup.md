# Запуск и проверка

## Локально
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp /dev/null .env   # необязательно; значения по умолчанию ниже
uvicorn studylab:app --host 127.0.0.1 --port 8201 --reload
```
Открыть `http://127.0.0.1:8201`. Пользователи по умолчанию: `admin` / `admin123`, `student` / `student123` (задаются `ADMIN_PASSWORD`, `STUDENT_PASSWORD`).

Переменные окружения или `.env` (читает `_cfg`): `DATA_DIR` (по умолчанию `./data`), `SECRET_KEY`, `TIMEWEB_API_KEY`, `ADMIN_PASSWORD`, `STUDENT_PASSWORD`, `SMTP_EMAIL`, `SMTP_PASSWORD`, `SMTP_HOST`, `SMTP_PORT`, `ENV_PATH`.

- Индексация и поиск требуют `ollama` с моделью `bge-m3` на `127.0.0.1:11434`. Без неё интерфейс проверяется, но источники не проиндексируются.
- Генерация ответов и OCR требуют `TIMEWEB_API_KEY`. Без ключа эндпоинт вернёт 503: для разработки интерфейса используйте заглушку (ответ-пример) за флагом `STUDYLAB_FAKE_LLM=1`, **добавить в рамках задачи 04**, если ключа нет.
- Не коммитьте `.env`, `data/`, ключи и базы.

## Проверки перед PR
```bash
python3 -m py_compile studylab.py
python3 - <<'PY'
import re
s = open('studylab.py', encoding='utf-8').read()
a = s.index('HTML_SPA = r"""'); b = s.index('"""', a + 20)
open('/tmp/spa.js', 'w').write(max(re.findall(r'<script>(.*?)</script>', s[a:b], re.S), key=len))
PY
node --check /tmp/spa.js
```
Затем открыть страницу в headless Chromium (Playwright) на ширинах 1280, 820, 390: нет ошибок консоли и горизонтальной прокрутки, обе темы. Для Safari: проверить вручную на Mac или iPhone, если доступно.

## Деплой (делает владелец, не Claude Code)
Сервис `studylab` (`deploy/studylab.service`, порт 8201), путь `/opt/studylab/`. Обновление: заменить `studylab.py`, `systemctl restart studylab`. Перед миграциями БД делать копию `data/studylab.db`.
