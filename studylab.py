#!/usr/bin/env python3
"""StudyLab — персональная образовательная среда для студентки биофака МГУ."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import bcrypt
import jwt
from fastapi import (Cookie, Depends, FastAPI, File, Form, HTTPException,
                     Query, Request, Response, UploadFile)
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
import uvicorn


# ═══════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════

def _load_dotenv(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return result


BASE_DIR = Path(__file__).parent
_DOTENV = _load_dotenv(os.environ.get("ENV_PATH", str(BASE_DIR / ".env")))
if not _DOTENV:
    _DOTENV = _load_dotenv("/opt/studylab/.env")


def _cfg(key: str, default: str = "") -> str:
    return os.environ.get(key) or _DOTENV.get(key) or default


DATA_DIR         = Path(_cfg("DATA_DIR", str(BASE_DIR / "data")))
DB_PATH          = DATA_DIR / "studylab.db"
SUBJECTS_DIR     = DATA_DIR / "subjects"
SECRET_KEY       = _cfg("SECRET_KEY", "dev-secret-please-change")
TIMEWEB_API_KEY  = _cfg("TIMEWEB_API_KEY", "")
ADMIN_PASSWORD   = _cfg("ADMIN_PASSWORD", "admin123")
STUDENT_PASSWORD = _cfg("STUDENT_PASSWORD", "student123")
SMTP_EMAIL       = _cfg("SMTP_EMAIL", "")
SMTP_PASSWORD    = _cfg("SMTP_PASSWORD", "")
SMTP_HOST        = _cfg("SMTP_HOST", "smtp.yandex.ru")
SMTP_PORT        = int(_cfg("SMTP_PORT", "465"))
ADMIN_EMAIL      = "y53@yandex.ru"

DATA_DIR.mkdir(parents=True, exist_ok=True)
SUBJECTS_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════════════════

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT           NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'student',
            created_at    TEXT           NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subjects (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            slug        TEXT UNIQUE NOT NULL,
            title       TEXT        NOT NULL,
            description TEXT        DEFAULT '',
            year        INTEGER     DEFAULT 0,
            created_at  TEXT        NOT NULL,
            created_by  INTEGER
        );
        CREATE TABLE IF NOT EXISTS sources (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_slug  TEXT NOT NULL,
            slug          TEXT NOT NULL,
            filename      TEXT NOT NULL,
            original_name TEXT NOT NULL,
            title         TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'uploaded',
            chunk_count   INTEGER      DEFAULT 0,
            created_at    TEXT         NOT NULL,
            UNIQUE(subject_slug, slug)
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_slug TEXT NOT NULL,
            user_id      INTEGER NOT NULL,
            title        TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chat_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL DEFAULT 0,
            subject_slug    TEXT NOT NULL,
            user_id         INTEGER NOT NULL,
            role            TEXT    NOT NULL,
            content         TEXT    NOT NULL,
            created_at      TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT    UNIQUE NOT NULL,
            status     TEXT    NOT NULL DEFAULT 'pending',
            created_at TEXT    NOT NULL,
            resolved_at TEXT   DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS exam_tickets (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_slug TEXT NOT NULL,
            question     TEXT NOT NULL,
            answer       TEXT DEFAULT '',
            status       TEXT NOT NULL DEFAULT 'pending',
            created_at   TEXT NOT NULL,
            generated_at TEXT DEFAULT ''
        );
    """)
    # Safe migrations: add columns that may not exist in older DBs
    for migration in [
        "ALTER TABLE chat_history ADD COLUMN conversation_id INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE subjects ADD COLUMN year INTEGER DEFAULT 0",
    ]:
        try:
            db.execute(migration)
        except sqlite3.OperationalError:
            pass  # column already exists

    now = datetime.now(timezone.utc).isoformat()
    for uname, pwd, role in [("admin", ADMIN_PASSWORD, "admin"),
                              ("student", STUDENT_PASSWORD, "student")]:
        if not db.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone():
            pw_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            db.execute(
                "INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                (uname, pw_hash, role, now)
            )
    db.commit()
    db.close()


# ═══════════════════════════════════════════════════════════════════════
# Auth helpers
# ═══════════════════════════════════════════════════════════════════════

JWT_ALG  = "HS256"
JWT_DAYS = 30


def make_token(user_id: int, username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=JWT_DAYS)
    return jwt.encode(
        {"sub": str(user_id), "username": username, "role": role, "exp": exp},
        SECRET_KEY, algorithm=JWT_ALG
    )


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
    except Exception:
        return None


def current_user(sl_token: Optional[str] = Cookie(default=None)) -> dict:
    if not sl_token:
        raise HTTPException(401, "Требуется авторизация")
    payload = decode_token(sl_token)
    if not payload:
        raise HTTPException(401, "Недействительный токен")
    return payload


def admin_user(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "Только для администратора")
    return user


# ═══════════════════════════════════════════════════════════════════════
# FastAPI app
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(title="StudyLab", docs_url=None, redoc_url=None)


@app.on_event("startup")
async def on_startup():
    init_db()


# ─── Auth endpoints ────────────────────────────────────────────────────

@app.post("/api/login")
async def api_login(response: Response,
                    username: str = Form(),
                    password: str = Form()):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(401, "Неверный логин или пароль")
    token = make_token(row["id"], row["username"], row["role"])
    response.set_cookie("sl_token", token, httponly=True, samesite="lax",
                        max_age=JWT_DAYS * 86400, path="/")
    return {"ok": True, "username": row["username"], "role": row["role"]}


@app.post("/api/logout")
async def api_logout(response: Response):
    response.delete_cookie("sl_token", path="/")
    return {"ok": True}


@app.get("/api/me")
async def api_me(user: dict = Depends(current_user)):
    return {"username": user["username"], "role": user["role"]}


# ─── Password validation & SMTP ──────────────────────────────────────

def _validate_password(pw: str) -> str | None:
    if len(pw) < 8:
        return "Пароль должен содержать минимум 8 символов"
    if not any(c.isupper() for c in pw):
        return "Пароль должен содержать хотя бы одну заглавную букву"
    if not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in pw):
        return "Пароль должен содержать хотя бы один спецсимвол"
    return None


def _send_email(subject: str, body_html: str):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("[smtp] SMTP not configured, skipping email", flush=True)
        return
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body_html, "html", "utf-8"))
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as srv:
            srv.login(SMTP_EMAIL, SMTP_PASSWORD)
            srv.sendmail(SMTP_EMAIL, ADMIN_EMAIL, msg.as_string())
        print(f"[smtp] Email sent: {subject}", flush=True)
    except Exception as e:
        print(f"[smtp error] {e}", flush=True)


# ─── Password reset flow ─────────────────────────────────────────────

@app.post("/api/request-password-reset")
async def request_password_reset(user: dict = Depends(current_user)):
    uid = int(user["sub"])
    db = get_db()
    pending = db.execute(
        "SELECT id FROM password_reset_requests WHERE user_id=? AND status='pending'", (uid,)
    ).fetchone()
    if pending:
        db.close()
        raise HTTPException(409, "Уже есть активный запрос на смену пароля")
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO password_reset_requests (user_id,token,status,created_at) VALUES (?,?,'pending',?)",
        (uid, token, now)
    )
    db.commit()
    db.close()
    _send_email(
        f"StudyLab: запрос на смену пароля от {user['username']}",
        f"<p>Пользователь <b>{user['username']}</b> запросил смену пароля.</p>"
        f"<p><a href='https://study.24pensi.ru/#/approve-reset/{token}'>Подтвердить смену пароля</a></p>"
        f"<p>Если вы не одобряете — просто проигнорируйте это письмо.</p>"
    )
    return {"ok": True, "message": "Запрос отправлен администратору"}


@app.get("/api/password-reset-status")
async def password_reset_status(user: dict = Depends(current_user)):
    db = get_db()
    row = db.execute(
        "SELECT status FROM password_reset_requests WHERE user_id=? ORDER BY id DESC LIMIT 1",
        (int(user["sub"]),)
    ).fetchone()
    db.close()
    if not row:
        return {"has_pending": False, "status": None}
    return {"has_pending": row["status"] == "pending", "status": row["status"]}


@app.get("/api/approve-reset/{token}")
async def approve_reset(token: str):
    db = get_db()
    row = db.execute(
        "SELECT * FROM password_reset_requests WHERE token=? AND status='pending'", (token,)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Запрос не найден или уже обработан")
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE password_reset_requests SET status='approved', resolved_at=? WHERE id=?",
        (now, row["id"])
    )
    db.commit()
    db.close()
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;padding:40px;text-align:center'>"
        "<h2>Смена пароля одобрена</h2>"
        "<p>Пользователь теперь может установить новый пароль.</p>"
        "</body></html>"
    )


@app.post("/api/set-new-password")
async def set_new_password(new_password: str = Form(), user: dict = Depends(current_user)):
    err = _validate_password(new_password)
    if err:
        raise HTTPException(400, err)
    uid = int(user["sub"])
    db = get_db()
    row = db.execute(
        "SELECT id FROM password_reset_requests WHERE user_id=? AND status='approved' ORDER BY id DESC LIMIT 1",
        (uid,)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(403, "Нет одобренного запроса на смену пароля")
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (pw_hash, uid))
    db.execute(
        "UPDATE password_reset_requests SET status='completed', resolved_at=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), row["id"])
    )
    db.commit()
    db.close()
    return {"ok": True, "message": "Пароль успешно изменён"}


# ─── Conversations ────────────────────────────────────────────────────

@app.get("/api/subjects/{slug}/conversations")
async def list_conversations(slug: str, q: str = "", user: dict = Depends(current_user)):
    uid = int(user["sub"])
    db = get_db()
    if q:
        rows = db.execute(
            "SELECT DISTINCT c.* FROM conversations c "
            "JOIN chat_history h ON h.conversation_id=c.id "
            "WHERE c.subject_slug=? AND c.user_id=? AND h.content LIKE ? "
            "ORDER BY c.updated_at DESC",
            (slug, uid, f"%{q}%")
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM conversations WHERE subject_slug=? AND user_id=? ORDER BY updated_at DESC",
            (slug, uid)
        ).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.post("/api/subjects/{slug}/conversations")
async def create_conversation(slug: str, title: str = Form(default=""),
                               user: dict = Depends(current_user)):
    uid = int(user["sub"])
    now = datetime.now(timezone.utc).isoformat()
    db = get_db()
    cur = db.execute(
        "INSERT INTO conversations (subject_slug,user_id,title,created_at,updated_at) VALUES (?,?,?,?,?)",
        (slug, uid, title or "Новая беседа", now, now)
    )
    cid = cur.lastrowid
    db.commit()
    db.close()
    return {"ok": True, "id": cid}


@app.put("/api/subjects/{slug}/conversations/{cid}")
async def rename_conversation(slug: str, cid: int, title: str = Form(),
                                user: dict = Depends(current_user)):
    db = get_db()
    db.execute("UPDATE conversations SET title=? WHERE id=? AND user_id=?",
               (title, cid, int(user["sub"])))
    db.commit()
    db.close()
    return {"ok": True}


@app.delete("/api/subjects/{slug}/conversations/{cid}")
async def delete_conversation(slug: str, cid: int, user: dict = Depends(current_user)):
    uid = int(user["sub"])
    db = get_db()
    db.execute("DELETE FROM chat_history WHERE conversation_id=? AND user_id=?", (cid, uid))
    db.execute("DELETE FROM conversations WHERE id=? AND user_id=?", (cid, uid))
    db.commit()
    db.close()
    return {"ok": True}


@app.delete("/api/subjects/{slug}/conversations")
async def delete_all_conversations(slug: str, user: dict = Depends(current_user)):
    uid = int(user["sub"])
    db = get_db()
    conv_ids = [r["id"] for r in db.execute(
        "SELECT id FROM conversations WHERE subject_slug=? AND user_id=?", (slug, uid)
    ).fetchall()]
    if conv_ids:
        placeholders = ",".join("?" * len(conv_ids))
        db.execute(f"DELETE FROM chat_history WHERE conversation_id IN ({placeholders}) AND user_id=?",
                   conv_ids + [uid])
        db.execute(f"DELETE FROM conversations WHERE id IN ({placeholders}) AND user_id=?",
                   conv_ids + [uid])
    db.commit()
    db.close()
    return {"ok": True}


# ─── Stage 3: Subjects + Upload + Indexing ────────────────────────────

import asyncio
import shutil
import sys as _sys

_sys.path.insert(0, str(BASE_DIR))
try:
    from mklib import (
        convert_source as mk_convert,
        segment_text,
        embed_texts,
        embed_query,
        open_db as mk_open_db,
        init_db as mk_init_db,
        db_upsert,
        db_search,
        chunk_segment,
        read_text as mk_read_text,
        DIM,
    )
    MKLIB_OK = True
except Exception as _e:
    MKLIB_OK = False
    print(f"[warn] mklib unavailable: {_e}", flush=True)


def _slug(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^a-z0-9а-яёa-z]+", "-", text.lower().strip(), flags=re.UNICODE)
    return s.strip("-")[:maxlen]


def subject_dir(slug: str) -> Path:
    d = SUBJECTS_DIR / slug
    for sub in ("uploads", "md", ""):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d


async def _index_source(subject_slug: str, source_slug: str,
                         upload_path: Path, source_title: str):
    """Background: convert → segment → embed → store in sqlite-vec."""
    db = get_db()
    try:
        db.execute("UPDATE sources SET status='indexing:convert' WHERE subject_slug=? AND slug=?",
                   (subject_slug, source_slug))
        db.commit()

        subj_dir = subject_dir(subject_slug)
        md_dir = subj_dir / "md"

        def _update_status(st):
            sdb = get_db()
            sdb.execute("UPDATE sources SET status=? WHERE subject_slug=? AND slug=?",
                        (st, subject_slug, source_slug))
            sdb.commit()
            sdb.close()

        def _run():
            if not MKLIB_OK:
                raise RuntimeError("mklib недоступен")
            mk_convert(upload_path, source_slug, md_dir, with_images=True)
            _update_status('indexing:segment')
            text = mk_read_text(md_dir, source_slug)
            if not text:
                raise RuntimeError("Текст не извлечён")
            segs = segment_text(text)
            if not segs:
                segs = [{"index": 0, "title": source_title,
                         "start_char": 0, "end_char": len(text),
                         "words": len(text.split())}]
            seg_path = subj_dir / "segments.json"
            all_segs: dict = {}
            if seg_path.exists():
                try:
                    all_segs = json.loads(seg_path.read_text(encoding="utf-8"))
                except Exception:
                    all_segs = {}
            all_segs[source_slug] = {"title": source_title, "segments": segs,
                                      "words": len(text.split())}
            seg_path.write_text(json.dumps(all_segs, ensure_ascii=False, indent=1),
                                encoding="utf-8")
            db_path = subj_dir / "index.db"
            vec_db = mk_open_db(db_path)
            mk_init_db(vec_db, "chunks")
            vec_db.execute("DELETE FROM chunks WHERE slug=?", (source_slug,))
            vec_db.commit()
            records, payloads = [], []
            header = f"Предмет: {subject_slug}. Источник: «{source_title}»."
            for seg in segs:
                for ci, (a, b) in enumerate(chunk_segment(text, seg)):
                    body = text[a:b].strip()
                    if len(body.split()) < 10:
                        continue
                    full = f"{header} Раздел: «{seg['title']}».\n\n{body}"
                    cid = "c_" + hashlib.sha1(
                        f"{subject_slug}|{source_slug}|{a}|{b}".encode()
                    ).hexdigest()[:16]
                    records.append({
                        "chunk_id": cid, "slug": source_slug,
                        "topic": subject_slug, "priority": 1,
                        "segment": seg["index"], "title": seg["title"],
                        "text": full, "meta": {"start_char": a, "end_char": b},
                    })
                    payloads.append(full)
            _update_status(f'indexing:embed 0/{len(records)}')
            for i in range(0, len(records), 8):
                _update_status(f'indexing:embed {i}/{len(records)}')
                vecs = embed_texts(payloads[i:i+8])
                for r, v in zip(records[i:i+8], vecs):
                    r["embedding"] = v
                db_upsert(vec_db, "chunks", records[i:i+8])
            vec_db.close()
            return len(records)

        n = await asyncio.to_thread(_run)
        db.execute(
            "UPDATE sources SET status='indexed', chunk_count=? WHERE subject_slug=? AND slug=?",
            (n, subject_slug, source_slug)
        )
    except Exception as e:
        db.execute(
            "UPDATE sources SET status='error' WHERE subject_slug=? AND slug=?",
            (subject_slug, source_slug)
        )
        print(f"[index error] {subject_slug}/{source_slug}: {e}", flush=True)
    finally:
        db.commit()
        db.close()


@app.post("/api/subjects")
async def create_subject(title: str = Form(), description: str = Form(default=""),
                          year: int = Form(default=0),
                          user: dict = Depends(admin_user)):
    slug = _slug(title)
    if not slug:
        raise HTTPException(400, "Некорректное название")
    subject_dir(slug)
    db = get_db()
    try:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO subjects (slug,title,description,year,created_at,created_by) VALUES (?,?,?,?,?,?)",
            (slug, title, description, year, now, int(user["sub"]))
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"Предмет '{slug}' уже существует")
    finally:
        db.close()
    return {"ok": True, "slug": slug}


@app.get("/api/subjects")
async def list_subjects(user: dict = Depends(current_user)):
    db = get_db()
    subjects = [dict(r) for r in db.execute(
        "SELECT slug,title,description,year,created_at FROM subjects ORDER BY created_at DESC"
    ).fetchall()]
    for s in subjects:
        rows = db.execute(
            "SELECT status, chunk_count FROM sources WHERE subject_slug=?", (s["slug"],)
        ).fetchall()
        s["source_count"] = len(rows)
        s["active_count"] = sum(1 for r in rows if r["status"] == "active")
        s["total_chunks"] = sum(r["chunk_count"] for r in rows if r["status"] == "active")
    db.close()
    return subjects


@app.get("/api/subjects/{slug}")
async def get_subject(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    row = db.execute("SELECT * FROM subjects WHERE slug=?", (slug,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Предмет не найден")
    return dict(row)


@app.post("/api/subjects/{slug}/upload")
async def upload_source(slug: str, file: UploadFile = File(),
                         title: str = Form(default=""),
                         user: dict = Depends(current_user),
                         background_tasks=None,
                         request: Request = None):
    db = get_db()
    if not db.execute("SELECT id FROM subjects WHERE slug=?", (slug,)).fetchone():
        db.close()
        raise HTTPException(404, "Предмет не найден")
    db.close()

    allowed = {".pdf", ".docx", ".doc", ".txt", ".md"}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(400, f"Формат {ext} не поддерживается. Разрешены: {', '.join(allowed)}")

    src_title = title or Path(file.filename).stem
    src_slug = _slug(src_title)
    if not src_slug:
        src_slug = _slug(file.filename)

    subj_dir = subject_dir(slug)
    upload_path = subj_dir / "uploads" / file.filename

    content = await file.read()
    upload_path.write_bytes(content)

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()
    try:
        db.execute(
            "INSERT OR REPLACE INTO sources "
            "(subject_slug,slug,filename,original_name,title,status,chunk_count,created_at) "
            "VALUES (?,?,?,?,?,'uploaded',0,?)",
            (slug, src_slug, upload_path.name, file.filename, src_title, now)
        )
        db.commit()
    finally:
        db.close()

    return {"ok": True, "slug": src_slug, "title": src_title, "status": "uploaded"}


@app.get("/api/subjects/{slug}/sources")
async def list_sources(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? ORDER BY created_at DESC", (slug,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.post("/api/subjects/{slug}/sources/{src_slug}/index")
async def index_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    """Запустить индексацию (конвертация + сегментация + эмбеддинги)."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Источник не найден")
    if row["status"] == "indexing":
        raise HTTPException(409, "Индексация уже идёт")
    upload_path = subject_dir(slug) / "uploads" / row["filename"]
    if not upload_path.exists():
        raise HTTPException(404, "Файл не найден на сервере")
    asyncio.create_task(_index_source(slug, src_slug, upload_path, row["title"]))
    return {"ok": True, "message": "Индексация запущена"}


@app.put("/api/subjects/{slug}/sources/{src_slug}/rename")
async def rename_source(slug: str, src_slug: str, title: str = Form(),
                         user: dict = Depends(admin_user)):
    db = get_db()
    db.execute("UPDATE sources SET title=? WHERE subject_slug=? AND slug=?",
               (title.strip(), slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.post("/api/subjects/{slug}/sources/{src_slug}/activate")
async def activate_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    """Включить источник в библиотеку (поиск и RAG)."""
    db = get_db()
    row = db.execute(
        "SELECT status FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Источник не найден")
    if row["status"] not in ("indexed", "inactive"):
        db.close()
        raise HTTPException(400, f"Нельзя активировать источник со статусом '{row['status']}'")
    db.execute("UPDATE sources SET status='active' WHERE subject_slug=? AND slug=?",
               (slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.post("/api/subjects/{slug}/sources/{src_slug}/deactivate")
async def deactivate_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    """Отключить источник от библиотеки (индекс сохраняется)."""
    db = get_db()
    row = db.execute(
        "SELECT status FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Источник не найден")
    if row["status"] != "active":
        db.close()
        raise HTTPException(400, "Источник не активен")
    db.execute("UPDATE sources SET status='inactive' WHERE subject_slug=? AND slug=?",
               (slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.delete("/api/subjects/{slug}/sources/{src_slug}")
async def delete_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    """Полное удаление: файл, markdown, чанки из индекса."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Источник не найден")

    subj = subject_dir(slug)
    # Удалить файл
    upload_path = subj / "uploads" / row["filename"]
    upload_path.unlink(missing_ok=True)
    # Удалить markdown
    md_dir = subj / "md" / src_slug
    if md_dir.exists():
        shutil.rmtree(md_dir, ignore_errors=True)
    # Удалить из segments.json
    seg_path = subj / "segments.json"
    if seg_path.exists():
        try:
            all_segs = json.loads(seg_path.read_text(encoding="utf-8"))
            all_segs.pop(src_slug, None)
            seg_path.write_text(json.dumps(all_segs, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass
    # Удалить чанки из векторного индекса
    vec_db_path = subj / "index.db"
    if vec_db_path.exists() and MKLIB_OK:
        try:
            vec_db = mk_open_db(vec_db_path)
            vec_db.execute("DELETE FROM chunks WHERE slug=?", (src_slug,))
            vec_db.commit()
            vec_db.close()
        except Exception:
            pass
    # Удалить из БД
    db.execute("DELETE FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


# ─── Stage 4: Search + Reader ─────────────────────────────────────────

def _active_slugs(subject_slug: str) -> set[str]:
    """Return set of source slugs with status='active'."""
    db = get_db()
    rows = db.execute(
        "SELECT slug FROM sources WHERE subject_slug=? AND status='active'", (subject_slug,)
    ).fetchall()
    db.close()
    return {r["slug"] for r in rows}


@app.get("/api/subjects/{slug}/search")
async def search_subject(slug: str, q: str, k: int = 8,
                          user: dict = Depends(current_user)):
    if not MKLIB_OK:
        raise HTTPException(503, "Поисковый движок недоступен")
    db_path = subject_dir(slug) / "index.db"
    if not db_path.exists():
        return []
    active = _active_slugs(slug)
    if not active:
        return []

    def _search():
        vec = embed_query(q)
        vdb = mk_open_db(db_path)
        hits = db_search(vdb, "chunks", vec, k=k * 3)
        vdb.close()
        return hits

    hits = await asyncio.to_thread(_search)
    filtered = [h for h in hits if h["slug"] in active][:k]
    return [
        {
            "score": h["score"],
            "slug": h["slug"],
            "segment": h["segment"],
            "title": h["title"],
            "text": h["text"][:400],
        }
        for h in filtered
    ]


@app.get("/api/subjects/{slug}/segments")
async def list_segments(slug: str, user: dict = Depends(current_user)):
    seg_path = subject_dir(slug) / "segments.json"
    if not seg_path.exists():
        return {}
    try:
        return json.loads(seg_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@app.get("/api/subjects/{slug}/segments/{src_slug}/{seg_id}")
async def get_segment(slug: str, src_slug: str, seg_id: int,
                       user: dict = Depends(current_user)):
    seg_path = subject_dir(slug) / "segments.json"
    if not seg_path.exists():
        raise HTTPException(404, "Сегменты не найдены")
    all_segs = json.loads(seg_path.read_text(encoding="utf-8"))
    if src_slug not in all_segs:
        raise HTTPException(404, f"Источник {src_slug} не найден")
    segs = all_segs[src_slug]["segments"]
    if seg_id < 0 or seg_id >= len(segs):
        raise HTTPException(404, "Сегмент не найден")
    seg = segs[seg_id]

    def _read():
        md_dir = subject_dir(slug) / "md"
        if not MKLIB_OK:
            return ""
        return mk_read_text(md_dir, src_slug)

    text = await asyncio.to_thread(_read)
    body = text[seg["start_char"]:seg["end_char"]] if text else ""
    return {
        "index": seg["index"],
        "title": seg["title"],
        "words": seg["words"],
        "text": body,
        "source": src_slug,
        "source_title": all_segs[src_slug].get("title", src_slug),
    }


# ─── Stage 5: Chat + RAG + SSE ────────────────────────────────────────

import httpx as _httpx
import base64 as _b64

TIMEWEB_URL = _cfg("LLM_BASE_URL", "https://api.timeweb.ai/v1") + "/chat/completions"
CHAT_MODEL  = "deepseek/deepseek-v4-pro"
VISION_MODEL = "gemini/gemini-3.5-flash"

SYSTEM_BIO = (
    "Ты — интеллектуальный ассистент по биологии и микробиологии для студентки 2 курса биофака МГУ. "
    "Приоритет — предоставленные фрагменты источников. К фактам из источников добавляй провенанс в ТОЧНОМ формате: [src:SLUG#SEG | раздел: заголовок]. SLUG и SEG бери из заголовка фрагмента [N src:SLUG#SEG]. "
    "Если в источниках нет ответа, используй свои знания по биологии, химии, биохимии — но явно укажи: «Из общих знаний:». "
    "Используй правильные латинские названия организмов. "
    "Формулы пиши в LaTeX: инлайн $...$ и блочные $$...$$. "
    "Отвечай развёрнуто, структурированно, на уровне университетского курса."
)


async def _rag_context(subject_slug: str, question: str, k: int = 8) -> list[dict]:
    """Retrieve top-k relevant chunks from active sources across ALL subjects."""
    if not MKLIB_OK:
        return []

    def _fetch():
        vec = embed_query(question)
        all_hits = []
        # Search across all subjects' indexes
        db = get_db()
        subjects = [r["slug"] for r in db.execute("SELECT slug FROM subjects").fetchall()]
        db.close()
        for subj_slug in subjects:
            idx_path = subject_dir(subj_slug) / "index.db"
            if not idx_path.exists():
                continue
            active = _active_slugs(subj_slug)
            if not active:
                continue
            try:
                vdb = mk_open_db(idx_path)
                hits = db_search(vdb, "chunks", vec, k=k * 2)
                vdb.close()
                for h in hits:
                    if h["slug"] in active:
                        h["_subject"] = subj_slug
                        all_hits.append(h)
            except Exception:
                pass
        # Sort by score, prioritize current subject
        all_hits.sort(key=lambda h: (-0.05 if h.get("_subject") == subject_slug else 0) - h["score"])
        return all_hits[:k]

    try:
        return await asyncio.to_thread(_fetch)
    except Exception as e:
        print(f"[rag error] {e}", flush=True)
        return []


def _build_messages(history: list[dict], question: str,
                    context_chunks: list[dict], image_b64: str | None = None) -> list[dict]:
    ctx = ""
    if context_chunks:
        parts = []
        for i, h in enumerate(context_chunks, 1):
            src_slug = h.get("slug", "")
            seg_idx = h.get("segment", 0)
            title = h.get("title", "")
            parts.append(f"[{i} src:{src_slug}#{seg_idx}] «{title}»\n{h['text'][:600]}")
        ctx = "Фрагменты из источников:\n\n" + "\n\n---\n\n".join(parts) + "\n\n"

    messages: list[dict] = [{"role": "system", "content": SYSTEM_BIO}]
    for msg in history[-10:]:
        messages.append({"role": msg["role"], "content": msg["content"]})

    if image_b64:
        user_content = [
            {"type": "text",
             "text": ctx + "Распознай текст, формулы и схемы с этого фото конспекта, "
                          "затем ответь на вопрос: " + question},
            {"type": "image_url",
             "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}}
        ]
    else:
        user_content = ctx + question

    messages.append({"role": "user", "content": user_content})
    return messages


@app.get("/api/subjects/{slug}/chat/history")
async def chat_history(slug: str, conversation_id: int = 0, limit: int = 50,
                        user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT role,content,created_at FROM chat_history "
        "WHERE subject_slug=? AND user_id=? AND conversation_id=? ORDER BY id DESC LIMIT ?",
        (slug, int(user["sub"]), conversation_id, limit)
    ).fetchall()
    db.close()
    return list(reversed([dict(r) for r in rows]))


@app.delete("/api/subjects/{slug}/chat/history")
async def clear_chat_history(slug: str, conversation_id: int = 0,
                              user: dict = Depends(current_user)):
    db = get_db()
    db.execute("DELETE FROM chat_history WHERE subject_slug=? AND user_id=? AND conversation_id=?",
               (slug, int(user["sub"]), conversation_id))
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/api/subjects/{slug}/chat/stream")
async def chat_stream(slug: str, q: str, conversation_id: int = 0,
                       user: dict = Depends(current_user),
                       image: Optional[str] = None):
    if not TIMEWEB_API_KEY:
        raise HTTPException(503, "TIMEWEB_API_KEY не задан")

    uid = int(user["sub"])
    now = datetime.now(timezone.utc).isoformat()

    # Auto-create conversation if needed
    if conversation_id == 0:
        db = get_db()
        auto_title = q[:60] + ("…" if len(q) > 60 else "")
        cur = db.execute(
            "INSERT INTO conversations (subject_slug,user_id,title,created_at,updated_at) VALUES (?,?,?,?,?)",
            (slug, uid, auto_title, now, now)
        )
        conversation_id = cur.lastrowid
        db.commit()
        db.close()

    db = get_db()
    history = [dict(r) for r in db.execute(
        "SELECT role,content FROM chat_history "
        "WHERE subject_slug=? AND user_id=? AND conversation_id=? ORDER BY id DESC LIMIT 20",
        (slug, uid, conversation_id)
    ).fetchall()]
    db.close()
    history = list(reversed(history))

    context_chunks = await _rag_context(slug, q)

    async def generate():
        full_answer = []
        try:
            messages = _build_messages(history, q, context_chunks, image)
            async with _httpx.AsyncClient(timeout=120) as client:
                async with client.stream(
                    "POST", TIMEWEB_URL,
                    headers={"Authorization": f"Bearer {TIMEWEB_API_KEY}"},
                    json={"model": CHAT_MODEL, "messages": messages,
                          "stream": True, "max_tokens": 4096, "temperature": 0.3}
                ) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        yield f"data: {{\"error\": \"API error {resp.status_code}\"}}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        raw = line[6:].strip()
                        if raw == "[DONE]":
                            break
                        try:
                            chunk = json.loads(raw)
                            delta = chunk["choices"][0]["delta"].get("content", "")
                            if delta:
                                full_answer.append(delta)
                                yield f"data: {json.dumps({'content': delta})}\n\n"
                        except Exception:
                            pass
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            answer_text = "".join(full_answer)
            if answer_text:
                save_db = get_db()
                save_db.execute(
                    "INSERT INTO chat_history (conversation_id,subject_slug,user_id,role,content,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (conversation_id, slug, uid, "user", q, now)
                )
                save_db.execute(
                    "INSERT INTO chat_history (conversation_id,subject_slug,user_id,role,content,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (conversation_id, slug, uid, "assistant", answer_text,
                     datetime.now(timezone.utc).isoformat())
                )
                save_db.execute(
                    "UPDATE conversations SET updated_at=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), conversation_id)
                )
                save_db.commit()
                save_db.close()
            yield f"data: {json.dumps({'done': True, 'conversation_id': conversation_id})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/subjects/{slug}/chat/upload-image")
async def upload_chat_image(slug: str, file: UploadFile = File(),
                             user: dict = Depends(current_user)):
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "Файл слишком большой (макс. 10 МБ)")
    encoded = _b64.b64encode(content).decode()
    return {"image_b64": encoded}


# ─── Stage 6: Exam Tickets ────────────────────────────────────────────

@app.get("/api/subjects/{slug}/tickets")
async def list_tickets(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM exam_tickets WHERE subject_slug=? ORDER BY id", (slug,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.post("/api/subjects/{slug}/tickets")
async def create_ticket(slug: str, question: str = Form(),
                         user: dict = Depends(current_user)):
    if not question.strip():
        raise HTTPException(400, "Вопрос не может быть пустым")
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO exam_tickets (subject_slug,question,status,created_at) VALUES (?,?,'pending',?)",
        (slug, question.strip(), now)
    )
    ticket_id = cur.lastrowid
    db.commit()
    db.close()
    return {"ok": True, "id": ticket_id}


@app.post("/api/subjects/{slug}/tickets/batch")
async def batch_create_tickets(slug: str, questions: str = Form(),
                                user: dict = Depends(current_user)):
    """Пакетная загрузка вопросов — один вопрос на строку."""
    db = get_db()
    if not db.execute("SELECT id FROM subjects WHERE slug=?", (slug,)).fetchone():
        db.close()
        raise HTTPException(404, "Предмет не найден")
    now = datetime.now(timezone.utc).isoformat()
    lines = [q.strip() for q in questions.strip().split("\n") if q.strip()]
    if not lines:
        db.close()
        raise HTTPException(400, "Список вопросов пуст")
    # Remove numbering like "1. ", "1) ", "- "
    import re as _re2
    cleaned = []
    for line in lines:
        line = _re2.sub(r"^\d+[.)]\s*", "", line)
        line = _re2.sub(r"^[-*]\s*", "", line)
        if line:
            cleaned.append(line)
    ids = []
    for q in cleaned:
        cur = db.execute(
            "INSERT INTO exam_tickets (subject_slug,question,status,created_at) VALUES (?,?,'pending',?)",
            (slug, q, now)
        )
        ids.append(cur.lastrowid)
    db.commit()
    db.close()
    return {"ok": True, "count": len(ids), "ids": ids}


@app.put("/api/subjects/{slug}/tickets/{tid}")
async def update_ticket(slug: str, tid: int, question: str = Form(),
                         user: dict = Depends(current_user)):
    db = get_db()
    db.execute(
        "UPDATE exam_tickets SET question=?, status='pending', answer='' WHERE id=? AND subject_slug=?",
        (question.strip(), tid, slug)
    )
    db.commit()
    db.close()
    return {"ok": True}


@app.delete("/api/subjects/{slug}/tickets/{tid}")
async def delete_ticket(slug: str, tid: int, user: dict = Depends(current_user)):
    db = get_db()
    db.execute("DELETE FROM exam_tickets WHERE id=? AND subject_slug=?", (tid, slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/api/subjects/{slug}/tickets/{tid}/generate")
async def generate_ticket_answer(slug: str, tid: int,
                                   user: dict = Depends(current_user)):
    if not TIMEWEB_API_KEY:
        raise HTTPException(503, "TIMEWEB_API_KEY не задан")
    db = get_db()
    row = db.execute(
        "SELECT * FROM exam_tickets WHERE id=? AND subject_slug=?", (tid, slug)
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Билет не найден")

    question = row["question"]
    context_chunks = await _rag_context(slug, question, k=10)

    system_prompt = (
        "Ты — преподаватель университетского курса, готовишь студенту развёрнутый ответ на экзаменационный билет.\n\n"
        "ФОРМАТ ОТВЕТА (строго следуй):\n"
        "1. Начни с **определения** ключевого понятия (термин выделяй **жирным**)\n"
        "2. Дай **классификацию** — нумерованные списки с подпунктами\n"
        "3. Все формулы пиши в LaTeX: инлайн $...$ и блочные $$...$$\n"
        "4. В нумерованных списках используй явные номера: 1. 2. 3. 4. (не повторяй 1.)\n"
        "5. Если уместно — добавь таблицу в markdown (|столбец|столбец|)\n"
        "6. Логика: определение → классификация → формулы/уравнения → вывод → следствия\n"
        "7. Выделяй **ключевые термины** жирным при первом упоминании\n"
        "7. Используй правильные латинские названия организмов\n"
        "8. Добавляй провенанс в ТОЧНОМ формате [src:SLUG#SEG | раздел: заголовок] к фактам из источников. SLUG и SEG бери из заголовка фрагмента.\n"
        "9. Если в источниках нет — используй общие знания, помечай «Из общих знаний:»\n"
        "10. Объём: 400-800 слов, на уровне университетского курса\n"
    )

    ctx = ""
    if context_chunks:
        parts = []
        for i, h in enumerate(context_chunks):
            src_slug = h.get("slug", "")
            seg_idx = h.get("segment", 0)
            title = h.get("title", "")
            parts.append(f"[{i+1} src:{src_slug}#{seg_idx}] «{title}»\n{h['text'][:800]}")
        ctx = "Источники:\n\n" + "\n\n---\n\n".join(parts) + "\n\n"

    async def generate():
        full_answer = []
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": ctx + "Вопрос экзаменационного билета: " + question}
            ]
            async with _httpx.AsyncClient(timeout=180) as client:
                async with client.stream(
                    "POST", TIMEWEB_URL,
                    headers={"Authorization": f"Bearer {TIMEWEB_API_KEY}"},
                    json={"model": CHAT_MODEL, "messages": messages,
                          "stream": True, "max_tokens": 4096, "temperature": 0.3}
                ) as resp:
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        raw = line[6:].strip()
                        if raw == "[DONE]":
                            break
                        try:
                            chunk = json.loads(raw)
                            delta = chunk["choices"][0]["delta"].get("content", "")
                            if delta:
                                full_answer.append(delta)
                                yield f"data: {json.dumps({'content': delta})}\n\n"
                        except Exception:
                            pass
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            answer_text = "".join(full_answer)
            if answer_text:
                save_db = get_db()
                save_db.execute(
                    "UPDATE exam_tickets SET answer=?, status='generated', generated_at=? WHERE id=?",
                    (answer_text, datetime.now(timezone.utc).isoformat(), tid)
                )
                save_db.commit()
                save_db.close()
            yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def _md_to_html(text: str) -> str:
    """Convert markdown to HTML with support for tables, lists, bold, italic, code, formulas."""
    if not text:
        return ""
    import html as _html
    # Normalize block formulas and protect from escaping
    text = re.sub(r"\$\$\s*\n([\s\S]*?)\n\s*\$\$", lambda m: "$$" + m.group(1).strip() + "$$", text)
    _formulas: list[str] = []
    def _save_formula(m):
        _formulas.append(m.group(0))
        return f"\x00F{len(_formulas)-1}\x00"
    text = re.sub(r"\$\$[^$]+\$\$", _save_formula, text)
    text = re.sub(r"\$[^$\n]+\$", _save_formula, text)
    lines = text.split("\n")
    out = []
    in_table = False
    in_list = False
    list_type = ""
    for line in lines:
        stripped = line.strip()
        # Table
        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("- :") for c in cells):
                continue  # separator row
            if not in_table:
                in_table = True
                out.append("<table>")
                tag = "th"
            else:
                tag = "td"
            out.append("<tr>" + "".join(f"<{tag}>{_html.escape(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            in_table = False
            out.append("</table>")
        # Headings
        if stripped.startswith("### "):
            if in_list:
                out.append(f"</{list_type}>"); in_list = False
            out.append(f"<h3>{_html.escape(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            if in_list:
                out.append(f"</{list_type}>"); in_list = False
            out.append(f"<h2>{_html.escape(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            if in_list:
                out.append(f"</{list_type}>"); in_list = False
            out.append(f"<h2>{_html.escape(stripped[2:])}</h2>")
            continue
        # Numbered list
        if re.match(r"^\d+\.\s", stripped):
            if not in_list or list_type != "ol":
                if in_list:
                    out.append(f"</{list_type}>")
                out.append("<ol>"); in_list = True; list_type = "ol"
            content = re.sub(r"^\d+\.\s+", "", stripped)
            out.append(f"<li>{_html.escape(content)}</li>")
            continue
        # Bullet list
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list or list_type != "ul":
                if in_list:
                    out.append(f"</{list_type}>")
                out.append("<ul>"); in_list = True; list_type = "ul"
            out.append(f"<li>{_html.escape(stripped[2:])}</li>")
            continue
        # Close list if not continuing
        if in_list and stripped:
            out.append(f"</{list_type}>"); in_list = False
        # Empty line
        if not stripped:
            continue
        # Paragraph
        out.append(f"<p>{_html.escape(stripped)}</p>")
    if in_list:
        out.append(f"</{list_type}>")
    if in_table:
        out.append("</table>")
    result = "\n".join(out)
    # Inline formatting (on the HTML)
    result = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", result)
    result = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", result)
    result = re.sub(r"`([^`]+)`", r"<code>\1</code>", result)
    result = re.sub(r"\[src:[a-z0-9а-яё\-]+#\d+\s*\|\s*([^\]]+)\]",
                    r'<span style="color:#60a5fa;font-size:.85em">[📖 \1]</span>', result, flags=re.IGNORECASE)
    result = re.sub(r"\[([^\]]+)\]", r'<span style="color:#60a5fa;font-size:.85em">[\1]</span>', result)
    # Restore formulas — block formulas get centered div
    def _restore(m):
        f = _formulas[int(m.group(1))]
        if f.startswith("$$"):
            return f'<div style="text-align:center;margin:.8em 0">{f}</div>'
        return f
    result = re.sub(r"\x00F(\d+)\x00", _restore, result)
    return result


TICKET_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js"
  onload="renderMathInElement(document.body,{{delimiters:[{{left:'$$',right:'$$',display:true}},{{left:'$',right:'$',display:false}},{{left:'\\(',right:'\\)',display:false}},{{left:'\\[',right:'\\]',display:true}}],throwOnError:false}})"></script>
<style>
:root{{--bg:#0f0f1a;--fg:#e8e8f0;--muted:#8888a0;--accent:#60a5fa;--border:rgba(255,255,255,0.12);
  --glass-bg:rgba(255,255,255,0.06);--card-bg:rgba(255,255,255,0.08);--card-border:rgba(255,255,255,0.15)}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,'SF Pro Display','Inter',system-ui,sans-serif;background:linear-gradient(135deg,#0f0f1a,#1a1a2e,#16213e);
  color:var(--fg);line-height:1.7;min-height:100vh;-webkit-font-smoothing:antialiased}}
body::before{{content:'';position:fixed;width:500px;height:500px;top:-10%;left:-5%;border-radius:50%;
  filter:blur(120px);opacity:0.4;z-index:-1;pointer-events:none;
  background:radial-gradient(circle,rgba(96,165,250,0.3),transparent 70%)}}
.container{{max-width:820px;margin:0 auto;padding:2.5rem 1.5rem}}
h1{{font-size:1.5rem;font-weight:700;letter-spacing:-0.03em;margin-bottom:0.5rem}}
.subtitle{{color:var(--muted);font-size:.85rem;margin-bottom:2rem}}
.ticket{{background:var(--card-bg);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid var(--card-border);border-radius:16px;padding:1.5rem 2rem;margin-bottom:1.5rem;
  box-shadow:0 8px 32px rgba(0,0,0,0.3);position:relative;overflow:hidden;page-break-inside:avoid}}
.ticket::before{{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 10%,rgba(255,255,255,0.15) 50%,transparent 90%)}}
.ticket-num{{font-size:.75rem;font-weight:600;color:var(--accent);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.3rem}}
.ticket-q{{font-size:1.1rem;font-weight:600;margin-bottom:1rem;padding-bottom:.75rem;border-bottom:1px solid var(--border)}}
.ticket-body{{font-size:.93rem;line-height:1.8}}
.ticket-body h2{{font-size:1rem;font-weight:600;margin:1.5rem 0 .5rem;color:var(--accent)}}
.ticket-body h3{{font-size:.93rem;font-weight:600;margin:1.2rem 0 .4rem}}
.ticket-body p{{margin-bottom:.7rem}}
.ticket-body strong{{color:#fff}}
.ticket-body table{{width:100%;border-collapse:collapse;margin:.8rem 0;font-size:.88rem}}
.ticket-body th,.ticket-body td{{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--border)}}
.ticket-body th{{font-weight:600;font-size:.76rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}}
.ticket-body ul,.ticket-body ol{{margin:.5rem 0 .5rem 1.5rem}}
.ticket-body li{{margin-bottom:.3rem}}
.ticket-body code{{font-family:'JetBrains Mono',monospace;font-size:.82rem;background:rgba(255,255,255,0.08);
  padding:.1rem .4rem;border-radius:6px}}
.footer{{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.78rem;color:var(--muted)}}
@media print{{body{{background:#fff;color:#1a1a2e}}body::before{{display:none}}
  .ticket{{background:#fff;border:1px solid #ddd;box-shadow:none}}
  .ticket::before{{display:none}}.ticket-body h2{{color:#2563eb}}
  .ticket-body strong{{color:#000}}.footer{{color:#888}}}}
@media(max-width:640px){{.container{{padding:1.5rem 1rem}}.ticket{{padding:1.2rem 1.2rem}}}}
</style>
</head>
<body>
<div class="container">
<h1>{title}</h1>
<div class="subtitle">{subtitle}</div>
{tickets_html}
<div class="footer">StudyLab · study.24pensi.ru · Сгенерировано {date}</div>
</div>
</body>
</html>"""


@app.get("/api/subjects/{slug}/tickets/export")
async def export_tickets_html(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM exam_tickets WHERE subject_slug=? ORDER BY id", (slug,)
    ).fetchall()
    subject_row = db.execute("SELECT title FROM subjects WHERE slug=?", (slug,)).fetchone()
    db.close()
    title = subject_row["title"] if subject_row else slug

    tickets_html = []
    for i, r in enumerate(rows, 1):
        answer_html = _md_to_html(r["answer"]) if r["answer"] else "<p><em>Ответ не сгенерирован</em></p>"
        tickets_html.append(
            f'<div class="ticket">'
            f'<div class="ticket-num">Билет {i}</div>'
            f'<div class="ticket-q">{r["question"]}</div>'
            f'<div class="ticket-body">{answer_html}</div>'
            f'</div>'
        )

    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M")
    html = TICKET_HTML_TEMPLATE.format(
        title=f"Билеты: {title}",
        subtitle=f"{len(rows)} вопросов · {title}",
        tickets_html="\n".join(tickets_html),
        date=now
    )
    return HTMLResponse(html, headers={
        "Content-Disposition": f'attachment; filename="tickets_{slug}.html"'
    })


@app.get("/api/subjects/{slug}/tickets/{tid}/export")
async def export_single_ticket(slug: str, tid: int, user: dict = Depends(current_user)):
    db = get_db()
    row = db.execute("SELECT * FROM exam_tickets WHERE id=? AND subject_slug=?", (tid, slug)).fetchone()
    subject_row = db.execute("SELECT title FROM subjects WHERE slug=?", (slug,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Билет не найден")
    title = subject_row["title"] if subject_row else slug

    answer_html = _md_to_html(row["answer"]) if row["answer"] else "<p><em>Ответ не сгенерирован</em></p>"
    ticket_html = (
        f'<div class="ticket">'
        f'<div class="ticket-num">Билет</div>'
        f'<div class="ticket-q">{row["question"]}</div>'
        f'<div class="ticket-body">{answer_html}</div>'
        f'</div>'
    )

    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M")
    html = TICKET_HTML_TEMPLATE.format(
        title=row["question"],
        subtitle=title,
        tickets_html=ticket_html,
        date=now
    )
    return HTMLResponse(html, headers={
        "Content-Disposition": f'attachment; filename="ticket_{tid}.html"'
    })


# ─── Stage 7 additions ────────────────────────────────────────────────

@app.post("/api/subjects/{slug}/chat/ocr-image")
async def ocr_image(slug: str, file: UploadFile = File(),
                    user: dict = Depends(current_user)):
    """OCR a photo using Timeweb Vision API and return extracted text."""
    if not TIMEWEB_API_KEY:
        raise HTTPException(503, "TIMEWEB_API_KEY не задан")
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "Файл слишком большой (макс. 10 МБ)")
    b64 = _b64.b64encode(content).decode()
    messages = [{"role": "user", "content": [
        {"type": "text",
         "text": "Распознай весь текст, формулы и схемы с этого фото конспекта. Верни только распознанный текст."},
        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}
    ]}]
    async with _httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            TIMEWEB_URL,
            headers={"Authorization": f"Bearer {TIMEWEB_API_KEY}"},
            json={"model": VISION_MODEL, "messages": messages,
                  "stream": False, "max_tokens": 2048, "temperature": 0.1}
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
    return {"text": text}


# ─── Static media (images from converted documents) ──────────────────

from fastapi.responses import FileResponse
import mimetypes

@app.get("/api/subjects/{slug}/media/{src_slug}/{path:path}")
async def serve_media(slug: str, src_slug: str, path: str,
                       user: dict = Depends(current_user)):
    file_path = subject_dir(slug) / "md" / src_slug / path
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "Файл не найден")
    mime, _ = mimetypes.guess_type(str(file_path))
    return FileResponse(file_path, media_type=mime or "application/octet-stream")


# ─── ROUTES END ────────────────────────────────────────────────────────


# ─── Frontend ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_SPA


HTML_SPA = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>StudyLab</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060610;--bg2:#0a0a18;
  --glass:rgba(255,255,255,0.05);--glass2:rgba(255,255,255,0.08);
  --border:rgba(255,255,255,0.10);--border2:rgba(255,255,255,0.16);
  --accent:#818cf8;--accent2:#a78bfa;
  --green:#4ade80;--red:#f87171;--yellow:#fbbf24;
  --text:#e2e8f0;--muted:#94a3b8;--dim:#64748b;
}
body{background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse at 15% 15%,rgba(99,102,241,.12) 0%,transparent 50%),
             radial-gradient(ellipse at 85% 85%,rgba(139,92,246,.08) 0%,transparent 50%)}
#app{position:relative;z-index:1}
.glass{background:var(--glass);backdrop-filter:blur(24px) saturate(1.8);
  -webkit-backdrop-filter:blur(24px) saturate(1.8);
  border:1px solid var(--border);border-radius:16px}
.glass2{background:var(--glass2);backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);border:1px solid var(--border2);border-radius:12px}
.navbar{position:sticky;top:0;z-index:100;background:rgba(6,6,16,.85);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);padding:0 24px;height:56px;
  display:flex;align-items:center;gap:12px}
.logo{font-weight:700;font-size:1.1rem;color:var(--accent);letter-spacing:-.02em;text-decoration:none}
.nav-links{display:flex;gap:4px;flex:1;align-items:center;flex-wrap:wrap}
.nav-btn{background:none;border:none;color:var(--muted);cursor:pointer;padding:6px 12px;
  border-radius:8px;font-size:.875rem;transition:all .15s;font-family:inherit}
.nav-btn:hover{background:var(--glass2);color:var(--text)}
.nav-btn.active{background:var(--glass2);color:var(--accent)}
.nav-user{font-size:.8125rem;color:var(--muted);display:flex;align-items:center;gap:8px;flex-shrink:0}
.page{padding:32px 24px;max-width:1200px;margin:0 auto}
.card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.subject-card{padding:20px;cursor:pointer;transition:all .2s;text-decoration:none;color:inherit;display:block}
.subject-card:hover{background:var(--glass2);border-color:var(--border2);
  transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,.3)}
.card-title{font-size:1rem;font-weight:600;margin-bottom:6px}
.card-meta{font-size:.8125rem;color:var(--muted)}
input,textarea,select{background:rgba(255,255,255,.07);border:1px solid var(--border);
  border-radius:10px;color:var(--text);padding:10px 14px;font-size:.9375rem;
  width:100%;outline:none;transition:border-color .15s;font-family:inherit}
input:focus,textarea:focus{border-color:var(--accent);background:rgba(255,255,255,.09)}
input::placeholder,textarea::placeholder{color:var(--dim)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:10px;
  font-size:.875rem;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:inherit}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#6366f1}
.btn-ghost{background:var(--glass2);color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,.12)}
.btn-danger{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3)}
.btn-danger:hover{background:rgba(248,113,113,.25)}
.btn-sm{padding:5px 10px;font-size:.8125rem}
.btn:disabled{opacity:.5;cursor:not-allowed}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:500}
.badge-green{background:rgba(74,222,128,.15);color:var(--green)}
.badge-yellow{background:rgba(251,191,36,.15);color:var(--yellow)}
.badge-red{background:rgba(248,113,113,.15);color:var(--red)}
.badge-blue{background:rgba(129,140,248,.15);color:var(--accent)}
.progress{height:4px;background:var(--glass2);border-radius:2px;margin-top:8px}
.progress-bar{height:100%;background:var(--accent);border-radius:2px;transition:width .3s}
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.login-card{width:100%;max-width:380px;padding:36px}
.login-title{font-size:1.75rem;font-weight:700;margin-bottom:4px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.login-sub{color:var(--muted);font-size:.875rem;margin-bottom:28px}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:.8125rem;color:var(--muted);margin-bottom:6px}
.form-error{color:var(--red);font-size:.8125rem;margin-top:8px}
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px}
.section-title{font-size:1.125rem;font-weight:600}
.source-list{display:flex;flex-direction:column;gap:8px}
.source-item{padding:14px 16px;display:flex;align-items:center;gap:12px}
.source-icon{width:36px;height:36px;border-radius:8px;background:rgba(129,140,248,.15);
  display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0}
.source-info{flex:1;min-width:0}
.source-name{font-size:.9375rem;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.source-meta{font-size:.8rem;color:var(--muted);margin-top:2px}
.drop-zone{border:2px dashed var(--border2);border-radius:14px;padding:36px;text-align:center;
  cursor:pointer;transition:all .2s;background:rgba(255,255,255,.02)}
.drop-zone:hover,.drop-zone.drag-over{border-color:var(--accent);background:rgba(129,140,248,.05)}
.drop-zone-icon{font-size:2rem;margin-bottom:8px}
.drop-zone-sub{color:var(--muted);font-size:.875rem;margin-top:6px}
.three-col{display:grid;grid-template-columns:260px 1fr}
.reader-sidebar{border-right:1px solid var(--border);height:calc(100vh - 56px);
  overflow-y:auto;position:sticky;top:56px}
.reader-sidebar-inner{padding:16px 0}
.toc-group-label{padding:8px 16px 4px;font-size:.75rem;font-weight:600;color:var(--dim);
  text-transform:uppercase;letter-spacing:.06em}
.toc-item{padding:7px 16px;cursor:pointer;font-size:.875rem;color:var(--muted);
  transition:all .15s;display:flex;align-items:flex-start;gap:8px;line-height:1.4}
.toc-item:hover{background:rgba(255,255,255,.04);color:var(--text)}
.toc-item.active{background:rgba(129,140,248,.12);color:var(--accent)}
.toc-num{font-size:.75rem;color:var(--dim);flex-shrink:0;margin-top:1px}
.reader-content{padding:32px 40px;max-width:760px;line-height:1.8;font-size:.9375rem}
.reader-content h1,.reader-content h2,.reader-content h3{margin:1.5em 0 .5em;font-weight:600}
.reader-content h2{font-size:1.125rem}
.reader-content h3{font-size:1rem;color:var(--muted)}
.reader-content p{margin-bottom:.875em}
.reader-content code{background:var(--glass2);padding:2px 6px;border-radius:4px;font-size:.875em}
.reader-content pre{background:var(--glass2);padding:14px;border-radius:10px;overflow-x:auto;margin:1em 0}
.conv-sidebar{width:260px;border-right:1px solid var(--border);display:flex;flex-direction:column;
  background:rgba(6,6,16,.5);flex-shrink:0}
.conv-item{padding:10px 14px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.04);
  display:flex;align-items:center;gap:8px;transition:background .15s;position:relative}
.conv-item:hover{background:rgba(255,255,255,.04)}
.conv-item.active{background:rgba(129,140,248,.12)}
.conv-title{flex:1;font-size:.8125rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.conv-date{font-size:.7rem;color:var(--dim);flex-shrink:0}
.conv-del{background:none;border:none;color:var(--dim);cursor:pointer;font-size:.75rem;
  padding:2px 4px;opacity:0;transition:opacity .15s;flex-shrink:0}
.conv-item:hover .conv-del{opacity:1}
.conv-del:hover{color:var(--red)}
.chat-layout{display:flex;flex-direction:column;height:calc(100vh - 56px)}
.chat-messages{flex:1;overflow-y:auto;padding:20px 24px;display:flex;flex-direction:column;gap:16px}
.msg{display:flex;gap:12px;max-width:820px}
.msg-user{align-self:flex-end;flex-direction:row-reverse}
.msg-avatar{width:32px;height:32px;border-radius:50%;background:var(--glass2);
  display:flex;align-items:center;justify-content:center;font-size:.875rem;flex-shrink:0}
.msg-user .msg-avatar{background:rgba(129,140,248,.2)}
.msg-bubble{padding:12px 16px;border-radius:14px;line-height:1.65;font-size:.9375rem;max-width:660px}
.msg-user .msg-bubble{background:rgba(99,102,241,.18);border:1px solid rgba(99,102,241,.28);border-radius:14px 4px 14px 14px}
.msg-assistant .msg-bubble{background:var(--glass2);border:1px solid var(--border);border-radius:4px 14px 14px 14px}
.msg-bubble p{margin-bottom:.5em}
.msg-bubble p:last-child{margin-bottom:0}
.msg-bubble code{background:rgba(255,255,255,.1);padding:1px 5px;border-radius:3px;font-size:.875em}
.msg-bubble h2,.msg-bubble h3{margin:.75em 0 .3em;font-size:1em;font-weight:600}
.prov{font-size:.78em;color:var(--accent);opacity:.75}
.math-block{text-align:center;margin:.8em 0;font-size:1.1em}
.chat-input-area{padding:14px 24px 18px;border-top:1px solid var(--border);
  background:rgba(6,6,16,.7);backdrop-filter:blur(12px)}
.chat-input-row{display:flex;gap:8px;align-items:flex-end}
.chat-input-row textarea{flex:1;resize:none;min-height:44px;max-height:120px;border-radius:12px}
.img-preview-bar{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.img-preview-bar img{height:56px;border-radius:8px;border:1px solid var(--border)}
.chat-hint{font-size:.75rem;color:var(--dim);margin-top:8px;display:flex;justify-content:space-between;align-items:center}
.ticket-item{padding:18px 20px;margin-bottom:10px}
.ticket-q{font-weight:500;margin-bottom:8px;line-height:1.5}
.ticket-answer{color:var(--muted);font-size:.875rem;line-height:1.65;
  white-space:pre-wrap;margin-top:12px;padding-top:12px;border-top:1px solid var(--border)}
.ticket-answer p{margin-bottom:.5em}
.ticket-answer code{background:rgba(255,255,255,.1);padding:1px 5px;border-radius:3px}
.tabs{display:flex;gap:4px;margin-bottom:20px}
.tab{padding:7px 16px;border-radius:8px;font-size:.875rem;cursor:pointer;
  border:1px solid transparent;transition:all .15s;background:none;color:var(--muted);font-family:inherit}
.tab.active{background:var(--glass2);border-color:var(--border);color:var(--text)}
.tab:hover:not(.active){color:var(--text);background:rgba(255,255,255,.03)}
.search-hit{padding:14px;cursor:pointer;transition:all .15s}
.search-hit:hover{background:rgba(255,255,255,.06)}
.search-score{font-size:.75rem;color:var(--accent);font-weight:600}
.search-title{font-weight:500;margin:3px 0;font-size:.9375rem}
.search-text{font-size:.8125rem;color:var(--muted);line-height:1.5}
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast{padding:12px 18px;border-radius:10px;font-size:.875rem;max-width:320px;animation:slideIn .2s ease}
.toast-success{background:rgba(74,222,128,.15);border:1px solid rgba(74,222,128,.3);color:var(--green)}
.toast-error{background:rgba(248,113,113,.15);border:1px solid rgba(248,113,113,.3);color:var(--red)}
.toast-info{background:var(--glass2);border:1px solid var(--border);color:var(--text)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;
  display:flex;align-items:center;justify-content:center;padding:24px}
.modal{width:100%;max-width:420px;padding:28px}
.modal-title{font-size:1.1rem;font-weight:600;margin-bottom:20px}
.hidden{display:none!important}
.mt{margin-top:16px}.mt2{margin-top:24px}
.flex{display:flex}.gap{gap:10px}.ml-auto{margin-left:auto}
.text-muted{color:var(--muted)}.text-sm{font-size:.875rem}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.2);
  border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.2)}
@media(max-width:768px){
  .three-col{grid-template-columns:1fr}
  .reader-sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--border);max-height:260px}
  .page{padding:20px 16px}
  .navbar{padding:0 16px;gap:8px}
  .conv-sidebar{width:200px}
  .chat-messages{padding:14px 16px}
  .chat-input-area{padding:12px 16px 16px}
  .reader-content{padding:20px 18px}
}
</style>
</head>
<body>
<div id="app">
  <nav class="navbar hidden" id="navbar"></nav>
  <main id="main"></main>
  <div class="toast-container" id="toasts"></div>
</div>
<script>
// ── State ──────────────────────────────────────────────────────────────
const S = { user: null, chatES: null, pendingImg: null, chatConvId: 0 };

// ── Toast ──────────────────────────────────────────────────────────────
function toast(msg, type) {
  type = type || 'info';
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(function() { el.remove(); }, 3500);
}

// ── API helper ─────────────────────────────────────────────────────────
async function api(path, opts) {
  opts = opts || {};
  opts.credentials = 'include';
  const r = await fetch(path, opts);
  if (r.status === 401) {
    S.user = null;
    location.hash = '#/login';
    throw new Error('Не авторизован');
  }
  return r;
}

// ── HTML escape ────────────────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Simple markdown → HTML ─────────────────────────────────────────────
function md(text) {
  if (!text) return '';
  // Normalize block formulas: $$ on separate lines → single line $$...$$
  var t = text.replace(/\$\$\s*\n([\s\S]*?)\n\s*\$\$/g, function(_, body) {
    return '$$' + body.trim() + '$$';
  });
  // Protect LaTeX formulas from escaping
  var formulas = [];
  t = t.replace(/\$\$[^$]+\$\$/g, function(m) { formulas.push(m); return '\x00F' + (formulas.length - 1) + '\x00'; });
  t = t.replace(/\$[^$\n]+\$/g, function(m) { formulas.push(m); return '\x00F' + (formulas.length - 1) + '\x00'; });
  // Parse tables before escaping (protect cell content)
  var tables = [];
  t = t.replace(/((?:^\|.+\|$\n?){2,})/gm, function(block) {
    var rows = block.trim().split('\n');
    var html = '<table>';
    var isFirst = true;
    for (var ri = 0; ri < rows.length; ri++) {
      var row = rows[ri].trim();
      if (!row.startsWith('|')) continue;
      var cells = row.split('|').slice(1, -1);
      if (cells.every(function(c) { return /^[\s\-:]+$/.test(c); })) continue; // separator
      var tag = isFirst ? 'th' : 'td';
      html += '<tr>' + cells.map(function(c) { return '<' + tag + '>' + esc(c.trim()) + '</' + tag + '>'; }).join('') + '</tr>';
      isFirst = false;
    }
    html += '</table>';
    tables.push(html);
    return '\x00T' + (tables.length - 1) + '\x00';
  });
  var h = esc(t);
  h = h.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  h = h.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/^# (.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Provenance links: [src:SLUG#SEG | раздел: Title] → clickable link to reader
  h = h.replace(/\[src:([a-z0-9а-яё\-]+)#(\d+)\s*\|\s*([^\]]+)\]/gi, function(_, srcSlug, seg, rest) {
    var subjectSlug = (location.hash.match(/\/(chat|tickets|subject|reader)\/([^/]+)/) || [])[2] || '';
    return '<a href="#/reader/' + subjectSlug + '?src=' + srcSlug + '&seg=' + seg + '" class="prov" title="Открыть в читалке" style="cursor:pointer">[📖 ' + rest.trim() + ']</a>';
  });
  h = h.replace(/\[([^\]]+)\]/g, '<span class="prov">[$1]</span>');
  // Convert numbered lists with explicit numbers
  h = h.replace(/^(\d+)\.\s+(.+)$/gm, function(_, num, content) {
    return '<li value="' + num + '">' + content + '</li>';
  });
  h = h.replace(/((?:<li[^>]*>.*?<\/li>\n?)+)/g, '<ol>$1</ol>');
  // Bullet lists
  h = h.replace(/^[-*]\s+(.+)$/gm, '<li>$1</li>');
  h = h.replace(/((?:<li>.*?<\/li>\n?)+)/g, function(m) {
    if (m.includes('value=')) return m;
    return '<ul>' + m + '</ul>';
  });
  h = h.replace(/\n\n+/g, '</p><p>');
  h = h.replace(/\n/g, '<br>');
  // Restore tables
  h = h.replace(/\x00T(\d+)\x00/g, function(_, i) { return '</p>' + tables[parseInt(i)] + '<p>'; });
  // Restore formulas — block formulas get their own div
  h = h.replace(/\x00F(\d+)\x00/g, function(_, i) {
    var f = formulas[parseInt(i)];
    if (f.startsWith('$$')) return '</p><div class="math-block">' + f + '</div><p>';
    return f;
  });
  h = h.replace(/<p>\s*<\/p>/g, '');
  return '<p>' + h + '</p>';
}
function renderMath(el) {
  if (!el || typeof renderMathInElement !== 'function') return;
  try {
    renderMathInElement(el, {
      delimiters: [
        {left: '$$', right: '$$', display: true},
        {left: '$', right: '$', display: false},
        {left: '\\(', right: '\\)', display: false},
        {left: '\\[', right: '\\]', display: true}
      ],
      throwOnError: false
    });
  } catch(e) {}
}

// ── Router ─────────────────────────────────────────────────────────────
function route() {
  const hash = (location.hash.slice(1) || '/login').split('?')[0];
  const parts = hash.split('/').filter(Boolean);
  const view = parts[0] || 'login';
  const slug = parts[1] || '';
  if (S.chatES) { S.chatES.close(); S.chatES = null; }
  updateNav(view, slug);
  const main = document.getElementById('main');
  main.innerHTML = '';
  if (!S.user && view !== 'login') { location.hash = '#/login'; return; }
  if (S.user && view === 'login') { location.hash = '#/dashboard'; return; }
  const views = { login: vLogin, dashboard: vDashboard, subject: vSubject,
                  reader: vReader, chat: vChat, tickets: vTickets };
  const fn = views[view];
  if (fn) fn(main, slug); else location.hash = '#/dashboard';
}

// ── Navbar ─────────────────────────────────────────────────────────────
function updateNav(view, slug) {
  const nb = document.getElementById('navbar');
  if (view === 'login') { nb.classList.add('hidden'); return; }
  nb.classList.remove('hidden');
  const labels = {subject:'Предмет', reader:'Читалка', chat:'Чат', tickets:'Билеты'};
  const subjectViews = ['subject','reader','chat','tickets'];
  nb.innerHTML =
    '<a href="#/dashboard" class="logo">StudyLab</a>' +
    '<div class="nav-links">' +
    (slug && view !== 'dashboard' ?
      '<button class="nav-btn" onclick="location.hash=\'#/dashboard\'">← Предметы</button>' +
      '<span style="color:var(--dim)">›</span>' +
      '<span class="nav-btn active">' + (labels[view] || view) + '</span>' +
      (subjectViews.includes(view) && slug ?
        '<div class="flex gap" style="margin-left:6px">' +
        '<button class="nav-btn' + (view==='subject'?' active':'') + '" onclick="location.hash=\'#/subject/' + slug + '\'">Источники</button>' +
        '<button class="nav-btn' + (view==='reader'?' active':'') + '" onclick="location.hash=\'#/reader/' + slug + '\'">📖</button>' +
        '<button class="nav-btn' + (view==='chat'?' active':'') + '" onclick="location.hash=\'#/chat/' + slug + '\'">💬</button>' +
        '<button class="nav-btn' + (view==='tickets'?' active':'') + '" onclick="location.hash=\'#/tickets/' + slug + '\'">📋</button>' +
        '</div>' : '') :
      '<button class="nav-btn active">Предметы</button>') +
    '</div>' +
    '<div class="nav-user">' +
    '<span>' + esc(S.user ? S.user.username : '') + '</span>' +
    '<span class="badge badge-blue" style="font-size:.7rem">' + esc(S.user ? S.user.role : '') + '</span>' +
    (S.user && S.user.role !== 'admin' ? '<button class="btn btn-ghost btn-sm" onclick="showPasswordReset()" title="Сменить пароль">🔑</button>' : '') +
    '<button class="btn btn-ghost btn-sm" onclick="doLogout()">Выйти</button>' +
    '</div>';
}

async function showPasswordReset() {
  // Check status first
  var r = await api('/api/password-reset-status');
  var st = await r.json();
  if (st.has_pending) {
    toast('Запрос уже отправлен. Ожидайте подтверждения администратора.', 'info');
    return;
  }
  if (st.status === 'approved') {
    showSetNewPassword();
    return;
  }
  var ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML =
    '<div class="glass modal">' +
    '<div class="modal-title">Смена пароля</div>' +
    '<p class="text-sm text-muted" style="margin-bottom:16px">Запрос на смену пароля будет отправлен администратору на почту. После подтверждения вы сможете установить новый пароль.</p>' +
    '<div class="flex gap">' +
    '<button class="btn btn-ghost" id="pr-cancel">Отмена</button>' +
    '<button class="btn btn-primary" id="pr-send">Отправить запрос</button>' +
    '</div></div>';
  document.body.appendChild(ov);
  ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
  document.getElementById('pr-cancel').addEventListener('click', function() { ov.remove(); });
  document.getElementById('pr-send').addEventListener('click', async function() {
    var r2 = await api('/api/request-password-reset', {method:'POST'});
    if (r2.ok) { toast('Запрос отправлен администратору', 'success'); }
    else { var err = await r2.json(); toast(err.detail || 'Ошибка', 'error'); }
    ov.remove();
  });
}

function showSetNewPassword() {
  var ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML =
    '<div class="glass modal">' +
    '<div class="modal-title">Установка нового пароля</div>' +
    '<p class="text-sm" style="color:var(--green);margin-bottom:16px">Администратор одобрил смену пароля</p>' +
    '<form id="new-pw-form">' +
    '<div class="form-group"><label class="form-label">Новый пароль</label>' +
    '<input type="password" id="new-pw" placeholder="Минимум 8 символов, заглавная, спецсимвол"></div>' +
    '<div class="form-group"><label class="form-label">Повторите пароль</label>' +
    '<input type="password" id="new-pw2"></div>' +
    '<div id="pw-err" class="form-error hidden"></div>' +
    '<div class="flex gap" style="margin-top:8px">' +
    '<button type="button" class="btn btn-ghost" id="pw-cancel">Отмена</button>' +
    '<button type="submit" class="btn btn-primary">Сохранить</button>' +
    '</div></form></div>';
  document.body.appendChild(ov);
  ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
  document.getElementById('pw-cancel').addEventListener('click', function() { ov.remove(); });
  document.getElementById('new-pw-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    var pw = document.getElementById('new-pw').value;
    var pw2 = document.getElementById('new-pw2').value;
    var errEl = document.getElementById('pw-err');
    if (pw !== pw2) { errEl.textContent = 'Пароли не совпадают'; errEl.classList.remove('hidden'); return; }
    var fd = new FormData(); fd.append('new_password', pw);
    var r = await api('/api/set-new-password', {method:'POST', body:fd});
    if (r.ok) { toast('Пароль изменён', 'success'); ov.remove(); }
    else { var err = await r.json(); errEl.textContent = err.detail || 'Ошибка'; errEl.classList.remove('hidden'); }
  });
}

async function doLogout() {
  await fetch('/api/logout', {method:'POST', credentials:'include'});
  S.user = null;
  location.hash = '#/login';
}

// ── Login ──────────────────────────────────────────────────────────────
function vLogin(main) {
  main.innerHTML =
    '<div class="login-page">' +
    '<div class="glass login-card">' +
    '<div class="login-title">StudyLab</div>' +
    '<div class="login-sub">Персональная образовательная среда · Биофак МГУ</div>' +
    '<form id="login-form">' +
    '<div class="form-group"><label class="form-label">Имя пользователя</label>' +
    '<input type="text" id="u" placeholder="admin или student" autocomplete="username"></div>' +
    '<div class="form-group"><label class="form-label">Пароль</label>' +
    '<input type="password" id="p" autocomplete="current-password"></div>' +
    '<div id="lerr" class="form-error hidden"></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;justify-content:center">Войти</button>' +
    '</form>' +
    '<div style="text-align:center;margin-top:16px">' +
    '<button class="btn btn-ghost btn-sm" style="font-size:.8rem;color:var(--muted)" id="btn-forgot">Забыла пароль</button>' +
    '</div></div></div>';
  document.getElementById('btn-forgot').addEventListener('click', function() {
    toast('Войдите в аккаунт, затем запросите смену пароля в меню', 'info');
  });
  document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const fd = new FormData();
    fd.append('username', document.getElementById('u').value);
    fd.append('password', document.getElementById('p').value);
    const errEl = document.getElementById('lerr');
    errEl.classList.add('hidden');
    try {
      const r = await fetch('/api/login', {method:'POST', body:fd, credentials:'include'});
      if (r.ok) {
        S.user = await r.json();
        location.hash = '#/dashboard';
      } else {
        const err = await r.json();
        errEl.textContent = err.detail || 'Ошибка входа';
        errEl.classList.remove('hidden');
      }
    } catch(e2) {
      errEl.textContent = 'Ошибка сети';
      errEl.classList.remove('hidden');
    }
  });
  document.getElementById('u').focus();
}

// ── Dashboard ──────────────────────────────────────────────────────────
async function vDashboard(main) {
  const isAdmin = S.user && S.user.role === 'admin';
  main.innerHTML =
    '<div class="page">' +
    '<div class="section-header">' +
    '<h1 class="section-title">Мои предметы</h1>' +
    (isAdmin ? '<button class="btn btn-primary btn-sm" id="btn-add-subj">+ Добавить предмет</button>' : '') +
    '</div>' +
    '<div id="subj-grid" class="card-grid"><div class="text-muted text-sm"><div class="spinner"></div></div></div>' +
    '</div>';
  if (isAdmin) {
    document.getElementById('btn-add-subj').addEventListener('click', showAddSubject);
  }
  try {
    const r = await api('/api/subjects');
    const list = await r.json();
    const grid = document.getElementById('subj-grid');
    if (!grid) return;
    if (!list.length) {
      grid.innerHTML = '<p class="text-muted text-sm">Предметов пока нет.' + (isAdmin ? ' Нажмите «+ Добавить предмет».' : '') + '</p>';
      return;
    }
    grid.innerHTML = list.map(function(s) {
      const pct = s.source_count ? Math.round(s.active_count / s.source_count * 100) : 0;
      return '<div class="glass subject-card" onclick="location.hash=\'#/subject/' + s.slug + '\'">' +
        '<div class="card-title">' + esc(s.title) + (s.year ? ' <span class="badge badge-blue" style="font-size:.65rem;vertical-align:middle">' + s.year + ' курс</span>' : '') + '</div>' +
        '<div class="card-meta">' + s.source_count + ' источников · ' + s.total_chunks + ' чанков</div>' +
        '<div class="progress"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
        '<div class="card-meta" style="margin-top:6px">' + s.active_count + '/' + s.source_count + ' активных</div>' +
        '</div>';
    }).join('');
  } catch(e) { toast('Ошибка загрузки', 'error'); }
}

function showAddSubject() {
  const ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML =
    '<div class="glass modal">' +
    '<div class="modal-title">Новый предмет</div>' +
    '<form id="new-subj-form">' +
    '<div class="form-group"><label class="form-label">Название</label>' +
    '<input type="text" id="ns-title" placeholder="Микробиология" required></div>' +
    '<div class="form-group"><label class="form-label">Описание</label>' +
    '<textarea id="ns-desc" rows="2" placeholder="Краткое описание…"></textarea></div>' +
    '<div class="form-group"><label class="form-label">Курс</label>' +
    '<select id="ns-year" style="padding:8px 12px"><option value="0">—</option><option value="1">1 курс</option><option value="2">2 курс</option><option value="3">3 курс</option><option value="4">4 курс</option><option value="5">5 курс</option><option value="6">6 курс</option></select></div>' +
    '<div class="flex gap" style="margin-top:4px">' +
    '<button type="button" class="btn btn-ghost" id="ns-cancel">Отмена</button>' +
    '<button type="submit" class="btn btn-primary">Создать</button>' +
    '</div></form></div>';
  document.body.appendChild(ov);
  ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
  document.getElementById('ns-cancel').addEventListener('click', function() { ov.remove(); });
  document.getElementById('new-subj-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const fd = new FormData();
    fd.append('title', document.getElementById('ns-title').value);
    fd.append('description', document.getElementById('ns-desc').value);
    fd.append('year', document.getElementById('ns-year').value);
    const r = await api('/api/subjects', {method:'POST', body:fd});
    if (r.ok) {
      toast('Предмет создан', 'success');
      ov.remove();
      vDashboard(document.getElementById('main'));
    } else {
      const err = await r.json();
      toast(err.detail || 'Ошибка', 'error');
    }
  });
  setTimeout(function() { document.getElementById('ns-title').focus(); }, 50);
}

// ── Subject ────────────────────────────────────────────────────────────
async function vSubject(main, slug) {
  let subject = {title: slug, slug: slug};
  try { const r = await api('/api/subjects/' + slug); subject = await r.json(); } catch(e) {}
  main.innerHTML =
    '<div class="page">' +
    '<div class="section-header">' +
    '<h1 class="section-title">' + esc(subject.title) + '</h1>' +
    '<div class="flex gap">' +
    '<button class="btn btn-ghost btn-sm" onclick="location.hash=\'#/chat/' + slug + '\'">💬 Чат</button>' +
    '<button class="btn btn-ghost btn-sm" onclick="location.hash=\'#/tickets/' + slug + '\'">📋 Билеты</button>' +
    '<button class="btn btn-ghost btn-sm" onclick="location.hash=\'#/reader/' + slug + '\'">📖 Читалка</button>' +
    '</div></div>' +
    '<div class="tabs">' +
    '<button class="tab active" id="tab-btn-src" onclick="switchTab(\'src\',this)">📁 Источники</button>' +
    '<button class="tab" id="tab-btn-srch" onclick="switchTab(\'srch\',this)">🔍 Поиск</button>' +
    '</div>' +
    '<div id="tab-src"></div>' +
    '<div id="tab-srch" class="hidden">' +
    '<input type="text" id="srch-input" placeholder="Семантический поиск по источникам… (Enter)">' +
    '<div id="srch-res" class="mt"></div>' +
    '</div>' +
    '</div>';
  setupSearch(slug);
  await loadSources(slug);
}

function switchTab(tab, btn) {
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  btn.classList.add('active');
  ['src','srch'].forEach(function(t) {
    const el = document.getElementById('tab-' + t);
    if (el) el.classList.toggle('hidden', t !== tab);
  });
}

function setupSearch(slug) {
  const inp = document.getElementById('srch-input');
  if (!inp) return;
  inp.addEventListener('keydown', async function(e) {
    if (e.key !== 'Enter') return;
    const q = inp.value.trim();
    if (!q) return;
    const res = document.getElementById('srch-res');
    res.innerHTML = '<div class="text-muted text-sm"><div class="spinner"></div> Поиск…</div>';
    try {
      const r = await api('/api/subjects/' + slug + '/search?q=' + encodeURIComponent(q));
      const hits = await r.json();
      if (!hits.length) { res.innerHTML = '<p class="text-muted text-sm">Ничего не найдено.</p>'; return; }
      res.innerHTML = '<div style="display:flex;flex-direction:column;gap:10px">' +
        hits.map(function(h) {
          return '<div class="glass2 search-hit">' +
            '<span class="search-score">' + Math.round(h.score * 100) + '%</span>' +
            '<div class="search-title">' + esc(h.title) + '</div>' +
            '<div class="search-text">' + esc(h.text) + '</div>' +
            '</div>';
        }).join('') + '</div>';
    } catch(e2) {
      res.innerHTML = '<p class="text-sm" style="color:var(--red)">Ошибка поиска</p>';
    }
  });
}

async function loadSources(slug) {
  const el = document.getElementById('tab-src');
  if (!el) return;
  try {
    const r = await api('/api/subjects/' + slug + '/sources');
    const srcs = await r.json();
    const isAdmin = S.user && S.user.role === 'admin';
    let html = '';
    if (isAdmin) {
      html += '<div class="drop-zone" id="drop-zone">' +
        '<div class="drop-zone-icon">📁</div>' +
        '<div><strong>Перетащите файлы сюда</strong> или нажмите для выбора</div>' +
        '<div class="drop-zone-sub">PDF, DOCX, TXT, MD — до 50 МБ</div>' +
        '<input type="file" id="file-input" style="display:none" accept=".pdf,.docx,.doc,.txt,.md" multiple>' +
        '</div>';
    }
    html += '<div class="source-list mt" id="src-list">';
    if (!srcs.length) {
      html += '<p class="text-muted text-sm">Источников пока нет.' + (isAdmin ? ' Загрузите файлы выше.' : '') + '</p>';
    } else {
      html += srcs.map(function(s) { return renderSrc(s, slug, isAdmin); }).join('');
    }
    html += '</div>';
    el.innerHTML = html;
    if (isAdmin) setupDrop(slug);
    if (srcs.some(function(s) { return s.status.startsWith('indexing'); })) {
      setTimeout(function() { loadSources(slug); }, 3000);
    }
  } catch(e) { el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>'; }
}

function renderSrc(s, slug, isAdmin) {
  const extIcon = {pdf:'📄', docx:'📝', doc:'📝', txt:'📄', md:'📋'};
  const ext = (s.original_name || '').split('.').pop().toLowerCase();
  var statusBadge;
  if (s.status.startsWith('indexing:')) {
    var parts = s.status.split(':')[1].split(' ');
    var phase = parts[0];
    var phaseLabel = {convert:'конвертация',segment:'сегментация',embed:'эмбеддинг'}[phase] || phase;
    if (phase === 'embed' && parts[1]) {
      var nums = parts[1].split('/');
      var done = parseInt(nums[0]) || 0;
      var total = parseInt(nums[1]) || 1;
      var pct = Math.round(done / total * 100);
      statusBadge = '<span class="badge badge-yellow" style="display:inline-flex;align-items:center;gap:6px;min-width:140px">' +
        '<span class="spinner" style="width:10px;height:10px"></span>' +
        '<span style="flex:1"><div class="progress" style="margin:0;height:6px;background:rgba(255,255,255,.1)"><div class="progress-bar" style="width:' + pct + '%;background:var(--yellow)"></div></div></span>' +
        '<span style="font-size:.7rem">' + done + '/' + total + '</span></span>';
    } else {
      statusBadge = '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> ' + phaseLabel + '</span>';
    }
  } else {
    statusBadge = {
      uploaded: '<span class="badge badge-blue">📥 загружен</span>',
      indexing: '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> индексация</span>',
      indexed: '<span class="badge badge-blue">🔍 проиндексирован</span>',
      active: '<span class="badge badge-green">✓ активен</span>',
      inactive: '<span class="badge" style="background:rgba(255,255,255,.08);color:var(--dim)">⏸ отключён</span>',
      error: '<span class="badge badge-red">⚠ ошибка</span>'
    }[s.status] || '<span class="badge badge-blue">' + esc(s.status) + '</span>';
  }
  var actions = '';
  if (isAdmin) {
    if (s.status === 'uploaded' || s.status === 'error') {
      actions += '<button class="btn btn-primary btn-sm" onclick="srcAction(\'' + slug + '\',\'' + s.slug + '\',\'index\')">⚡ Индексировать</button>';
    }
    if (s.status === 'indexed' || s.status === 'inactive') {
      actions += '<button class="btn btn-primary btn-sm" onclick="srcAction(\'' + slug + '\',\'' + s.slug + '\',\'activate\')">▶ Активировать</button>';
    }
    if (s.status === 'active') {
      actions += '<button class="btn btn-ghost btn-sm" onclick="srcAction(\'' + slug + '\',\'' + s.slug + '\',\'deactivate\')">⏸ Отключить</button>';
    }
    if (s.status === 'indexed' || s.status === 'inactive' || s.status === 'active') {
      actions += '<button class="btn btn-ghost btn-sm" onclick="srcAction(\'' + slug + '\',\'' + s.slug + '\',\'index\')" title="Переиндексировать">🔄</button>';
    }
    actions += '<button class="btn btn-ghost btn-sm" onclick="renameSrc(\'' + slug + '\',\'' + s.slug + '\',\'' + esc(s.title).replace(/'/g,'\\&#39;') + '\')" title="Переименовать">✏️</button>';
    actions += '<button class="btn btn-danger btn-sm" onclick="delSrc(\'' + slug + '\',\'' + s.slug + '\')" title="Удалить">✕</button>';
  }
  var readerLink = (s.status === 'active' || s.status === 'indexed' || s.status === 'inactive') ?
    '<a href="#/reader/' + slug + '" class="btn btn-ghost btn-sm" title="Открыть в читалке" style="text-decoration:none">📖</a>' : '';
  return '<div class="glass2 source-item" id="si-' + s.slug + '">' +
    '<div class="source-icon">' + (extIcon[ext] || '📄') + '</div>' +
    '<div class="source-info">' +
    '<div class="source-name">' + esc(s.title) + '</div>' +
    '<div class="source-meta">' + esc(s.original_name) + (s.chunk_count ? ' · ' + s.chunk_count + ' чанков' : '') + '</div>' +
    '</div>' +
    statusBadge + readerLink +
    '<div class="flex gap" style="flex-shrink:0">' + actions + '</div>' +
    '</div>';
}

function setupDrop(slug) {
  const zone = document.getElementById('drop-zone');
  const inp = document.getElementById('file-input');
  if (!zone || !inp) return;
  zone.addEventListener('click', function(e) { if (e.target !== inp) inp.click(); });
  zone.addEventListener('dragover', function(e) { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', function() { zone.classList.remove('drag-over'); });
  zone.addEventListener('drop', function(e) { e.preventDefault(); zone.classList.remove('drag-over'); uploadFiles(slug, e.dataTransfer.files); });
  inp.addEventListener('change', function() { uploadFiles(slug, inp.files); });
}

async function uploadFiles(slug, files) {
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const fd = new FormData();
    fd.append('file', file);
    fd.append('title', file.name.replace(/\.[^.]+$/, ''));
    // Show upload progress bar
    var progEl = document.createElement('div');
    progEl.className = 'toast toast-info';
    progEl.style.minWidth = '240px';
    progEl.innerHTML = '<div style="margin-bottom:4px;font-size:.8125rem">' + esc(file.name) + '</div>' +
      '<div class="progress" style="height:6px;margin:0"><div class="progress-bar" id="up-prog-' + i + '" style="width:0%"></div></div>';
    document.getElementById('toasts').appendChild(progEl);
    try {
      var xhr = new XMLHttpRequest();
      await new Promise(function(resolve, reject) {
        xhr.upload.onprogress = function(e) {
          if (e.lengthComputable) {
            var pct = Math.round(e.loaded / e.total * 100);
            var bar = document.getElementById('up-prog-' + i);
            if (bar) bar.style.width = pct + '%';
          }
        };
        xhr.onload = function() { resolve(); };
        xhr.onerror = function() { reject(new Error('Ошибка сети')); };
        xhr.open('POST', '/api/subjects/' + slug + '/upload');
        xhr.withCredentials = true;
        xhr.send(fd);
      });
      progEl.remove();
      if (xhr.status === 200) {
        toast(file.name + ' загружен', 'success');
        loadSources(slug);
      } else {
        try { var err = JSON.parse(xhr.responseText); toast(err.detail || 'Ошибка', 'error'); }
        catch(e2) { toast('Ошибка загрузки', 'error'); }
      }
    } catch(e) { progEl.remove(); toast('Ошибка сети', 'error'); }
  }
}

async function srcAction(slug, srcSlug, action) {
  const labels = {index:'Индексация запущена', activate:'Источник активирован', deactivate:'Источник отключён'};
  const r = await api('/api/subjects/' + slug + '/sources/' + srcSlug + '/' + action, {method:'POST'});
  if (r.ok) { toast(labels[action] || 'Готово', 'success'); loadSources(slug); }
  else { const err = await r.json(); toast(err.detail || 'Ошибка', 'error'); }
}

async function renameSrc(slug, srcSlug, currentTitle) {
  var newTitle = prompt('Новое название:', currentTitle);
  if (!newTitle || newTitle === currentTitle) return;
  var fd = new FormData(); fd.append('title', newTitle);
  var r = await api('/api/subjects/' + slug + '/sources/' + srcSlug + '/rename', {method:'PUT', body:fd});
  if (r.ok) { toast('Переименовано', 'success'); loadSources(slug); }
  else { var err = await r.json(); toast(err.detail || 'Ошибка', 'error'); }
}

async function delSrc(slug, srcSlug) {
  if (!confirm('Удалить источник, файл и индекс с сервера?')) return;
  const r = await api('/api/subjects/' + slug + '/sources/' + srcSlug, {method:'DELETE'});
  if (r.ok) { toast('Источник удалён', 'success'); loadSources(slug); }
  else toast('Ошибка удаления', 'error');
}

// ── Reader ─────────────────────────────────────────────────────────────
async function vReader(main, slug) {
  main.innerHTML =
    '<div class="three-col" style="min-height:calc(100vh - 56px)">' +
    '<div class="reader-sidebar"><div class="reader-sidebar-inner">' +
    '<div class="toc-group-label">Содержание</div>' +
    '<div id="toc"></div>' +
    '</div></div>' +
    '<div id="rcontent" class="reader-content"><p class="text-muted">Выберите раздел слева.</p></div>' +
    '</div>';
  try {
    const r = await api('/api/subjects/' + slug + '/segments');
    const segs = await r.json();
    const toc = document.getElementById('toc');
    if (!toc || !Object.keys(segs).length) {
      if (toc) toc.innerHTML = '<p class="text-muted text-sm" style="padding:0 16px">Источников нет или индекс ещё не готов.</p>';
      return;
    }
    let html = '';
    for (const srcSlug in segs) {
      const src = segs[srcSlug];
      html += '<div class="toc-group-label">' + esc(src.title || srcSlug) + '</div>';
      (src.segments || []).forEach(function(seg) {
        html += '<div class="toc-item" data-src="' + srcSlug + '" data-seg="' + seg.index + '" onclick="loadSeg(\'' + slug + '\',\'' + srcSlug + '\',' + seg.index + ',this)">' +
          '<span class="toc-num">' + (seg.index + 1) + '</span>' +
          '<span>' + esc(seg.title) + '</span>' +
          '</div>';
      });
    }
    toc.innerHTML = html;
    // Auto-open segment from query params: ?src=SLUG&seg=N
    var qm = location.hash.indexOf('?');
    if (qm > -1) {
      var params = new URLSearchParams(location.hash.slice(qm + 1));
      var autoSrc = params.get('src');
      var autoSeg = params.get('seg');
      if (autoSrc) {
        var target = document.querySelector('.toc-item[data-src="' + autoSrc + '"][data-seg="' + (autoSeg || '0') + '"]');
        if (target) target.click();
      }
    }
  } catch(e) {
    const toc = document.getElementById('toc');
    if (toc) toc.innerHTML = '<p style="color:var(--red);padding:0 16px;font-size:.875rem">Ошибка загрузки TOC</p>';
  }
}

async function loadSeg(slug, srcSlug, segId, tocEl) {
  document.querySelectorAll('.toc-item').forEach(function(t) { t.classList.remove('active'); });
  tocEl.classList.add('active');
  const content = document.getElementById('rcontent');
  if (!content) return;
  content.innerHTML = '<div class="text-muted text-sm"><div class="spinner"></div> Загрузка…</div>';
  try {
    const r = await api('/api/subjects/' + slug + '/segments/' + srcSlug + '/' + segId);
    const seg = await r.json();
    content.innerHTML =
      '<h2 style="margin-bottom:12px">' + esc(seg.title) + '</h2>' +
      '<p class="text-muted text-sm" style="margin-bottom:20px">' + esc(seg.source_title) + ' · ' + seg.words + ' слов</p>' +
      '<div style="white-space:pre-wrap">' + esc(seg.text) + '</div>';
    renderMath(content);
  } catch(e) {
    content.innerHTML = '<p style="color:var(--red)">Ошибка загрузки сегмента</p>';
  }
}

// ── Chat ───────────────────────────────────────────────────────────────
async function vChat(main, slug) {
  S.pendingImg = null;
  S.chatConvId = 0;
  main.innerHTML =
    '<div style="display:flex;height:calc(100vh - 56px)">' +
    '<div class="conv-sidebar" id="conv-sidebar">' +
    '<div style="padding:12px 14px;border-bottom:1px solid var(--border)">' +
    '<button class="btn btn-primary btn-sm" style="width:100%" id="btn-new-conv">+ Новая беседа</button>' +
    '<input type="text" id="conv-search" placeholder="Поиск по беседам…" style="margin-top:8px;padding:6px 10px;font-size:.8125rem">' +
    '</div>' +
    '<div id="conv-list" style="flex:1;overflow-y:auto;padding:6px 0"></div>' +
    '<div style="padding:8px 14px;border-top:1px solid var(--border)">' +
    '<button class="btn btn-danger btn-sm" style="width:100%;font-size:.75rem" id="btn-del-all-conv">Удалить все беседы</button>' +
    '</div>' +
    '</div>' +
    '<div class="chat-layout" style="flex:1">' +
    '<div class="chat-messages" id="chat-msgs">' +
    '<p class="text-muted text-sm" style="text-align:center;padding:20px">Выберите беседу или начните новую</p>' +
    '</div>' +
    '<div class="chat-input-area">' +
    '<div id="img-bar" class="img-preview-bar hidden"></div>' +
    '<div class="chat-input-row">' +
    '<button class="btn btn-ghost btn-sm" id="btn-photo" title="Прикрепить фото конспекта" style="flex-shrink:0">📷</button>' +
    '<input type="file" id="photo-inp" accept="image/*" style="display:none">' +
    '<textarea id="chat-inp" placeholder="Задайте вопрос по материалам…" rows="1"></textarea>' +
    '<button class="btn btn-primary" id="btn-send" style="flex-shrink:0">↑</button>' +
    '</div>' +
    '<div class="chat-hint">' +
    '<span>Shift+Enter — отправить</span>' +
    '</div></div></div></div>';

  await loadConvList(slug);

  document.getElementById('btn-new-conv').addEventListener('click', function() {
    S.chatConvId = 0;
    document.querySelectorAll('.conv-item').forEach(function(el) { el.classList.remove('active'); });
    var msgsEl = document.getElementById('chat-msgs');
    msgsEl.innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Новая беседа · Задайте вопрос</p>';
  });

  var searchTimer = null;
  document.getElementById('conv-search').addEventListener('input', function() {
    clearTimeout(searchTimer);
    var q = this.value;
    searchTimer = setTimeout(function() { loadConvList(slug, q); }, 300);
  });

  document.getElementById('btn-del-all-conv').addEventListener('click', async function() {
    if (!confirm('Удалить все беседы по этому предмету?')) return;
    await api('/api/subjects/' + slug + '/conversations', {method:'DELETE'});
    S.chatConvId = 0;
    toast('Все беседы удалены', 'success');
    loadConvList(slug);
    document.getElementById('chat-msgs').innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Новая беседа</p>';
  });

  // Photo OCR
  document.getElementById('btn-photo').addEventListener('click', function() {
    document.getElementById('photo-inp').click();
  });
  document.getElementById('photo-inp').addEventListener('change', async function(e) {
    var file = e.target.files[0];
    if (!file) return;
    toast('Распознавание текста на фото…', 'info');
    try {
      var fd = new FormData(); fd.append('file', file);
      var r = await api('/api/subjects/' + slug + '/chat/ocr-image', {method:'POST', body:fd});
      if (r.ok) {
        var data = await r.json();
        var bar = document.getElementById('img-bar');
        bar.innerHTML = '<span class="badge badge-blue" style="font-size:.75rem">📷 OCR</span>' +
          '<span class="text-sm text-muted" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(data.text.slice(0, 80)) + '…</span>' +
          '<button class="btn btn-ghost btn-sm" style="flex-shrink:0" onclick="clearOcr()">✕</button>';
        bar.classList.remove('hidden');
        S.pendingImg = data.text;
        toast('Текст распознан', 'success');
      } else { toast('Ошибка OCR', 'error'); }
    } catch(err) { toast('Ошибка распознавания', 'error'); }
  });

  async function sendMsg() {
    var inpEl = document.getElementById('chat-inp');
    var q = inpEl.value.trim();
    if (!q && !S.pendingImg) return;
    var fullQ = S.pendingImg ? 'Содержимое конспекта:\n' + S.pendingImg + (q ? '\n\nВопрос: ' + q : '') : q;
    inpEl.value = ''; inpEl.style.height = '';
    clearOcr();

    var msgsDiv = document.getElementById('chat-msgs');
    var placeholder = msgsDiv.querySelector('.text-muted.text-sm');
    if (placeholder) msgsDiv.innerHTML = '';
    appendMsg('user', fullQ);
    msgsDiv.scrollTop = msgsDiv.scrollHeight;

    var msgEl = appendMsg('assistant', '');
    var bubble = msgEl.querySelector('.msg-bubble');
    bubble.innerHTML = '<div class="spinner"></div>';

    var full = '';
    var url = '/api/subjects/' + slug + '/chat/stream?q=' + encodeURIComponent(fullQ) + '&conversation_id=' + S.chatConvId;
    var es = new EventSource(url);
    S.chatES = es;

    es.onmessage = function(ev) {
      if (ev.data === '[DONE]') {
        es.close(); S.chatES = null;
        bubble.innerHTML = md(full);
        renderMath(bubble);
        msgsDiv.scrollTop = msgsDiv.scrollHeight;
        loadConvList(slug);
        return;
      }
      try {
        var d = JSON.parse(ev.data);
        if (d.error) { bubble.innerHTML = '<span style="color:var(--red)">' + esc(d.error) + '</span>'; es.close(); return; }
        if (d.conversation_id) { S.chatConvId = d.conversation_id; }
        if (d.content) {
          full += d.content;
          bubble.innerHTML = md(full) + '<span class="spinner" style="width:10px;height:10px;margin-left:4px"></span>';
          msgsDiv.scrollTop = msgsDiv.scrollHeight;
        }
      } catch(e2) {}
    };
    es.onerror = function() {
      es.close(); S.chatES = null;
      if (!full) bubble.innerHTML = '<span style="color:var(--red)">Ошибка соединения</span>';
    };
  }

  document.getElementById('btn-send').addEventListener('click', sendMsg);
  document.getElementById('chat-inp').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.shiftKey) { e.preventDefault(); sendMsg(); }
  });
  document.getElementById('chat-inp').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
  });
}

async function loadConvList(slug, q) {
  var el = document.getElementById('conv-list');
  if (!el) return;
  var url = '/api/subjects/' + slug + '/conversations';
  if (q) url += '?q=' + encodeURIComponent(q);
  try {
    var r = await api(url);
    var convs = await r.json();
    if (!convs.length) {
      el.innerHTML = '<p class="text-muted text-sm" style="padding:12px 14px">Бесед пока нет</p>';
      return;
    }
    el.innerHTML = convs.map(function(c) {
      var active = c.id === S.chatConvId ? ' active' : '';
      var dt = c.updated_at ? c.updated_at.slice(0, 10) : '';
      return '<div class="conv-item' + active + '" data-id="' + c.id + '" onclick="openConv(\'' + slug + '\',' + c.id + ')">' +
        '<div class="conv-title">' + esc(c.title) + '</div>' +
        '<div class="conv-date">' + dt + '</div>' +
        '<button class="conv-del" onclick="event.stopPropagation();delConv(\'' + slug + '\',' + c.id + ')" title="Удалить">✕</button>' +
        '</div>';
    }).join('');
  } catch(e) {}
}

async function openConv(slug, cid) {
  S.chatConvId = cid;
  document.querySelectorAll('.conv-item').forEach(function(el) {
    el.classList.toggle('active', Number(el.dataset.id) === cid);
  });
  var msgsEl = document.getElementById('chat-msgs');
  msgsEl.innerHTML = '<div class="text-muted text-sm" style="text-align:center;padding:20px"><div class="spinner"></div></div>';
  try {
    var r = await api('/api/subjects/' + slug + '/chat/history?conversation_id=' + cid);
    var hist = await r.json();
    msgsEl.innerHTML = '';
    if (!hist.length) {
      msgsEl.innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Пустая беседа</p>';
    } else {
      hist.forEach(function(m) { appendMsg(m.role, m.content); });
      msgsEl.scrollTop = msgsEl.scrollHeight;
    }
  } catch(e) { msgsEl.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>'; }
}

async function delConv(slug, cid) {
  if (!confirm('Удалить беседу?')) return;
  await api('/api/subjects/' + slug + '/conversations/' + cid, {method:'DELETE'});
  if (S.chatConvId === cid) {
    S.chatConvId = 0;
    document.getElementById('chat-msgs').innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Выберите беседу</p>';
  }
  toast('Беседа удалена', 'success');
  loadConvList(slug);
}

function clearOcr() {
  S.pendingImg = null;
  const bar = document.getElementById('img-bar');
  if (bar) bar.classList.add('hidden');
  const inp = document.getElementById('chat-inp');
  if (inp) inp.placeholder = 'Задайте вопрос по материалам…';
}

function appendMsg(role, content) {
  const msgsEl = document.getElementById('chat-msgs');
  const div = document.createElement('div');
  div.className = 'msg msg-' + role;
  div.innerHTML =
    '<div class="msg-avatar">' + (role === 'user' ? '👤' : '🔬') + '</div>' +
    '<div class="msg-bubble">' + (content ? md(content) : '') + '</div>';
  msgsEl.appendChild(div);
  if (content) renderMath(div.querySelector('.msg-bubble'));
  return div;
}

// ── Tickets ────────────────────────────────────────────────────────────
async function vTickets(main, slug) {
  let subject = {title: slug};
  try { const r = await api('/api/subjects/' + slug); subject = await r.json(); } catch(e) {}
  main.innerHTML =
    '<div class="page">' +
    '<div class="section-header">' +
    '<h1 class="section-title">Билеты: ' + esc(subject.title) + '</h1>' +
    '<a href="/api/subjects/' + slug + '/tickets/export" class="btn btn-ghost btn-sm" target="_blank">⬇ Экспорт</a>' +
    '</div>' +
    '<div style="display:flex;gap:10px;margin-bottom:16px">' +
    '<input type="text" id="new-q" placeholder="Новый вопрос для билета… (Enter)">' +
    '<button class="btn btn-primary btn-sm" style="flex-shrink:0" id="btn-add-t">+ Добавить</button>' +
    '<button class="btn btn-ghost btn-sm" style="flex-shrink:0" id="btn-batch-t">📋 Пакетная загрузка</button>' +
    '</div>' +
    '<div id="t-list"><div class="text-muted text-sm"><div class="spinner"></div></div></div>' +
    '</div>';

  async function addTicket() {
    const q = document.getElementById('new-q').value.trim();
    if (!q) return;
    const fd = new FormData();
    fd.append('question', q);
    const r = await api('/api/subjects/' + slug + '/tickets', {method:'POST', body:fd});
    if (r.ok) { document.getElementById('new-q').value = ''; toast('Билет добавлен', 'success'); loadTickets(slug); }
    else toast('Ошибка', 'error');
  }

  document.getElementById('btn-add-t').addEventListener('click', addTicket);
  document.getElementById('new-q').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') addTicket();
  });
  document.getElementById('btn-batch-t').addEventListener('click', function() {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML =
      '<div class="glass modal" style="max-width:560px">' +
      '<div class="modal-title">Пакетная загрузка вопросов</div>' +
      '<p class="text-sm text-muted" style="margin-bottom:12px">Один вопрос на строку. Нумерация (1. 2. 3.) удаляется автоматически.</p>' +
      '<form id="batch-form">' +
      '<div class="form-group"><textarea id="batch-q" rows="10" placeholder="1. Первый закон термодинамики\n2. Закон Гесса\n3. Энтропия как функция состояния" style="font-size:.875rem"></textarea></div>' +
      '<div class="flex gap" style="margin-top:4px">' +
      '<button type="button" class="btn btn-ghost" id="batch-cancel">Отмена</button>' +
      '<button type="submit" class="btn btn-primary">Загрузить</button>' +
      '</div></form></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
    document.getElementById('batch-cancel').addEventListener('click', function() { ov.remove(); });
    document.getElementById('batch-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var fd = new FormData();
      fd.append('questions', document.getElementById('batch-q').value);
      var r = await api('/api/subjects/' + slug + '/tickets/batch', {method:'POST', body:fd});
      if (r.ok) {
        var data = await r.json();
        toast(data.count + ' вопросов загружено', 'success');
        ov.remove();
        loadTickets(slug);
      } else {
        var err = await r.json();
        toast(err.detail || 'Ошибка', 'error');
      }
    });
    setTimeout(function() { document.getElementById('batch-q').focus(); }, 50);
  });
  await loadTickets(slug);
}

async function loadTickets(slug) {
  const el = document.getElementById('t-list');
  if (!el) return;
  try {
    const r = await api('/api/subjects/' + slug + '/tickets');
    const tickets = await r.json();
    if (!tickets.length) {
      el.innerHTML = '<p class="text-muted text-sm">Билетов пока нет. Добавьте вопросы выше.</p>';
      return;
    }
    el.innerHTML = tickets.map(function(t) {
      var hasAnswer = t.answer && t.answer.length > 0;
      return '<div class="glass ticket-item" id="tk-' + t.id + '">' +
        '<div style="display:flex;align-items:flex-start;gap:10px">' +
        (hasAnswer ? '<button class="btn btn-ghost btn-sm toggle-answer" onclick="toggleAnswer(this)" style="flex-shrink:0;padding:4px 8px;font-size:1rem" title="Развернуть/свернуть">▶</button>' : '') +
        '<div class="ticket-q" style="flex:1">' + esc(t.question) + '</div>' +
        '<div class="flex gap" style="flex-shrink:0">' +
        '<button class="btn btn-primary btn-sm" onclick="genTicket(\'' + slug + '\',' + t.id + ')">' +
        (t.status === 'generated' ? '🔄' : '⚡') + ' Ответить</button>' +
        (hasAnswer ? '<a href="/api/subjects/' + slug + '/tickets/' + t.id + '/export" class="btn btn-ghost btn-sm" target="_blank" title="Скачать HTML">📄</a>' : '') +
        '<button class="btn btn-danger btn-sm" onclick="delTicket(\'' + slug + '\',' + t.id + ')">✕</button>' +
        '</div></div>' +
        (hasAnswer ? '<div class="ticket-answer" style="display:none">' + md(t.answer) + '</div>' : '') +
        '</div>';
    }).join('');
    renderMath(el);
  } catch(e) { el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>'; }
}

function toggleAnswer(btn) {
  var ticket = btn.closest('.ticket-item');
  var answer = ticket.querySelector('.ticket-answer');
  if (!answer) return;
  var hidden = answer.style.display === 'none';
  answer.style.display = hidden ? '' : 'none';
  btn.textContent = hidden ? '▼' : '▶';
  if (hidden) renderMath(answer);
}

async function genTicket(slug, tid) {
  const ticketEl = document.getElementById('tk-' + tid);
  if (!ticketEl) return;
  let ansEl = ticketEl.querySelector('.ticket-answer');
  if (!ansEl) {
    ansEl = document.createElement('div');
    ansEl.className = 'ticket-answer';
    ticketEl.appendChild(ansEl);
  }
  ansEl.innerHTML = '<div class="spinner"></div> Генерация ответа…';
  let full = '';
  const es = new EventSource('/api/subjects/' + slug + '/tickets/' + tid + '/generate');
  es.onmessage = function(ev) {
    if (ev.data === '[DONE]') { es.close(); loadTickets(slug); return; }
    try {
      const d = JSON.parse(ev.data);
      if (d.error) { ansEl.innerHTML = '<span style="color:var(--red)">' + esc(d.error) + '</span>'; es.close(); return; }
      if (d.content) {
        full += d.content;
        ansEl.innerHTML = md(full) + '<span class="spinner" style="width:10px;height:10px;margin-left:4px"></span>';
      }
    } catch(e2) {}
  };
  es.onerror = function() { es.close(); if (!full) ansEl.innerHTML = '<span style="color:var(--red)">Ошибка генерации</span>'; };
}

async function delTicket(slug, tid) {
  if (!confirm('Удалить билет?')) return;
  const r = await api('/api/subjects/' + slug + '/tickets/' + tid, {method:'DELETE'});
  if (r.ok) { toast('Билет удалён', 'success'); loadTickets(slug); }
  else toast('Ошибка удаления', 'error');
}

// ── Init ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async function() {
  try {
    const r = await fetch('/api/me', {credentials:'include'});
    if (r.ok) S.user = await r.json();
  } catch(e) {}
  window.addEventListener('hashchange', route);
  route();
});
</script>
</body>
</html>"""


if __name__ == "__main__":
    uvicorn.run("studylab:app", host="0.0.0.0", port=8201, reload=False)
