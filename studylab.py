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
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
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
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_slug TEXT NOT NULL,
            source_slug TEXT NOT NULL,
            segment INTEGER DEFAULT 0,
            path TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            width INTEGER DEFAULT 0,
            height INTEGER DEFAULT 0,
            kind TEXT DEFAULT 'other',
            caption TEXT DEFAULT '',
            latex TEXT DEFAULT '',
            figure_label TEXT DEFAULT '',
            context TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            hidden INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
    """)
    # Safe migrations: add columns that may not exist in older DBs
    for migration in [
        "ALTER TABLE chat_history ADD COLUMN conversation_id INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE subjects ADD COLUMN year INTEGER DEFAULT 0",
        "ALTER TABLE subjects ADD COLUMN semester INTEGER DEFAULT 0",
        "ALTER TABLE subjects ADD COLUMN exam_date TEXT DEFAULT ''",
        "ALTER TABLE exam_tickets ADD COLUMN position INTEGER DEFAULT 0",
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


_INDEX_TASKS: dict[str, asyncio.Task] = {}  # key = "subject/src_slug"


@app.on_event("startup")
async def on_startup():
    init_db()
    # Re-queue sources stuck in indexing/uploaded after restart
    db = get_db()
    stuck = db.execute(
        "SELECT subject_slug, slug, filename, title, status FROM sources "
        "WHERE status LIKE 'indexing:%' OR status = 'uploaded'"
    ).fetchall()
    # Re-queue image description for active sources with pending images
    pending_imgs = db.execute(
        "SELECT DISTINCT subject_slug, source_slug FROM images WHERE status='pending'"
    ).fetchall()
    db.close()
    for row in stuck:
        key = f"{row['subject_slug']}/{row['slug']}"
        upload_path = subject_dir(row["subject_slug"]) / "uploads" / row["filename"]
        if upload_path.exists():
            task = asyncio.create_task(_index_source(
                row["subject_slug"], row["slug"], upload_path, row["title"]))
            _INDEX_TASKS[key] = task
            print(f"[startup] re-queued: {key}", flush=True)
        else:
            db2 = get_db()
            db2.execute("UPDATE sources SET status='error' WHERE subject_slug=? AND slug=?",
                        (row["subject_slug"], row["slug"]))
            db2.commit()
            db2.close()
            print(f"[startup] file missing, set error: {key}", flush=True)
    for row in pending_imgs:
        asyncio.create_task(_extract_and_describe_images(row["subject_slug"], row["source_slug"]))
        print(f"[startup] re-queued image description: {row['subject_slug']}/{row['source_slug']}", flush=True)


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

_INDEX_SEM = asyncio.Semaphore(2)
_IMAGE_SEM = asyncio.Semaphore(1)
MAX_IMAGES_PER_SOURCE = 150
MIN_IMAGE_FILE_KB = 8
MIN_IMAGE_SHORT_SIDE = 120
MAX_IMAGE_LONG_SIDE = 1600
LOGO_PAGE_RATIO = 0.30  # images on 30%+ pages are logos/headers

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
    async with _INDEX_SEM:
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
                "UPDATE sources SET status='active', chunk_count=? WHERE subject_slug=? AND slug=?",
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
            _INDEX_TASKS.pop(f"{subject_slug}/{source_slug}", None)

    # If indexing succeeded, launch image extraction + description in background
    # We check status after the block above
    _check_db = get_db()
    _src_row = _check_db.execute(
        "SELECT status FROM sources WHERE subject_slug=? AND slug=?",
        (subject_slug, source_slug)
    ).fetchone()
    _check_db.close()
    if _src_row and _src_row["status"] == "active":
        asyncio.create_task(_extract_and_describe_images(subject_slug, source_slug))


def _extract_images_from_media(subject_slug: str, source_slug: str,
                                md_dir: Path, full_text: str) -> int:
    """Extract images from media/ dir, filter junk, store in images table.
    Returns count of inserted images."""
    import fitz  # PyMuPDF

    media_dir = md_dir / source_slug / "media"
    if not media_dir.exists():
        return 0

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()

    # Gather all existing sha1s in the subject (for dedup)
    existing_sha1s: set[str] = {
        r["sha1"] for r in db.execute(
            "SELECT sha1 FROM images WHERE subject_slug=?", (subject_slug,)
        ).fetchall()
    }

    # Count page occurrences of each sha1 in the markdown text
    # Images referenced as ![](media/page{N}_img{M}.png)
    all_refs = re.findall(r"!\[\]\(media/([^)]+)\)", full_text)
    total_pages = max(1, len(set(
        re.match(r"page(\d+)_", r).group(1)
        for r in all_refs if re.match(r"page(\d+)_", r)
    )))
    # sha1 → count of pages it appears on
    sha1_page_counts: dict[str, set[str]] = {}

    image_files = sorted(media_dir.glob("*.*"))
    # First pass: compute sha1s
    file_sha1: dict[Path, str] = {}
    for img_path in image_files:
        try:
            data = img_path.read_bytes()
            file_sha1[img_path] = hashlib.sha1(data).hexdigest()
        except Exception:
            pass

    # Count page occurrences per sha1
    for img_path, sha1 in file_sha1.items():
        m = re.match(r"page(\d+)_", img_path.name)
        if m:
            page_num = m.group(1)
            sha1_page_counts.setdefault(sha1, set()).add(page_num)

    inserted = 0
    seen_sha1_this_source: set[str] = set()

    for img_path in image_files:
        if img_path not in file_sha1:
            continue
        sha1 = file_sha1[img_path]
        data = img_path.read_bytes()

        # Filter 1: file size < 8KB
        if len(data) < MIN_IMAGE_FILE_KB * 1024:
            continue

        # Filter 2: dimensions via fitz
        try:
            pix = fitz.Pixmap(data)
            w, h = pix.width, pix.height
        except Exception:
            continue

        short_side = min(w, h)
        if short_side < MIN_IMAGE_SHORT_SIDE:
            continue

        # Filter 3: duplicate sha1 within subject
        if sha1 in existing_sha1s:
            continue
        if sha1 in seen_sha1_this_source:
            continue

        # Filter 4: logo/header heuristic (appears on 30%+ pages)
        pages_with_img = len(sha1_page_counts.get(sha1, set()))
        if total_pages > 1 and pages_with_img / total_pages >= LOGO_PAGE_RATIO:
            continue

        # Normalize: max 1600px long side
        long_side = max(w, h)
        if long_side > MAX_IMAGE_LONG_SIDE:
            scale = MAX_IMAGE_LONG_SIDE / long_side
            new_w = int(w * scale)
            new_h = int(h * scale)
            try:
                mat = fitz.Matrix(scale, scale)
                pix2 = pix.set_dpi(72, 72)
                # Use Pixmap resize via transformation
                pix2 = fitz.Pixmap(pix, 0) if pix.alpha else pix
                # fitz doesn't have direct resize — use samples manipulation
                # Save as PNG, reload scaled via PDF page approach
                # Since fitz.Pixmap doesn't have .resize(), we save and re-read
                # to avoid Pillow dependency; just save as-is if too large is the fallback
                pix2 = pix
            except Exception:
                pix2 = pix
        else:
            pix2 = pix
            new_w, new_h = w, h

        # Save as PNG in normalized path
        norm_filename = f"img_{sha1[:12]}.png"
        norm_path = media_dir / norm_filename
        try:
            if pix2.colorspace and pix2.colorspace.n > 3:
                pix2 = fitz.Pixmap(fitz.csRGB, pix2)
            elif pix2.alpha:
                pix2 = fitz.Pixmap(fitz.csRGB, pix2)
            pix2.save(str(norm_path))
        except Exception as ex:
            print(f"[images] save failed {img_path.name}: {ex}", flush=True)
            continue

        # Determine segment by finding where this image is referenced in text
        img_ref = f"![](media/{img_path.name})"
        ref_pos = full_text.find(img_ref)
        segment_idx = 0
        if ref_pos >= 0:
            # Find which segment contains this position (approximate)
            seg_path = subject_dir(subject_slug) / "segments.json"
            if seg_path.exists():
                try:
                    all_segs = json.loads(seg_path.read_text(encoding="utf-8"))
                    src_segs = all_segs.get(source_slug, {}).get("segments", [])
                    for seg in src_segs:
                        if seg.get("start_char", 0) <= ref_pos <= seg.get("end_char", 0):
                            segment_idx = seg.get("index", 0)
                            break
                except Exception:
                    pass

        # Extract figure label from neighboring text
        figure_label = ""
        if ref_pos >= 0:
            window_start = max(0, ref_pos - 400)
            window_end = min(len(full_text), ref_pos + 400)
            window = full_text[window_start:window_end]
            fig_m = re.search(r"(?:Рис\.?\s*\d+[\.\d]*|Рисунок\s+\d+[\.\d]*|Fig\.?\s*\d+[\.\d]*)[^\n]*", window)
            if fig_m:
                figure_label = fig_m.group(0).strip()[:120]

        # Extract context: nearest paragraph up to 300 chars before the image ref
        context = ""
        if ref_pos >= 0:
            before = full_text[max(0, ref_pos - 600):ref_pos]
            paras = [p.strip() for p in re.split(r"\n\n+", before) if p.strip()]
            if paras:
                ctx_raw = paras[-1]
                # Strip markdown image refs
                ctx_raw = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", ctx_raw).strip()
                context = ctx_raw[:300]

        rel_path = str(norm_path.relative_to(subject_dir(subject_slug)))

        db.execute(
            "INSERT INTO images (subject_slug,source_slug,segment,path,sha1,"
            "width,height,kind,caption,latex,figure_label,context,status,hidden,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (subject_slug, source_slug, segment_idx, rel_path, sha1,
             new_w if long_side > MAX_IMAGE_LONG_SIDE else w,
             new_h if long_side > MAX_IMAGE_LONG_SIDE else h,
             "other", "", "", figure_label, context, "pending", 0, now)
        )
        seen_sha1_this_source.add(sha1)
        existing_sha1s.add(sha1)
        inserted += 1

    db.commit()
    db.close()
    return inserted


async def _extract_and_describe_images(subject_slug: str, source_slug: str):
    """Post-indexing background task: extract images, then describe them with vision model."""
    async with _IMAGE_SEM:
        # Step 1: extract images from media dir
        def _do_extract():
            subj_dir = subject_dir(subject_slug)
            md_dir = subj_dir / "md"
            if not MKLIB_OK:
                return 0
            full_text = mk_read_text(md_dir, source_slug)
            if not full_text:
                return 0
            return _extract_images_from_media(subject_slug, source_slug, md_dir, full_text)

        try:
            n_extracted = await asyncio.to_thread(_do_extract)
            print(f"[images] extracted {n_extracted} images for {subject_slug}/{source_slug}", flush=True)
        except Exception as e:
            print(f"[images] extraction error {subject_slug}/{source_slug}: {e}", flush=True)
            return

        if not TIMEWEB_API_KEY:
            print("[images] TIMEWEB_API_KEY not set, skipping vision description", flush=True)
            return

        # Step 2: describe with vision model
        db = get_db()
        pending = db.execute(
            "SELECT * FROM images WHERE subject_slug=? AND source_slug=? AND status='pending' LIMIT ?",
            (subject_slug, source_slug, MAX_IMAGES_PER_SOURCE)
        ).fetchall()
        db.close()

        total = len(pending)
        print(f"[images] describing {total} images for {subject_slug}/{source_slug}", flush=True)

        for idx, img_row in enumerate(pending):
            img_id = img_row["id"]
            img_sha1 = img_row["sha1"]

            # Check sha1 cache: if same image already described elsewhere
            cache_db = get_db()
            cached = cache_db.execute(
                "SELECT kind,caption,latex FROM images WHERE sha1=? AND status='described' LIMIT 1",
                (img_sha1,)
            ).fetchone()
            cache_db.close()

            if cached:
                upd_db = get_db()
                upd_db.execute(
                    "UPDATE images SET kind=?,caption=?,latex=?,status='described' WHERE id=?",
                    (cached["kind"], cached["caption"], cached["latex"], img_id)
                )
                upd_db.commit()
                upd_db.close()
                continue

            # Load image file
            img_full_path = subject_dir(subject_slug) / img_row["path"]
            if not img_full_path.exists():
                err_db = get_db()
                err_db.execute("UPDATE images SET status='error' WHERE id=?", (img_id,))
                err_db.commit()
                err_db.close()
                continue

            try:
                import base64 as _b64_local
                img_data = img_full_path.read_bytes()
                img_b64 = _b64_local.b64encode(img_data).decode()
            except Exception as e:
                print(f"[images] read error img {img_id}: {e}", flush=True)
                continue

            vision_prompt = (
                "Это иллюстрация из учебника. Определи тип: scheme/formula/table/photo/chart/other. "
                "Для формулы напиши LaTeX. Для остальных — описание на русском (1-2 предложения). "
                "Для декоративных — ответь SKIP. "
                "Формат: TYPE|DESCRIPTION|LATEX"
            )
            messages = [{"role": "user", "content": [
                {"type": "text", "text": vision_prompt},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img_b64}"}}
            ]}]

            # Try up to 2 times
            success = False
            for attempt in range(2):
                try:
                    async with _httpx.AsyncClient(timeout=60) as client:
                        resp = await client.post(
                            TIMEWEB_URL,
                            headers={"Authorization": f"Bearer {TIMEWEB_API_KEY}"},
                            json={"model": VISION_MODEL, "messages": messages,
                                  "stream": False, "max_tokens": 512, "temperature": 0.1}
                        )
                        resp.raise_for_status()
                        raw = resp.json()["choices"][0]["message"]["content"].strip()

                    if raw.upper().startswith("SKIP"):
                        upd_db = get_db()
                        upd_db.execute("UPDATE images SET status='skipped' WHERE id=?", (img_id,))
                        upd_db.commit()
                        upd_db.close()
                        success = True
                        break

                    parts = raw.split("|", 2)
                    kind = parts[0].strip().lower() if len(parts) > 0 else "other"
                    caption = parts[1].strip() if len(parts) > 1 else raw
                    latex = parts[2].strip() if len(parts) > 2 else ""

                    valid_kinds = {"scheme", "formula", "table", "photo", "chart", "other"}
                    if kind not in valid_kinds:
                        kind = "other"

                    upd_db = get_db()
                    upd_db.execute(
                        "UPDATE images SET kind=?,caption=?,latex=?,status='described' WHERE id=?",
                        (kind, caption, latex, img_id)
                    )
                    upd_db.commit()
                    upd_db.close()
                    success = True
                    break

                except Exception as e:
                    print(f"[images] vision error img {img_id} attempt {attempt+1}: {e}", flush=True)
                    if attempt == 0:
                        await asyncio.sleep(2)

            if not success:
                err_db = get_db()
                err_db.execute("UPDATE images SET status='error' WHERE id=?", (img_id,))
                err_db.commit()
                err_db.close()

        # Step 3: create vector index chunks for described images
        db = get_db()
        described = db.execute(
            "SELECT * FROM images WHERE subject_slug=? AND source_slug=? AND status='described' AND hidden=0",
            (subject_slug, source_slug)
        ).fetchall()
        db.close()

        if described and MKLIB_OK:
            def _index_images():
                subj_dir = subject_dir(subject_slug)
                db_path = subj_dir / "index.db"
                vec_db = mk_open_db(db_path)
                mk_init_db(vec_db, "chunks")
                records, payloads = [], []
                for img_row in described:
                    text_parts = [p for p in [img_row["caption"], img_row["figure_label"], img_row["context"]] if p]
                    if not text_parts:
                        continue
                    chunk_text = ". ".join(text_parts)
                    cid = "img_" + hashlib.sha1(
                        f"{subject_slug}|{source_slug}|img|{img_row['id']}".encode()
                    ).hexdigest()[:16]
                    records.append({
                        "chunk_id": cid, "slug": source_slug,
                        "topic": subject_slug, "priority": 1,
                        "segment": img_row["segment"], "title": img_row["figure_label"] or "Иллюстрация",
                        "text": chunk_text,
                        "meta": {"type": "image", "image_id": img_row["id"]},
                    })
                    payloads.append(chunk_text)
                if records:
                    vecs = embed_texts(payloads)
                    for rec, vec in zip(records, vecs):
                        rec["embedding"] = vec
                    db_upsert(vec_db, "chunks", records)
                vec_db.close()
                return len(records)

            try:
                n_indexed = await asyncio.to_thread(_index_images)
                print(f"[images] indexed {n_indexed} image chunks for {subject_slug}/{source_slug}", flush=True)
            except Exception as e:
                print(f"[images] index error {subject_slug}/{source_slug}: {e}", flush=True)


import math as _math

@app.post("/api/subjects")
async def create_subject(title: str = Form(), description: str = Form(default=""),
                          year: int = Form(default=0),
                          semester: int = Form(default=0),
                          exam_date: str = Form(default=""),
                          user: dict = Depends(current_user)):
    slug = _slug(title)
    if not slug:
        raise HTTPException(400, "Некорректное название")
    subject_dir(slug)
    # Auto-compute year from semester
    if semester > 0:
        year = _math.ceil(semester / 2)
    db = get_db()
    try:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO subjects (slug,title,description,year,semester,exam_date,created_at,created_by) VALUES (?,?,?,?,?,?,?,?)",
            (slug, title, description, year, semester, exam_date.strip(), now, int(user["sub"]))
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"Предмет '{slug}' уже существует")
    finally:
        db.close()
    return {"ok": True, "slug": slug}


@app.put("/api/subjects/{slug}")
async def update_subject(slug: str,
                          title: str = Form(default=""),
                          semester: int = Form(default=-1),
                          exam_date: str = Form(default="__unchanged__"),
                          description: str = Form(default="__unchanged__"),
                          user: dict = Depends(current_user)):
    db = get_db()
    row = db.execute("SELECT * FROM subjects WHERE slug=?", (slug,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Предмет не найден")
    new_title = title.strip() if title.strip() else row["title"]
    new_semester = semester if semester >= 0 else (row["semester"] or 0)
    new_year = _math.ceil(new_semester / 2) if new_semester > 0 else (row["year"] or 0)
    new_exam_date = exam_date if exam_date != "__unchanged__" else (row["exam_date"] or "")
    new_description = description if description != "__unchanged__" else (row["description"] or "")
    db.execute(
        "UPDATE subjects SET title=?,semester=?,year=?,exam_date=?,description=? WHERE slug=?",
        (new_title, new_semester, new_year, new_exam_date.strip(), new_description, slug)
    )
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/api/subjects")
async def list_subjects(user: dict = Depends(current_user)):
    db = get_db()
    subjects = [dict(r) for r in db.execute(
        "SELECT slug,title,description,year,semester,exam_date,created_at FROM subjects ORDER BY created_at DESC"
    ).fetchall()]
    for s in subjects:
        rows = db.execute(
            "SELECT status, chunk_count FROM sources WHERE subject_slug=?", (s["slug"],)
        ).fetchall()
        s["source_count"] = len(rows)
        s["active_count"] = sum(1 for r in rows if r["status"] == "active")
        s["total_chunks"] = sum(r["chunk_count"] for r in rows if r["status"] == "active")
        # ticket stats
        ticket_rows = db.execute(
            "SELECT status FROM exam_tickets WHERE subject_slug=?", (s["slug"],)
        ).fetchall()
        s["ticket_count"] = len(ticket_rows)
        s["answered_count"] = sum(1 for t in ticket_rows if t["status"] == "generated")
        # normalize nulls
        s["semester"] = s.get("semester") or 0
        s["exam_date"] = s.get("exam_date") or ""
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

    # Auto-start indexing in background (goes through semaphore queue)
    key = f"{slug}/{src_slug}"
    task = asyncio.create_task(_index_source(slug, src_slug, upload_path, src_title))
    _INDEX_TASKS[key] = task

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
async def index_source(slug: str, src_slug: str, user: dict = Depends(current_user)):
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
    key = f"{slug}/{src_slug}"
    task = asyncio.create_task(_index_source(slug, src_slug, upload_path, row["title"]))
    _INDEX_TASKS[key] = task
    return {"ok": True, "message": "Индексация запущена"}


@app.put("/api/subjects/{slug}/sources/{src_slug}/rename")
async def rename_source(slug: str, src_slug: str, title: str = Form(),
                         user: dict = Depends(current_user)):
    db = get_db()
    db.execute("UPDATE sources SET title=? WHERE subject_slug=? AND slug=?",
               (title.strip(), slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.post("/api/subjects/{slug}/sources/{src_slug}/activate")
async def activate_source(slug: str, src_slug: str, user: dict = Depends(current_user)):
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
async def deactivate_source(slug: str, src_slug: str, user: dict = Depends(current_user)):
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
async def delete_source(slug: str, src_slug: str, user: dict = Depends(current_user)):
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
        "SELECT * FROM exam_tickets WHERE subject_slug=? ORDER BY COALESCE(position,0), id", (slug,)
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
    max_pos = db.execute(
        "SELECT COALESCE(MAX(position),0) FROM exam_tickets WHERE subject_slug=?", (slug,)
    ).fetchone()[0]
    cur = db.execute(
        "INSERT INTO exam_tickets (subject_slug,question,status,created_at,position) VALUES (?,?,'pending',?,?)",
        (slug, question.strip(), now, max_pos + 1)
    )
    ticket_id = cur.lastrowid
    db.commit()
    db.close()
    return {"ok": True, "id": ticket_id}


def _parse_ticket_lines(text: str) -> list[str]:
    """Parse raw text into a list of clean question strings.

    Handles numbering prefixes: '1.', '1)', '- ', 'Билет 1.', 'Вопрос 1:', '№1', '№ 1'.
    Merges continuation lines (next line doesn't start with a numbering prefix).
    """
    NUMBER_RE = re.compile(
        r"^(?:"
        r"(?:Билет\s+\d+[.):]\s*)"    # Билет 1.
        r"|(?:Вопрос\s+\d+[.:)]\s*)"  # Вопрос 1:
        r"|(?:№\s*\d+[.):]*\s*)"       # №1 or № 1
        r"|(?:\d+[.)]\s+)"             # 1. or 1)
        r"|(?:[-*]\s+)"                # - or *
        r")",
        re.IGNORECASE
    )

    raw_lines = text.splitlines()
    paragraphs: list[str] = []
    current: str | None = None

    for raw in raw_lines:
        line = raw.strip()
        if not line:
            continue
        if NUMBER_RE.match(line):
            if current is not None:
                paragraphs.append(current)
            # Strip the prefix
            current = NUMBER_RE.sub("", line).strip()
        else:
            # Continuation line
            if current is not None:
                current = current + " " + line
            else:
                # No prefix encountered yet — treat as a plain question
                current = line

    if current is not None:
        paragraphs.append(current)

    return [p for p in paragraphs if p]


@app.post("/api/subjects/{slug}/tickets/batch")
async def batch_create_tickets(slug: str, questions: str = Form(),
                                user: dict = Depends(current_user)):
    """Пакетная загрузка вопросов с умным парсингом, дедупликацией и позициями."""
    db = get_db()
    if not db.execute("SELECT id FROM subjects WHERE slug=?", (slug,)).fetchone():
        db.close()
        raise HTTPException(404, "Предмет не найден")

    parsed = _parse_ticket_lines(questions)
    if not parsed:
        db.close()
        raise HTTPException(400, "Список вопросов пуст")

    # Load existing questions for dedup (case-insensitive)
    existing = {
        row[0].strip().lower()
        for row in db.execute(
            "SELECT question FROM exam_tickets WHERE subject_slug=?", (slug,)
        ).fetchall()
    }

    # Get max position
    max_pos = db.execute(
        "SELECT COALESCE(MAX(position),0) FROM exam_tickets WHERE subject_slug=?", (slug,)
    ).fetchone()[0]

    now = datetime.now(timezone.utc).isoformat()
    ids: list[int] = []
    skipped = 0
    seen_in_batch: set[str] = set()

    for q in parsed:
        key = q.strip().lower()
        if key in existing or key in seen_in_batch:
            skipped += 1
            continue
        seen_in_batch.add(key)
        max_pos += 1
        cur = db.execute(
            "INSERT INTO exam_tickets (subject_slug,question,status,created_at,position) VALUES (?,?,'pending',?,?)",
            (slug, q.strip(), now, max_pos)
        )
        ids.append(cur.lastrowid)

    db.commit()
    db.close()
    return {"ok": True, "count": len(ids), "skipped": skipped, "ids": ids}


@app.post("/api/subjects/{slug}/tickets/import")
async def import_tickets_preview(slug: str, file: UploadFile = File(),
                                  user: dict = Depends(current_user)):
    """Парсит файл со списком вопросов и возвращает список для предпросмотра (ничего не сохраняет)."""
    db = get_db()
    if not db.execute("SELECT id FROM subjects WHERE slug=?", (slug,)).fetchone():
        db.close()
        raise HTTPException(404, "Предмет не найден")
    db.close()

    filename = (file.filename or "").lower()
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""

    if ext == "heic":
        raise HTTPException(400, "Фото в формате HEIC не поддерживается, выберите другое")
    if ext in ("xlsx", "xls"):
        raise HTTPException(400, "Формат XLSX пока не поддерживается")

    content = await file.read()

    raw_text = ""

    if ext in ("txt", "md"):
        try:
            raw_text = content.decode("utf-8", errors="replace")
        except Exception as e:
            raise HTTPException(400, f"Ошибка чтения файла: {e}")

    elif ext == "pdf":
        try:
            import fitz  # PyMuPDF
            import io
            doc = fitz.open(stream=io.BytesIO(content), filetype="pdf")
            parts = []
            for page in doc:
                parts.append(page.get_text())
            raw_text = "\n".join(parts)
        except ImportError:
            raise HTTPException(503, "PyMuPDF не установлен")
        except Exception as e:
            raise HTTPException(400, f"Ошибка чтения PDF: {e}")

    elif ext in ("docx", "doc"):
        try:
            import subprocess
            import tempfile
            import os as _os
            with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                result = subprocess.run(
                    ["pandoc", "--to", "plain", tmp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    raw_text = result.stdout
                else:
                    raise RuntimeError(result.stderr)
            finally:
                _os.unlink(tmp_path)
        except FileNotFoundError:
            # pandoc not available — try python-docx via mklib convert
            try:
                import tempfile
                import os as _os
                with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                if MKLIB_OK:
                    md_tmp = Path(tempfile.mkdtemp())
                    try:
                        mk_convert(Path(tmp_path), "import_tmp", md_tmp, with_images=False)
                        md_file = md_tmp / "import_tmp.md"
                        if md_file.exists():
                            raw_text = md_file.read_text(encoding="utf-8")
                        else:
                            for f2 in md_tmp.rglob("*.md"):
                                raw_text = f2.read_text(encoding="utf-8")
                                break
                    finally:
                        shutil.rmtree(md_tmp, ignore_errors=True)
                        _os.unlink(tmp_path)
                else:
                    _os.unlink(tmp_path)
                    raise HTTPException(503, "Конвертация DOCX недоступна — установите pandoc")
            except HTTPException:
                raise
            except Exception as e2:
                raise HTTPException(400, f"Ошибка чтения DOCX: {e2}")
        except Exception as e:
            raise HTTPException(400, f"Ошибка обработки файла: {e}")

    elif ext in ("jpg", "jpeg", "png", "webp", "gif", "bmp"):
        if not TIMEWEB_API_KEY:
            raise HTTPException(503, "TIMEWEB_API_KEY не задан — OCR недоступен")
        b64 = _b64.b64encode(content).decode()
        messages = [{"role": "user", "content": [
            {"type": "text",
             "text": (
                 "На этом изображении — список экзаменационных вопросов или билетов. "
                 "Распознай все вопросы и выведи их нумерованным списком, по одному на строку. "
                 "Формат: '1. Текст вопроса'. Только список, без пояснений."
             )},
            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}
        ]}]
        try:
            async with _httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    TIMEWEB_URL,
                    headers={"Authorization": f"Bearer {TIMEWEB_API_KEY}"},
                    json={"model": VISION_MODEL, "messages": messages,
                          "stream": False, "max_tokens": 2048, "temperature": 0.1}
                )
                resp.raise_for_status()
                raw_text = resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            raise HTTPException(502, f"Ошибка OCR: {e}")
    else:
        raise HTTPException(400, f"Формат .{ext} не поддерживается. Используйте TXT, MD, PDF, DOCX, JPG, PNG")

    questions = _parse_ticket_lines(raw_text)
    return {"questions": questions, "count": len(questions)}


@app.post("/api/subjects/{slug}/tickets/bulk-delete")
async def bulk_delete_tickets(slug: str, request: Request,
                               user: dict = Depends(current_user)):
    """Удаляет несколько билетов по списку id."""
    body = await request.json()
    raw_ids = body.get("ids", [])
    if not raw_ids:
        raise HTTPException(400, "Список id пуст")
    try:
        ids = [int(i) for i in raw_ids]
    except (ValueError, TypeError):
        raise HTTPException(400, "Все id должны быть числами")
    db = get_db()
    placeholders = ",".join("?" * len(ids))
    cur = db.execute(
        f"DELETE FROM exam_tickets WHERE subject_slug=? AND id IN ({placeholders})",
        [slug] + ids
    )
    deleted = cur.rowcount
    db.commit()
    db.close()
    return {"ok": True, "deleted": deleted}


@app.put("/api/subjects/{slug}/tickets/{tid}")
async def update_ticket(slug: str, tid: int, question: str = Form(),
                         user: dict = Depends(current_user)):
    new_q = question.strip()
    db = get_db()
    row = db.execute("SELECT question FROM exam_tickets WHERE id=? AND subject_slug=?", (tid, slug)).fetchone()
    if row and row["question"].strip() == new_q:
        db.close()
        return {"ok": True, "changed": False}
    db.execute(
        "UPDATE exam_tickets SET question=?, status='pending', answer='' WHERE id=? AND subject_slug=?",
        (new_q, tid, slug)
    )
    db.commit()
    db.close()
    return {"ok": True, "changed": True}


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
async def export_tickets_html(slug: str, inline: int = 0, user: dict = Depends(current_user)):
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
    headers = {} if inline else {"Content-Disposition": f'attachment; filename="tickets_{slug}.html"'}
    return HTMLResponse(html, headers=headers)


@app.get("/api/subjects/{slug}/tickets/{tid}/export")
async def export_single_ticket(slug: str, tid: int, inline: int = 0, user: dict = Depends(current_user)):
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
    headers = {} if inline else {"Content-Disposition": f'attachment; filename="ticket_{tid}.html"'}
    return HTMLResponse(html, headers=headers)


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
    # Path traversal protection
    allowed_root = (subject_dir(slug) / "md" / src_slug).resolve()
    file_path = (allowed_root / path).resolve()
    if not str(file_path).startswith(str(allowed_root)):
        raise HTTPException(403, "Доступ запрещён")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "Файл не найден")
    mime, _ = mimetypes.guess_type(str(file_path))
    return FileResponse(file_path, media_type=mime or "application/octet-stream",
                        headers={"Cache-Control": "public, max-age=3600"})


@app.get("/api/images/{image_id}")
async def serve_image(image_id: int, w: Optional[int] = None,
                       user: dict = Depends(current_user)):
    """Serve image by id, optional thumbnail width ?w=400."""
    db = get_db()
    row = db.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Изображение не найдено")

    # Path traversal protection: reconstruct from subject_slug only
    allowed_root = subject_dir(row["subject_slug"]).resolve()
    file_path = (subject_dir(row["subject_slug"]) / row["path"]).resolve()
    if not str(file_path).startswith(str(allowed_root)):
        raise HTTPException(403, "Доступ запрещён")
    if not file_path.exists():
        raise HTTPException(404, "Файл не найден")

    if w and w > 0:
        # Resize using fitz.Pixmap
        def _resize():
            import fitz
            pix = fitz.Pixmap(str(file_path))
            orig_w = pix.width
            orig_h = pix.height
            if orig_w <= w:
                return file_path.read_bytes(), "image/png"
            scale = w / orig_w
            # fitz doesn't have direct resize but we can use a matrix on a temp document
            # Create a temporary in-memory image document
            # Workaround: convert via pixmap samples
            new_h = int(orig_h * scale)
            # Use fitz.Pixmap shrink (only works for integer factors) or just return original
            # For proper resize without Pillow, create a PDF page with the image and render at scale
            try:
                import io
                doc = fitz.open()
                rect = fitz.Rect(0, 0, w, new_h)
                page = doc.new_page(width=w, height=new_h)
                page.insert_image(rect, pixmap=pix)
                pix2 = page.get_pixmap(dpi=72)
                buf = pix2.tobytes("png")
                doc.close()
                return buf, "image/png"
            except Exception:
                return file_path.read_bytes(), "image/png"

        buf, mime_type = await asyncio.to_thread(_resize)
        return Response(content=buf, media_type=mime_type,
                        headers={"Cache-Control": "public, max-age=3600"})

    mime, _ = mimetypes.guess_type(str(file_path))
    return FileResponse(str(file_path), media_type=mime or "image/png",
                        headers={"Cache-Control": "public, max-age=3600"})


@app.put("/api/images/{image_id}")
async def update_image(image_id: int, request: Request,
                        user: dict = Depends(current_user)):
    """Update hidden flag and/or caption for an image."""
    body = await request.json()
    db = get_db()
    row = db.execute("SELECT id FROM images WHERE id=?", (image_id,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Изображение не найдено")
    updates = []
    params = []
    if "hidden" in body:
        updates.append("hidden=?")
        params.append(1 if body["hidden"] else 0)
    if "caption" in body:
        updates.append("caption=?")
        params.append(str(body["caption"])[:500])
    if not updates:
        db.close()
        return {"ok": True}
    params.append(image_id)
    db.execute(f"UPDATE images SET {','.join(updates)} WHERE id=?", params)
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/api/subjects/{slug}/images")
async def list_images(slug: str, source_slug: str = "",
                       user: dict = Depends(current_user)):
    """List images for a subject, optionally filtered by source_slug."""
    db = get_db()
    if source_slug:
        rows = db.execute(
            "SELECT id,source_slug,segment,path,sha1,width,height,kind,caption,"
            "figure_label,context,status,hidden,created_at "
            "FROM images WHERE subject_slug=? AND source_slug=? ORDER BY id",
            (slug, source_slug)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id,source_slug,segment,path,sha1,width,height,kind,caption,"
            "figure_label,context,status,hidden,created_at "
            "FROM images WHERE subject_slug=? ORDER BY id",
            (slug,)
        ).fetchall()
    db.close()

    result = []
    for r in rows:
        d = dict(r)
        # Add image URL
        d["url"] = f"/api/images/{d['id']}"
        result.append(d)
    return result


# ─── ROUTES END ────────────────────────────────────────────────────────


# ─── Frontend ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_SPA


_ICON_180_B64 = "iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAATZklEQVR42u2deZRU1Z3HP/feV3v1Ai0SXBBxOxpcIhEZVAaDIC5xi0Q5LtGgSYzLxMTkjJmYMImjTpIzMYmOOsbBGOMSEIUorkQOUTQY5SgG14hING5Ad9de9e6980c1BByQqu5Wu7p+n3M4x4N0d/V7n3ff7/e9992n7rzRewRhkKDlEAgitCCI0IIgQguCCC2I0IIgQguCCC0IIrQgiNCCCC0IIrQgiNCCIEILgggtiNCCIEILgggtCCK0IIjQgggtCCK0IIjQgiBCC4IILYjQgiBCC4IILQgitCCI0IIILQgitCCI0IIgQguCCC2I0IIgQguCCC0IIrQgQguCCC0IIrQgiNCCIEILIrQgiNCCIEILgggtCCK0IEILgggtCCK0IIjQgiBCCyK0IIjQgiBCC4IILQgitCBCC4IILQgitCCI0IIgQgsidHPjvcd7LwdChG5snLN47zBGEQQK8D1/J3KL0A04IqdThlhMk8tn6c50obWiJW0wRuGckwM1AAnkEHxwVPZEAoU2sGjJPJ58aj5vv/sa1oZ0DN2RffeZyLTJM0klU+QLFmOMHLQBhLrzRrl/bipzNKrI5bq44dff5JlnH8SYCJEghlKKMKxQrhQYueM+fPXsn7HX7mPozoQYI+OClBwDsMwwxlEp57j2pgv58/KFtLUMI5loJQgiGBMQiyVpb92et99bxZVXz+CPT9xHa0uAtVYOoAg90IR2xKKG/73tBzz7/CMMaR9BaCsbm8DqH0doKyTiacKwzE2//VdefnUlqaT52Gpq7x3WhXjv8N7hnJV6XoTeHOssqaRh+YonWLpsLq0twwjD8tb/vQ2JRRKUywWum30R3ZlOIgEfefrhnCUa1bSmA+IxTSymSacNyYTGeSfpizSFVQkjRpHJZrn9rlkYE4UaxLAuJBFP89bbr3D97Ev49oW/IrQhYADV758RPC1pw19XvcpTyxeyes3zhGGZEZ/agwPGTGL/MYdQqUBoPUqppj2fTd8UWhvS1hpw+12/ZO6Cq2hrHYa1Yc1fb0xAd3Ytn596IV+a8R26uvu3SfTeo5UnEtHcs/Ba7n3wv8nluwiCSHXUtiHaBEwYdwJnfHEWiXgLFQtaNefNt6lLDuccyUTACy+v5P5HriOdGlKXzBsuiHRyCAsfuY4/LFlAW783iY5oVHPz7bO47a4foZSmrXU7kolWkokWWtIdpBJtLH7sdn5+w3kopQi0atryo6mFVqp60ufMv4pSOY/Wvc+Uo5E4t9z5b7z46l/6rUm0NiSdMjyw6FbuX3QDQ9tHoFT17zc0g9aFWBcypH0EL76ylJ/f8HWcD3t+Ny9CN1sj+PDiO1ixcjHJRDvO9W5k9d4RBFFK5QLXz/4XuvqhSax+voCVL63gznsupzW9Hc6FW/2e1lZIJdp58s/zePLPC0klNLYJ04+mFNp7RyyieW/tOu5Z+F/EYkm871uZ4Jzd2CTeMPsSgkADtlejpPeeaKDoznZz4y0X46xFa73NC8R5Ryo1lLvv+ynvr+8iGuimKz2aVGhPECjunHcFnV3vEA3i/XLiqyXCEJ5Z8SC3zf0xLene1tOWSETz69t/wJt/f4l4PFXT3cN7RzSI8c67q3hk8S3EYgrnnQjdDKXG8hVP8PiyuSQTbVgX9t/372OTWL0oAu5/5FYe/9McWlIddTWqzltSyXbuX3Q9q9esJhHTTTXx0lRCbylz/qgS2940iRtSlw11cyrZjquzFPLeY3RAsZhlwQO/QGvVVM1hUwntnCWZ1Nz/yGxWr3meeCxZxy1Z1SHV5k1id6aLYBtNoveewEChWOBXv/lmT91selUKWReSTLSxdNldLH9uKcmE6XXDK0IPWJn7kjkrwNU1A7dpk3j97G8RjWhg69PT3lvicc1tc6/kb2/VXjdv9RMr0DpgzvwrKJdDjFY1zYCK0A1CbzNnpRTeW7SOEIbluqTeUE8vX/EQs2/7IamkwW/hjmCtpSUd8Icl97Boyc29muDZ0gUcj6VY9cZzPPrYHBIJjW2CBrEphLbWkk71LnN23qG14cKvXM8eu40jX+iuawLGupB0qp2HHr2RhxfPpSVlsJv87Oqdw/DX11/h1jmXkYintyh973oGRyyWZMEDV7NufXdTxHiDXmjnHfGYZs2bf2PugquIx9M1Z87GBORynUyZNJMJB43nrBn/QXvrcCphGVXHWgnvPclEG7fc+V3+8tJzpHpq2uoabE+xVODGWy6hWMphTKTfpKvm2XHWrf87Cx64hlhM9dvFIkJ/ctEGQaC4+96fkcmuI2KiNQmjlaZYyrPLzmM4Zuo5vLs2ZKcdRvLVs39BGJbqahS992itAcW1N53HuvXriEY01oYk4obfzrmSv656mmSird+bN+stiUQrjz52K6+/8TrxmBnUMd6gFtq6aqmxdNnDPL5sbrU2rTFz9oC1ZWZ8YRYt6TR4RTYXcuC+4znt5H+nO/t+Xc8TOueIReKsW/8W1950Ac5bhrRHWLTkbhYtuZmWdAfWVuroCVTNF7TRhnK5wO/mX4lS/+gnBiNm+nGzZg3OgbknBivkuW72hRSKGQId4GvIZI0OyBU6OfTg6Rw3bSb5QjVC01pTrlj23vMA1neu44WXl5JItNR8G/feE4smWfPmSsKKo7V1e6658TyMidTVbCqlqIRltA5q/rmRSJy/vfUio0cdxM477kK5Yusqm2SEHgC1cyKhueven7PmzReIx1I1Zc5KKcphifa24Zxy0ncJww8umNeUK44zTrmMvfec0MsmcQiPPvYbfvrLmVTCMkYHNdfNSimsDRnWMRLva48SqyOzZs49gzvGG5RCO+dIxg0vvfoCj/7xFlLJ9ppjMKUMxWKGE47+JsM6hlKquM1GsurT39WZwIu++j8MafsU5Uqxp0auj0z2fSJBrOYR3uiAfKGb3Ud/lksvvpVkoqXmKLFZYrxBKLRHa08lDLn1d9/vuTXXNoJqbcgXujhw/2kcMelUcnmL2cLXaq0pli1D24dw/jnXU91RydX96JMxQc0yK6Uph0XaWodx1ozL2XHEcI458kJK5ULNpUMzxHiDTmhrHamk4dHH5vLiK0+QjLfWlBwopbAuJBZNcOpJ3wMP3qsPGS0NuYLl03vtx5mnXEG+0FV3TVqPTAqoVIp8acZV7LzjLqxdb5k88VR2HbkfxVKupjtEM8R4g0roTTPnu37/nyQSrTUv7tHKUCh0c+yRFzJq51EUSnabkhhtyOQsUyadzNTDzyWTW4fR/f/csTEBmdw6jjri6xwy7ggyuRAFRCOG6Sd8t2dLg/pjvFVvvE58kK3GG1wj9KaZc2Zt7Zmz1hRKGUaN3I9jpp5LoeBqfshUKU2+YDnji5fx6b0OI1fo2mKZ0usTpA25fBf77HUYp5zwLXJ5i1YGrQ2FouWAMRM4YN8pFIqZ2kqrTWK8OfOvRGs1qGK8QSN0nzJnXxXz1BMvIxYNsM7XkR4onKv+2/PPuYahQ3ag1MsmcUvfOwzLtLZ0cO6ZP0EbjXNq42fzXuE9fPH4S4lGE9Up9ZoaREsy0cry5x5k6VMPkUxsPh0vQn/iA/OGdc455t37Y4IgWnMkZUxANreOw8afwoH7jyfXkznXN4pqShXH0PahnD/zul43iVsa/YulLGeccgU77bATxaLb7ELRWlMsWUaNHMXhh55OodCNUbV+do/WAQvuv5pisTJonhQfJEI74nHN3AVX1585V4oMHzaKE4/9RlWYXkrYH03i5hdahEx2LZMnns0h46aSyW55p1OlNKWS57hpFzB0yAjKYbHmGC8RS7N6zQruX3QzyaQeFI9rNbzQ1dunYcXKZ3h48U2kU0Nrzpy1MhSKGU469jsMH7Yd5Yrvm4T91CRuiA9323Usp02/lFJp67N61Ykgx9AhrRw37RsUi1lUjaO085ZYLMUji2/inffeJxo0furR4EJ7tIZSucKc+VcCqubbvNaGXKGLsfsfxaHjjyWb65+9nvvaJFZnAivEYynOPfOnxGMJQvvhv5dRmnzBcfhh09l7zwkUS5m6Yrz3173J3fddTTyucQ1edjS00Na6no1YbuaFl5eSTLT0KnNWSn9o5lxvI9eXJlEpTaGY5fTpP2K3UXv0rCPR2/oirPPEogEnHfsdnLW1x3guJJVs44ll83jh5ZUN/1Btwwq9IXNeveYNFj58Halk7Usve5M5fxxN4j/q5rP43MQTyGTDmu8aRhtyecuYfT7LhIO/QL7QVXO5o7WhWMox796fNHyM17BCKzzGKG6/63Iy2bUENWfOhkIp26vMuTdN4j49TWI2tx5QW/1ZgYmQy3durJsLRVtzLbzZUXFw3LSLiMfTWBfW2CBWtz54fuVili5r7BivIYW2PY3g0mUPsnzFQ9XFRzVnzh6871Xm3Cup85bJ/3wyJxxzMflCN5WwhDGRjctRtTYYEyGbW086NZSv9NTN1qq6P1d1gsiyy867cNTkr5HLd6LriPGUNix4oLFjvIYTesM2WZ1d3dwx74cEQazmA290QC6/nimTZnLg/uM3rnP+SO8kypAvWE6ffgkXfeV6Wlu2o6v7XfL5LgqFDLlcJ92Z99l99Fguvfi3jNx5D/IfyJvrOqE9Md4Rk85k+Pa7Nl2MFzSe0I5YzHD7vGt4b+0b1Z2FahidldKUKgWGdYzk+KMvoFh0H9sCd60Mmaxlwrhp7LnbwTz59HxefW052dw6OobsxD57Hcy4sZ8nEjEUCg7Th3q+GuNZthvaxonHXMJ1s79OW3oY1m/7GG0a4x06/kTaWjsIQ9dQDwI01IbnGzLnv7z4DFdefTLxWO1PSG/Ids+feQOHHHwk2a0sDf1oP78jEmjicbAWnAdjqivp8oXq/++f5rS6la5SIVddfTqvrnq6OtlUQ3phdEB3bi2TD/sSXzv7crqzH/9xapKSo/eZc7XU6OQz+05lwrgjq+8X/AROktaa0HoyWUu+4CiVHLmcJZuzPb9ff50OhXOeeCzaqxgvnRzCH5+4g2eff3rjE+oidH83gn3InENbpiXdwYwvfA9rPZ5P7h0kSqmNDaFSuue/+/+9LLoPMV41p7f8/sFfYK2jkV7Z0hBC9ylz7ll+efSU89hl55EUS66J3j/Shxgv0cazzy/isT/dRzrVODGebpDT0uvMOV/IsPeeE5g2+aye6e3m2Z+yLzGe845oNMl9D11DZ1eGiGmMGG/An90N+zn3OnPGM/34S4lFI1R7ouZ65dn/i/EqtcV43jvisSSr16zgoUd/s/FdiCJ0X9pA74kGmvfWruWOu3/Uq8x56uHnsO8+B34smfOAvLv1rMbbbkgbJx3z7erzh7WO0s6SSLSx+PFbefu9tUQDM+BH6QEttPOWeFyx7OmFvPPuKmKRZE0x3WaZ81EXUCq5QbmpSq0YbcjmLYeOP5b9x3yOXKGrpou7OqDEePe91Tz1zELiceregF2E/mC3beHl154iCCJ4anzkHwgrJU496fu0t7VSDpv77apVOcEYzeePvAijTe27PeExJsLLrz2FtQz44ziwhUbhHORynTV/VK0N+WKGAw+Y9olmzgOvQaxOwe/36bFMnHAquXw9MZ4ml+vEueo5EaF7O6r0TKakUu1ArfvHOYIgwrFTL8B7j7zP/QNNtvUc9k+nEo3G6ygfHKlUO1pT096AIvSH1HDGwJ6jDyIMK9usg5XSVMIyQ9t3YMcRu1Gu0NS18xaPTwV2GLEbQ9t3qGmfa6U0YVhhz9EHYQzSFPbpwylDsegZN/Zohg8btc1XSRgTUCxmmDhhBq3pRM8slxKTN+lJQutoSyeYOGEGxWIGY4IPLVNK5TzDh41i3NijKRZ9HctRRegtnoBK6BjW0cFp02dRLhcIwwrGBCilNv7R2hCYCOs732bM3pM4esqXKRSdjM5bGXELRcfRU77MmL0nsb7zbYKe9dmbHlNjAsKwQrlc4LTpsxjW0UElHPgDxIDfH1opTalsGb3L7gzbbleef2EJmey6jQfWOUupnKdQzDD2gGmcP/OXPZuuKBmdtzJIbEg8DtxvCn9/5zVef+M5rA1RVGcDra2QL3STiKeZecaPOfTgY6o7NjVAc90wy0ddz85Ib7z5Og8uupFXXltOJrOWIIjyqe1HM/6g45k44SSchdBKTFdLfxIYhTawZOk8nnxqPm+/+xphWKalpYM9Rn+GIyefy8gdR5HNNc6kVIOth3ZEo5pYFDJZ27OfW0Bba5rAQC7vN45CQm1SA6SSitBCV3cW50IS8RZa0oZSGcpl168PEH/UNNQTK1prKhVPuewwxtDa0o73UCo5it435dR2X8sPgGzOopQilUyjFDhXHTCqy1sbqw8JGvEkKFVdUxCG/6izZVDuy0BRHQis3XCHo2EHh6BxT4MSiT+iEbuhL045jcKgutvIIRBEaEEQoQVBhBYEEVoQoQVBhBYEEVoQRGhBEKEFEVoQRGhBEKEFQYQWBBFaEKEFQYQWBBFaEERoQRChBRFaEERoQRChBUGEFgQRWhChBUGEFgQRWhBEaEEQoQURWhBEaEEQoQVBhBYEEVoQoQVBhBYEEVoQRGhBhBYEEVoQRGhBEKEFQYQWRGhBEKEFQYQWBBFaEERoQYQWBBFaEERoQeh3/g+1UYSFdp/+TwAAAABJRU5ErkJggg=="
_ICON_32_B64 = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAElUlEQVR42sWXbWiVZRjHf9d9P+fsnLNzMpUspHBkWM7UVJBYWJKllomZuJVJ2mqZKIT2KWiMVQhlRR8sJ9ZsvZjOsWUqab5QhlEmmpBpJUpJ6Qxtbmdvz3me++rDNiNsuqNT/5+eL/fz/3FfL/d1CZ0qK1NTXi5u1TK9oU+Sp8OQqc4xGvC4NAXGsNdaNpxJ8+6TC+VElxeAAFRXqy0slHBdpRZ7lpetYWAYgp+hVxSNgLUQOv4MQkpnFktll6d0faxZqcuvSfJsSytkAkIjCGB6BwHnFI142EQcGtNUPFoi86ur1QrA2pU6J5Xk/aY0QadpbxmfAwK4VBKvKc3cohKpktUr9XpP+MmzXJsJ4DKan4WIeBCENARKvhGYF4/Rrz2DXgFzANOeQeMx+gnMMyjTghDtjPkVkREkCFGUaZ7ASN9HuiriSjH4PgiMNCJYrpJEsIarLC/7gg476Q0i/42aomSbSlkCKIlER8R8H8IQuhhUFWsEp5pVOvU4BKqOSESo21jBm2/Pp6W1iYjXYayqWCu0+W0YI0gWl9AjgNCF5CYMu/duZU3tK+z6roaPqsuwVlENiXhCurmB0iUT+XhdOZFIB3CvAKgqESs0NjVTu2EpOdE41/UfxM5vPqFuUwWplIcYZXXNS5z86yjbvlzFgYN7SMTN2Xy5JACnjnjcULdpGb8c3c2w28ZRMud14rEUtRuXcuDgfjZvq+KrXavJTfQFI9RtXEpbu48xAujFAzjnSMQsPx8+xI6dq+jfZyDTH3qeewrGM3Xyc7S1N/POewtY//lbxGNJnpr9KoPzRrPvwFa+3bOF3LghdO5iARRjFD/js7qmnL8b63nw/oXkDxnGiZPtzJi6gPF3Pc7x+sOk06cpnP4ikyY8wOR7nyEWzeXTTW9wqqGRqGdQ1ewBQudI5lq2bP+QH378gqG3FDBpwhO0tDqMiRCEypzHyhk6pIBRIyYxZeJcjp/wKRg7idEjJnPk2D42bl5OTo6cNyG97kouFrX8duwYm7dXkEz0peiRUq5JJkm3hFhjCQIlnpPihUU1OOfwfRCxOKc8PGURvx75nh1ff8DdBUXcODCPNt9hxPTsBhTF82BN7RL+OHmImweNYkT+nbS0OqyxnZ1QyASKEYPneTgHxlja2pVbB+cz6KbhnDrzOzWfvYa1dJuM3YRAcA7uGH4fA/rlMX7cbMRwTixFBKWjEZ1tPgKBUwrGzmBAvzxG3j4B9+/4ea7T2pXdZ0g0Ak3NrSQTcTqnpR4rEoF0cyup3Ph5h9vzlmG774jH4vgZl/Ur53eebfcvUIaqhN2/14YwVESyf7V7claV0Cjsj0bRzon1f3508YPSec66aBRV2G8Q1nsWcXqBntmbY7GinkUQ1huFFa1tnM6JIN3dQm/750SQ1jZOK6wws0qkXpXFsRima3G4nOaAi8UwqiyeVSL1prpabVGJVDWmqUgl8azFuI7E7E0Q55TQWkwqideYpqKoRKrOrmZXczk1AIWFEpaVqZlZLJUNTYwJQkqDkN1A0Av+QRCyOwgpbWhizMxiqSwrU1NYKCHAP7ruEhtBnwpgAAAAAElFTkSuQmCC"


@app.get("/apple-touch-icon.png")
async def apple_touch_icon():
    import base64
    return Response(content=base64.b64decode(_ICON_180_B64), media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/favicon.ico")
async def favicon():
    import base64
    return Response(content=base64.b64decode(_ICON_32_B64), media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})


HTML_SPA = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c0b14">
<meta name="apple-mobile-web-app-title" content="StudyLab">
<title>StudyLab</title>
<link rel="icon" type="image/png" sizes="32x32" href="/favicon.ico">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geologica:wght@400;500;600&family=Unbounded:wght@500;700&display=swap">
<script>
(function(){
  var t = 'dark';
  try {
    t = localStorage.getItem('sl-theme') || (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  } catch(e) {}
  document.documentElement.setAttribute('data-theme', t === 'light' ? 'light' : 'dark');
  var m = document.querySelector('meta[name="theme-color"]');
  if (m) m.setAttribute('content', t === 'light' ? '#f4f3fa' : '#0c0b14');
})();
</script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
/* ── Ночной атлас: токены ───────────────────────────────────────────── */
:root{
  color-scheme:dark;
  --nav-h:60px;
  --bg:#0c0b14;--bg2:#12101c;
  --glass:rgba(255,255,255,0.05);--glass2:rgba(255,255,255,0.08);
  --border:rgba(255,255,255,0.14);--border2:rgba(255,255,255,0.26);
  --accent:#a99bff;--accent2:#c4b9ff;--accent-ink:#14102b;
  --green:#6ee7a8;--red:#ff8f8f;--yellow:#fbbf5b;
  --text:#ecebf5;--muted:#a3a1ba;--dim:#8d8ba6;
  --field:rgba(255,255,255,0.05);--field-b:rgba(255,255,255,0.26);
  --pop:#171424;--nav-bg:rgba(12,11,20,0.86);
  --orb1:#5b45e0;--orb2:#d946a8;--orb-o1:.3;--orb-o2:.2;
  --font:'Geologica',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --font-d:'Unbounded','Geologica',-apple-system,BlinkMacSystemFont,sans-serif;
  --r-s:12px;--r-m:18px;--r-l:22px;
}
:root[data-theme="light"]{
  color-scheme:light;
  --bg:#f4f3fa;--bg2:#ebe9f6;
  --glass:rgba(255,255,255,0.78);--glass2:rgba(23,21,43,0.06);
  --border:rgba(23,21,43,0.14);--border2:rgba(23,21,43,0.28);
  --accent:#5b45e0;--accent2:#7461ec;--accent-ink:#ffffff;
  --green:#0b7a47;--red:#b42318;--yellow:#8a5a00;
  --text:#17152b;--muted:#5a5873;--dim:#6b6985;
  --field:#ffffff;--field-b:rgba(23,21,43,0.28);
  --pop:#ffffff;--nav-bg:rgba(244,243,250,0.88);
  --orb1:#b6a8ff;--orb2:#f6b0dc;--orb-o1:.5;--orb-o2:.4;
}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font-family:var(--font);
  min-height:100vh;overflow-x:hidden;line-height:1.5}
body::before,body::after{content:'';position:fixed;z-index:0;pointer-events:none;border-radius:50%;
  -webkit-filter:blur(120px);filter:blur(120px)}
body::before{width:460px;height:460px;left:-160px;bottom:-220px;background:var(--orb1);opacity:var(--orb-o1)}
body::after{width:360px;height:360px;right:-120px;top:-160px;background:var(--orb2);opacity:var(--orb-o2)}
#app{position:relative;z-index:1}
a:focus-visible,button:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.glass{background:var(--glass);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);
  border:1px solid var(--border);border-radius:var(--r-m)}
.glass2{background:var(--glass2);border:1px solid var(--border);border-radius:var(--r-s)}
.ic{flex:0 0 auto}

/* ── Навигация ──────────────────────────────────────────────────────── */
.navbar{position:sticky;top:0;z-index:100;background:var(--nav-bg);
  -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--border);padding:0 24px;min-height:var(--nav-h);
  display:flex;align-items:center;gap:12px}
.logo{display:inline-flex;align-items:center;gap:10px;min-height:44px;flex-shrink:0;
  font-family:var(--font-d);font-weight:700;font-size:1rem;color:var(--text);text-decoration:none}
.crumb{display:flex;align-items:center;gap:6px;flex:1;min-width:0;overflow:hidden;white-space:nowrap;
  font-size:.9375rem;color:var(--muted)}
.crumb a{display:inline-flex;align-items:center;min-height:44px;padding:0 4px;color:var(--muted);text-decoration:none}
.crumb a:hover{color:var(--text)}
.crumb b{color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis}
.crumb .sep{color:var(--dim)}
.nav-user{display:flex;align-items:center;gap:8px;flex-shrink:0}
.icon-btn{width:44px;height:44px;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;
  border:none;border-radius:var(--r-s);background:var(--glass2);color:var(--text);cursor:pointer;
  transition:background .15s;font-family:inherit}
.icon-btn:hover{background:var(--border)}
.user-btn{min-height:44px;display:inline-flex;align-items:center;gap:10px;padding:0 14px 0 6px;border:none;
  border-radius:22px;background:var(--glass2);color:var(--text);font-family:inherit;font-size:.9375rem;
  font-weight:500;cursor:pointer}
.user-btn:hover{background:var(--border)}
.avatar{width:32px;height:32px;border-radius:50%;background:var(--accent);color:var(--accent-ink);
  display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;
  font-family:var(--font-d);font-weight:700;font-size:.8125rem}
.menuwrap{position:relative}
.menu{position:absolute;right:0;top:calc(100% + 6px);z-index:200;min-width:210px;padding:6px;
  border-radius:14px;background:var(--pop);border:1px solid var(--border);
  box-shadow:0 12px 32px rgba(0,0,0,.28);display:flex;flex-direction:column;gap:2px}
.menu button,.menu a{min-height:44px;display:flex;align-items:center;padding:0 12px;border:none;border-radius:10px;
  background:none;color:var(--text);font-family:inherit;font-size:.9375rem;text-align:left;cursor:pointer;text-decoration:none}
.menu button:hover,.menu a:hover{background:var(--glass2)}
.menu .danger{color:var(--red)}
.menu-label{padding:8px 12px 4px;font-size:.75rem;color:var(--dim)}
.menu-open{position:relative;z-index:50}

/* ── Разметка страниц ───────────────────────────────────────────────── */
.page{padding:32px 24px 56px;max-width:1200px;margin:0 auto}
.section-header{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.section-title{font-family:var(--font-d);font-size:1.75rem;font-weight:700;line-height:1.15}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.empty{display:flex;flex-direction:column;align-items:center;gap:12px;text-align:center;padding:48px 20px;
  border:1.5px dashed var(--border2);border-radius:var(--r-m);color:var(--muted)}
.empty svg{color:var(--accent)}
.empty b{color:var(--text);font-family:var(--font-d);font-weight:500;font-size:1.0625rem}

/* ── Карточки предметов ─────────────────────────────────────────────── */
.card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(260px,100%),1fr));gap:16px}
.subject-card{padding:22px;cursor:pointer;transition:transform .2s,border-color .2s,background .2s;
  text-decoration:none;color:inherit;display:flex;flex-direction:column;gap:16px}
.subject-card:hover{background:var(--glass2);border-color:var(--border2);transform:translateY(-2px)}
.card-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.card-title{font-family:var(--font-d);font-size:1.0625rem;font-weight:500;line-height:1.3}
.card-meta{font-size:.8125rem;color:var(--muted)}

/* ── Формы и кнопки ─────────────────────────────────────────────────── */
input,textarea,select{background:var(--field);border:1px solid var(--field-b);border-radius:var(--r-s);
  color:var(--text);padding:0 16px;min-height:48px;font-size:1rem;width:100%;outline:none;
  transition:border-color .15s;font-family:inherit}
textarea{padding:12px 16px;line-height:1.5}
select{padding:0 12px}
input:focus-visible,textarea:focus-visible,select:focus-visible{border-color:var(--accent);outline:2px solid var(--accent);outline-offset:1px}
input::placeholder,textarea::placeholder{color:var(--dim)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 18px;
  border-radius:var(--r-s);font-size:.9375rem;font-weight:500;cursor:pointer;border:none;
  transition:background .15s,filter .15s;font-family:inherit;text-decoration:none;color:var(--text)}
.btn-primary{background:var(--accent);color:var(--accent-ink);font-family:var(--font-d);font-size:.8125rem}
.btn-primary:hover{filter:brightness(1.08)}
.btn-ghost{background:var(--glass2);color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--border)}
.btn-danger{background:transparent;color:var(--red);border:1px solid var(--red)}
.btn-danger:hover{background:var(--glass2)}
.btn-sm{min-height:44px;padding:0 14px;font-size:.875rem}
.btn-primary.btn-sm{font-size:.75rem}
.btn:disabled{opacity:.45;cursor:not-allowed}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
  font-size:.8125rem;font-weight:600;white-space:nowrap;background:var(--glass2)}
.badge-dot:before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor;flex:0 0 auto}
.badge-green{color:var(--green)}
.badge-yellow{color:var(--yellow)}
.badge-red{color:var(--red)}
.badge-blue{color:var(--accent)}
.badge-dim{color:var(--muted)}
.progress{height:6px;background:var(--border);border-radius:999px;margin-top:10px;overflow:hidden}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--orb1),var(--accent));border-radius:999px;transition:width .3s}
.sw{min-height:44px;display:inline-flex;align-items:center;gap:10px;padding:0 4px;background:none;border:none;
  color:var(--text);font-family:inherit;font-size:.9375rem;font-weight:500;cursor:pointer}
.sw .knob{position:relative;width:42px;height:24px;border-radius:999px;background:var(--border2);flex:0 0 auto;transition:background .15s}
.sw .knob:after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:var(--muted);transition:left .15s}
.sw[aria-checked="true"] .knob{background:var(--accent)}
.sw[aria-checked="true"] .knob:after{left:21px;background:var(--accent-ink)}

/* ── Вход ───────────────────────────────────────────────────────────── */
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.login-card{width:100%;max-width:420px;padding:0;overflow:hidden;border-radius:var(--r-l)}
.login-card .bar{height:4px;background:linear-gradient(90deg,var(--orb1),var(--orb2))}
.login-card .body{padding:36px 32px 28px}
.login-title{font-family:var(--font-d);font-size:2rem;font-weight:700;line-height:1.1;margin-bottom:10px}
.login-sub{color:var(--muted);font-size:1rem;line-height:1.5;margin-bottom:28px}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:.875rem;font-weight:500;color:var(--muted);margin-bottom:6px}
.form-error{color:var(--red);font-size:.875rem;margin-top:8px}

/* ── Источники ──────────────────────────────────────────────────────── */
.source-list{display:flex;flex-direction:column;gap:10px}
.source-item{padding:14px 18px;display:flex;flex-wrap:wrap;align-items:center;gap:12px 16px}
.source-icon{width:44px;height:44px;border-radius:10px;background:var(--glass2);color:var(--accent);
  display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.6875rem;font-weight:600;letter-spacing:.04em}
.source-info{flex:1 1 220px;min-width:0}
.source-name{font-size:1rem;font-weight:500;overflow-wrap:anywhere}
.source-meta{font-size:.8125rem;color:var(--muted);margin-top:2px;overflow-wrap:anywhere}
.source-actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-left:auto}
.drop-zone{border:1.5px dashed var(--border2);border-radius:var(--r-m);padding:28px 20px;text-align:center;
  cursor:pointer;transition:border-color .2s,background .2s;background:var(--glass2)}
.drop-zone:hover,.drop-zone.drag-over{border-color:var(--accent)}
.drop-zone-icon{margin-bottom:8px;color:var(--accent);display:flex;justify-content:center}
.drop-zone-sub{color:var(--muted);font-size:.875rem;margin-top:6px}

/* ── Читалка ────────────────────────────────────────────────────────── */
.three-col{display:grid;grid-template-columns:280px 1fr}
.reader-sidebar{border-right:1px solid var(--border);height:calc(100vh - var(--nav-h));
  height:calc(100dvh - var(--nav-h));overflow-y:auto;position:sticky;top:var(--nav-h)}
.reader-sidebar-inner{padding:16px 0}
.toc-group-label{padding:8px 16px 4px;font-size:.75rem;font-weight:600;color:var(--dim);
  text-transform:uppercase;letter-spacing:.06em}
.toc-item{padding:10px 16px;min-height:44px;cursor:pointer;font-size:.9375rem;color:var(--muted);
  transition:background .15s,color .15s;display:flex;align-items:flex-start;gap:8px;line-height:1.4}
.toc-item:hover{background:var(--glass2);color:var(--text)}
.toc-item.active{background:var(--glass2);color:var(--accent);font-weight:600}
.toc-num{font-size:.75rem;color:var(--dim);flex-shrink:0;margin-top:2px}
.reader-content{padding:32px 40px;max-width:760px;line-height:1.8;font-size:1rem}
.reader-content h1,.reader-content h2,.reader-content h3{margin:1.5em 0 .5em;font-weight:600}
.reader-content h2{font-family:var(--font-d);font-weight:500;font-size:1.125rem}
.reader-content h3{font-size:1rem;color:var(--muted)}
.reader-content p{margin-bottom:.875em}
.reader-content code{background:var(--glass2);padding:2px 6px;border-radius:4px;font-size:.875em}
.reader-content pre{background:var(--glass2);padding:14px;border-radius:var(--r-s);overflow-x:auto;margin:1em 0}

/* ── Чат ────────────────────────────────────────────────────────────── */
.chat-shell{display:flex;position:relative;height:calc(100vh - var(--nav-h));height:calc(100dvh - var(--nav-h))}
.conv-sidebar{width:288px;border-right:1px solid var(--border);display:flex;flex-direction:column;
  background:var(--bg);flex-shrink:0;z-index:20}
.conv-head{padding:14px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:10px}
.conv-foot{padding:10px 14px;border-top:1px solid var(--border)}
.chat-close{display:none}
.conv-item{padding:0 4px 0 14px;min-height:48px;margin:2px 8px;cursor:pointer;border-radius:var(--r-s);
  display:flex;align-items:center;gap:8px;transition:background .15s}
.conv-item:hover{background:var(--glass2)}
.conv-item.active{background:var(--glass2);font-weight:600}
.conv-title{flex:1;font-size:.9375rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.conv-date{font-size:.75rem;color:var(--dim);flex-shrink:0}
.conv-del{background:none;border:none;color:var(--dim);cursor:pointer;font-size:.875rem;width:40px;height:40px;
  border-radius:10px;opacity:0;transition:opacity .15s;flex-shrink:0}
.conv-item:hover .conv-del,.conv-del:focus-visible{opacity:1}
.conv-del:hover{color:var(--red)}
@media(hover:none){.conv-del{opacity:1}}
.chat-layout{display:flex;flex-direction:column;flex:1;min-width:0}
.chat-bar{display:none;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid var(--border)}
.chat-scrim{display:none}
.chat-messages{flex:1;overflow-y:auto;padding:24px 28px;display:flex;flex-direction:column;gap:20px}
.msg{display:flex;gap:12px;max-width:820px;min-width:0}
.msg-user{align-self:flex-end;flex-direction:row-reverse}
.msg-avatar{width:32px;height:32px;border-radius:10px;background:var(--accent);color:var(--accent-ink);
  display:flex;align-items:center;justify-content:center;flex-shrink:0;font-family:var(--font-d);font-weight:700;font-size:.75rem}
.msg-user .msg-avatar{background:var(--glass2);color:var(--text)}
.msg-bubble{padding:2px 0;line-height:1.65;font-size:1rem;max-width:680px;min-width:0;overflow-wrap:anywhere}
.msg-user .msg-bubble{padding:12px 16px;background:var(--glass2);border:1px solid var(--border);border-radius:18px 18px 4px 18px}
.msg-bubble p{margin-bottom:.6em}
.msg-bubble p:last-child{margin-bottom:0}
.msg-bubble code{background:var(--glass2);padding:1px 5px;border-radius:3px;font-size:.875em}
.msg-bubble h2,.msg-bubble h3{margin:.75em 0 .3em;font-size:1em;font-weight:600}
.prov{font-size:.8em;color:var(--accent)}
.math-block{text-align:center;margin:.8em 0;font-size:1.1em;overflow-x:auto}
.chat-input-area{padding:12px 24px 20px;border-top:1px solid var(--border);background:var(--nav-bg);
  -webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px)}
.chat-scope{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;font-size:.8125rem;color:var(--muted);margin-bottom:10px}
.chat-scope .dot{width:8px;height:8px;border-radius:50%;background:var(--green);flex:0 0 auto}
.chat-scope b{color:var(--green);font-weight:600}
.chat-input-row{display:flex;gap:8px;align-items:flex-end}
.chat-input-row textarea{flex:1;resize:none;min-height:48px;max-height:120px;border-radius:var(--r-s)}
.img-preview-bar{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.img-preview-bar img{height:56px;border-radius:8px;border:1px solid var(--border)}
.chat-hint{font-size:.75rem;color:var(--dim);margin-top:8px;display:flex;justify-content:space-between;align-items:center}

/* ── Билеты ─────────────────────────────────────────────────────────── */
.ticket-add{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.ticket-add input{flex:1 1 260px;min-width:0}
.ticket-item{margin-bottom:10px;padding:0}
.ticket-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;padding:10px 14px 10px 8px}
.ticket-q{flex:1 1 240px;min-width:0;font-family:var(--font-d);font-weight:500;font-size:.9375rem;line-height:1.45;overflow-wrap:anywhere}
.toggle-answer svg{transition:transform .15s}
.toggle-answer.open svg{transform:rotate(90deg)}
.ticket-answer{padding:16px 22px 22px;border-top:1px solid var(--border);color:var(--text);
  font-size:1rem;line-height:1.65;white-space:pre-wrap;overflow-wrap:anywhere}
.ticket-answer p{margin-bottom:.5em}
.ticket-answer code{background:var(--glass2);padding:1px 5px;border-radius:3px}
.ticket-answer h2,.ticket-answer h3{margin:1em 0 .4em;font-size:.8125rem;font-weight:600;letter-spacing:.06em;
  text-transform:uppercase;color:var(--accent)}
.msg-bubble table,.ticket-answer table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse;margin:.6em 0;font-size:.9375rem}
.msg-bubble th,.msg-bubble td,.ticket-answer th,.ticket-answer td{border:1px solid var(--border);padding:8px 12px;text-align:left}
.msg-bubble th,.ticket-answer th{background:var(--glass2)}
.preview-frame{width:100%;height:70vh;border:1px solid var(--border);border-radius:var(--r-s);background:#fff}

/* ── Вкладки и поиск ────────────────────────────────────────────────── */
.tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border)}
.tab{min-height:46px;padding:0 18px;border:none;border-bottom:2px solid transparent;margin-bottom:-1px;
  background:none;color:var(--muted);font-family:inherit;font-size:1rem;font-weight:500;cursor:pointer;transition:color .15s}
.tab.active{color:var(--text);border-bottom-color:var(--accent)}
.tab:hover:not(.active){color:var(--text)}
.search-hit{padding:16px 18px;transition:background .15s}
.search-hit:hover{background:var(--border)}
.search-score{display:inline-flex;padding:3px 10px;border-radius:999px;background:var(--glass2);
  font-size:.8125rem;color:var(--green);font-weight:600}
.search-title{font-weight:500;margin:8px 0 4px;font-size:1rem}
.search-text{font-size:.9375rem;color:var(--muted);line-height:1.6}

/* ── Уведомления и окна ─────────────────────────────────────────────── */
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast{padding:12px 18px;border-radius:var(--r-s);font-size:.9375rem;max-width:340px;animation:slideIn .2s ease;
  background:var(--pop);border:1px solid var(--border);color:var(--text);box-shadow:0 8px 24px rgba(0,0,0,.25)}
.toast-success{border-color:var(--green);color:var(--green)}
.toast-error{border-color:var(--red);color:var(--red)}
.toast-info{color:var(--text)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
.modal-overlay{position:fixed;top:0;right:0;bottom:0;left:0;background:rgba(0,0,0,.6);z-index:1000;
  display:flex;align-items:center;justify-content:center;padding:24px}
.modal{width:100%;max-width:440px;padding:28px;border-radius:var(--r-l);background:var(--pop);max-height:100%;overflow-y:auto}
.modal.wide{max-width:920px}
.modal-title{font-family:var(--font-d);font-size:1.0625rem;font-weight:500;margin-bottom:20px}
.hidden{display:none!important}
.mt{margin-top:16px}.mt2{margin-top:24px}
.flex{display:flex}.gap{gap:10px}.ml-auto{margin-left:auto}
.text-muted{color:var(--muted)}.text-sm{font-size:.9375rem}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border2);
  border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
@media(prefers-reduced-motion:reduce){*{transition:none!important}.toast{animation:none}}

/* ── Узкие экраны ───────────────────────────────────────────────────── */
@media(max-width:768px){
  .three-col{grid-template-columns:1fr}
  .reader-sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--border);max-height:260px}
  .page{padding:20px 16px 40px}
  .navbar{padding:0 12px;gap:8px}
  .section-title{font-size:1.375rem}
  .chat-messages{padding:16px}
  .chat-input-area{padding:10px 16px 16px}
  .reader-content{padding:20px 16px}
  .msg{max-width:100%}
  .source-actions{margin-left:0;width:100%}
  .toast-container{left:16px;right:16px;bottom:16px}
  .toast{max-width:none}
  .conv-sidebar{position:absolute;left:0;top:0;bottom:0;width:min(300px,86%);
    -webkit-transform:translateX(-102%);transform:translateX(-102%);transition:transform .2s}
  .chat-shell.side-open .conv-sidebar{-webkit-transform:none;transform:none;box-shadow:0 0 40px rgba(0,0,0,.4)}
  .chat-shell.side-open .chat-scrim{display:block;position:absolute;top:0;right:0;bottom:0;left:0;z-index:15;background:rgba(0,0,0,.45)}
  .chat-bar{display:flex}
  .chat-close{display:inline-flex}
  .modal-overlay{padding:12px}
  .preview-frame{height:60vh}
}
@media(max-width:480px){
  .user-name{display:none}
  .user-btn{padding:0 6px}
  .send-label{display:none}
  .login-card .body{padding:28px 20px 22px}
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
const S = { user: null, chatES: null, pendingImg: null, chatConvId: 0, titles: {}, _pollTimers: [] };

// Stop all polling timers
function stopPolling() { S._pollTimers.forEach(clearTimeout); S._pollTimers = []; }
function pollLater(fn, ms) { var t = setTimeout(fn, ms); S._pollTimers.push(t); return t; }

// Pause/resume polling on tab visibility
document.addEventListener('visibilitychange', function() {
  if (document.hidden) { stopPolling(); }
  else if (S._resume) { S._resume(); }
});

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

// ── Plural, icons ──────────────────────────────────────────────────────
function plural(n, f) {
  var a = Math.abs(n) % 100, b = a % 10;
  if (a > 10 && a < 20) return f[2];
  if (b > 1 && b < 5) return f[1];
  if (b === 1) return f[0];
  return f[2];
}
function ic(d, size, filled) {
  size = size || 20;
  return '<svg class="ic" width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="' + (filled ? 'currentColor' : 'none') +
    '" stroke="' + (filled ? 'none' : 'currentColor') + '" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>';
}
const IC = {
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  dots: '<circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  camera: '<path d="M4 8h3l2-3h6l2 3h3v11H4zM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"/>',
  send: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  chev: '<path d="M9 6l6 6-6 6"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5M5 20h14"/>',
  flask: '<path d="M10 3h4M11 3v6l-5 9a2.5 2.5 0 0 0 2.2 3.7h7.6A2.5 2.5 0 0 0 18 18l-5-9V3"/>',
  doc: '<path d="M7 3h7l4 4v14H7zM14 3v4h4"/>'
};
function logoSvg() {
  return '<svg width="32" height="32" viewBox="0 0 34 34" aria-hidden="true"><rect width="34" height="34" rx="9" style="fill:var(--accent)"/>' +
    '<path d="M9 22l5-8 4 5 3-4 4 7" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="stroke:var(--accent-ink)"/></svg>';
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
  stopPolling();
  S._resume = null;
  updateNav(view, slug);
  ensureTitle(view, slug);
  const main = document.getElementById('main');
  main.innerHTML = '';
  if (!S.user && view !== 'login') { location.hash = '#/login'; return; }
  if (S.user && view === 'login') { location.hash = '#/dashboard'; return; }
  const views = { login: vLogin, dashboard: vDashboard, subject: vSubject,
                  reader: vReader, chat: vChat, tickets: vTickets, new: vNewSubject };
  const fn = views[view];
  if (fn) fn(main, slug); else location.hash = '#/dashboard';
}

// ── Theme, menus ───────────────────────────────────────────────────────
function curTheme() { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'; }
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('sl-theme', t); } catch(e) {}
  var m = document.querySelector('meta[name="theme-color"]');
  if (m) m.setAttribute('content', t === 'light' ? '#f4f3fa' : '#0c0b14');
}
function toggleTheme() { setTheme(curTheme() === 'light' ? 'dark' : 'light'); }

function closeMenus(except) {
  document.querySelectorAll('.menu').forEach(function(m) {
    if (m === except) return;
    m.classList.add('hidden');
    var b = m.parentNode.querySelector('[aria-haspopup="true"]');
    if (b) b.setAttribute('aria-expanded', 'false');
    var row = m.closest('.menu-open');
    if (row) row.classList.remove('menu-open');
  });
}
function toggleMenu(btn, ev) {
  if (ev) ev.stopPropagation();
  var menu = btn.parentNode.querySelector('.menu');
  if (!menu) return;
  var willOpen = menu.classList.contains('hidden');
  closeMenus(menu);
  menu.classList.toggle('hidden', !willOpen);
  btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
  var row = btn.closest('.source-item, .ticket-item');
  if (row) row.classList.toggle('menu-open', willOpen);
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('.menuwrap')) closeMenus(null);
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeMenus(null);
});

function chatSide(open) {
  var sh = document.getElementById('chat-shell');
  if (sh) sh.classList.toggle('side-open', !!open);
}

// ── Navbar ─────────────────────────────────────────────────────────────
function updateNav(view, slug) {
  const nb = document.getElementById('navbar');
  if (view === 'login') { nb.classList.add('hidden'); return; }
  nb.classList.remove('hidden');
  const labels = {subject:'Источники', reader:'Читалка', chat:'Чат', tickets:'Билеты'};
  const sep = '<span class="sep" aria-hidden="true">/</span>';
  var crumb;
  if (slug && view !== 'dashboard') {
    var title = esc(S.titles[slug] || slug);
    crumb = sep + '<a href="#/dashboard">Предметы</a>' + sep +
      (view === 'subject' ? '<b>' + title + '</b>' :
        '<a href="#/subject/' + slug + '">' + title + '</a>' + sep + '<b>' + (labels[view] || view) + '</b>');
  } else {
    crumb = sep + '<b>Предметы</b>';
  }
  const name = S.user ? S.user.username : '';
  const roleLabel = S.user && S.user.role === 'admin' ? 'Администратор' : 'Студент';
  nb.innerHTML =
    '<a href="#/dashboard" class="logo">' + logoSvg() + '<span>StudyLab</span></a>' +
    '<div class="crumb" aria-label="Путь">' + crumb + '</div>' +
    '<div class="nav-user">' +
    '<button class="icon-btn" type="button" onclick="toggleTheme()" aria-label="Переключить тему">' + ic(IC.moon) + '</button>' +
    '<div class="menuwrap">' +
    '<button class="user-btn" type="button" aria-haspopup="true" aria-expanded="false" onclick="toggleMenu(this,event)">' +
    '<span class="avatar" aria-hidden="true">' + esc(name.charAt(0).toUpperCase()) + '</span><span class="user-name">' + esc(name) + '</span></button>' +
    '<div class="menu hidden" role="menu">' +
    '<div class="menu-label">' + roleLabel + '</div>' +
    (S.user && S.user.role !== 'admin' ? '<button type="button" role="menuitem" onclick="closeMenus(null);showPasswordReset()">Сменить пароль</button>' : '') +
    '<button type="button" role="menuitem" onclick="closeMenus(null);doLogout()">Выйти</button>' +
    '</div></div></div>';
}

async function ensureTitle(view, slug) {
  if (!slug || S.titles[slug] || !S.user) return;
  try {
    const r = await fetch('/api/subjects/' + slug, {credentials:'include'});
    if (!r.ok) return;
    const s = await r.json();
    S.titles[slug] = s.title || slug;
    if (location.hash.indexOf('/' + slug) > -1) updateNav(view, slug);
  } catch(e) {}
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
    '<button class="icon-btn" type="button" onclick="toggleTheme()" aria-label="Переключить тему" style="position:fixed;top:16px;right:16px">' + ic(IC.moon) + '</button>' +
    '<div class="glass login-card"><div class="bar" aria-hidden="true"></div><div class="body">' +
    '<div class="login-title">StudyLab</div>' +
    '<div class="login-sub">Персональная образовательная среда · Биофак МГУ</div>' +
    '<form id="login-form">' +
    '<div class="form-group"><label class="form-label" for="u">Логин</label>' +
    '<input type="text" id="u" placeholder="Введи логин" autocomplete="username"></div>' +
    '<div class="form-group"><label class="form-label" for="p">Пароль</label>' +
    '<input type="password" id="p" placeholder="Введи пароль" autocomplete="current-password"></div>' +
    '<div id="lerr" class="form-error hidden" role="alert"></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;min-height:54px">Войти</button>' +
    '</form>' +
    '<div style="text-align:center;margin-top:8px">' +
    '<button type="button" class="btn btn-ghost btn-sm" style="border:none;background:none;color:var(--muted)" id="btn-forgot">Забыла пароль?</button>' +
    '</div></div></div></div>';
  document.getElementById('btn-forgot').addEventListener('click', function() {
    toast('Войдите в аккаунт, затем запросите смену пароля в меню профиля', 'info');
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
function _examBadge(examDate) {
  if (!examDate) return '';
  var today = new Date(); today.setHours(0,0,0,0);
  var exam = new Date(examDate); exam.setHours(0,0,0,0);
  var diff = Math.round((exam - today) / 86400000);
  if (diff < 0) return '<span class="badge badge-dim badge-dot">прошёл</span>';
  if (diff === 0) return '<span class="badge badge-red badge-dot">сегодня</span>';
  var cls = diff <= 3 ? 'badge-red' : (diff <= 7 ? 'badge-yellow' : 'badge-dim');
  return '<span class="badge ' + cls + ' badge-dot">через ' + diff + ' ' + plural(diff, ['день','дня','дней']) + '</span>';
}

function _subjectCardBtn(s) {
  if (!s.source_count) return '<a href="#/new" class="btn btn-primary btn-sm">Подготовить</a>';
  if (!s.ticket_count) return '<a href="#/tickets/' + s.slug + '" class="btn btn-ghost btn-sm">Добавить билеты</a>';
  return '<a href="#/tickets/' + s.slug + '" class="btn btn-primary btn-sm">Открыть</a>';
}

function _renderSubjectCard(s) {
  var pct = s.ticket_count ? Math.round(s.answered_count / s.ticket_count * 100) : 0;
  var unanswered = s.ticket_count - s.answered_count;
  var badge = _examBadge(s.exam_date);
  var semBadge = s.semester ? '<span class="badge badge-blue">' + s.semester + ' сем.</span>' : '<span class="badge badge-dim">Укажите семестр</span>';
  var meta = s.ticket_count
    ? (s.answered_count + ' из ' + s.ticket_count + ' ' + plural(s.ticket_count, ['билета','билетов','билетов']) + (unanswered > 0 ? ' · ' + unanswered + ' без ответа' : ''))
    : (s.source_count + ' ' + plural(s.source_count, ['источник','источника','источников']));
  return '<div class="glass subject-card" style="cursor:default">' +
    '<div class="card-top">' + semBadge + badge + '</div>' +
    '<div class="card-title">' + esc(s.title) + '</div>' +
    '<div><div class="progress" style="margin-top:0"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
    '<div class="card-meta" style="margin-top:8px">' + esc(meta) + '</div></div>' +
    '<div style="display:flex;align-items:center;gap:8px;justify-content:space-between">' +
    _subjectCardBtn(s) +
    '<div class="menuwrap"><button class="icon-btn" type="button" aria-haspopup="true" aria-expanded="false" aria-label="Действия с предметом" onclick="toggleMenu(this,event)">' + ic(IC.dots, 20, true) + '</button>' +
    '<div class="menu hidden" role="menu">' +
    '<a role="menuitem" href="#/subject/' + s.slug + '" onclick="closeMenus(null)">Источники</a>' +
    '<a role="menuitem" href="#/tickets/' + s.slug + '" onclick="closeMenus(null)">Билеты</a>' +
    '<a role="menuitem" href="#/chat/' + s.slug + '" onclick="closeMenus(null)">Чат</a>' +
    '<button type="button" role="menuitem" onclick="closeMenus(null);showEditSubject(\'' + s.slug + '\',\'' + esc(s.title).replace(/'/g,"&#39;") + '\',' + (s.semester||0) + ',\'' + esc(s.exam_date||'') + '\',\'' + esc(s.description||'').replace(/'/g,"&#39;") + '\')">Изменить</button>' +
    '</div></div></div>' +
    '</div>';
}

async function vDashboard(main) {
  main.innerHTML = '<div class="page">' +
    '<div class="section-header" style="margin-bottom:16px">' +
    '<h1 class="section-title">Предметы</h1>' +
    '<button class="btn btn-primary btn-sm" id="btn-add-subj">+ Новый предмет</button>' +
    '</div>' +
    '<div id="dash-tabs" class="tabs" role="tablist" style="margin-bottom:16px"></div>' +
    '<div style="margin-bottom:20px"><input type="text" id="dash-search" placeholder="Поиск по названию…" style="max-width:360px"></div>' +
    '<div id="dash-content"><div class="text-muted text-sm"><div class="spinner"></div></div></div>' +
    '</div>';

  document.getElementById('btn-add-subj').addEventListener('click', function() {
    var sem = 0;
    try { sem = parseInt(localStorage.getItem('sl-semester') || '0') || 0; } catch(e) {}
    location.hash = '#/new';
  });

  var allSubjects = [];
  var activeSem = 0;

  function detectSemester(list) {
    var today = new Date(); today.setHours(0,0,0,0);
    // find highest semester with a future exam_date
    var withFuture = list.filter(function(s) { return s.semester > 0 && s.exam_date && new Date(s.exam_date) >= today; });
    if (withFuture.length) {
      return Math.max.apply(null, withFuture.map(function(s) { return s.semester; }));
    }
    var withSem = list.filter(function(s) { return s.semester > 0; });
    if (withSem.length) {
      return Math.max.apply(null, withSem.map(function(s) { return s.semester; }));
    }
    return 0;
  }

  function getSemesters(list) {
    var set = {};
    list.forEach(function(s) { if (s.semester > 0) set[s.semester] = true; });
    return Object.keys(set).map(Number).sort(function(a,b) { return b - a; });
  }

  function renderTabs(semesters, current) {
    var tabs = document.getElementById('dash-tabs');
    if (!tabs) return;
    var html = '<button class="tab' + (current === 0 ? ' active' : '') + '" onclick="dashSetSem(0)">Все семестры</button>';
    semesters.forEach(function(sem) {
      html += '<button class="tab' + (current === sem ? ' active' : '') + '" onclick="dashSetSem(' + sem + ')">' + sem + ' семестр</button>';
    });
    tabs.innerHTML = html;
  }

  function renderContent(list, sem, query) {
    var today = new Date(); today.setHours(0,0,0,0);
    var filtered = list.filter(function(s) {
      if (sem > 0 && s.semester !== sem) return false;
      if (query && s.title.toLowerCase().indexOf(query.toLowerCase()) === -1) return false;
      return true;
    });

    var active = [], past = [];
    filtered.forEach(function(s) {
      if (s.exam_date && new Date(s.exam_date) < today) { past.push(s); }
      else { active.push(s); }
    });

    // Sort active by exam_date asc, no date at end
    active.sort(function(a,b) {
      if (!a.exam_date && !b.exam_date) return 0;
      if (!a.exam_date) return 1;
      if (!b.exam_date) return -1;
      return a.exam_date < b.exam_date ? -1 : 1;
    });
    // Past: sorted by exam_date desc
    past.sort(function(a,b) { return a.exam_date > b.exam_date ? -1 : 1; });

    var content = document.getElementById('dash-content');
    if (!content) return;

    if (!filtered.length) {
      content.innerHTML = '<div class="empty">' + ic(IC.flask, 40) + '<b>Предметов нет</b><span>Попробуйте другой семестр или нажмите «+ Новый предмет».</span></div>';
      return;
    }

    var html = '';
    if (active.length) {
      html += '<div class="card-grid" id="dash-grid">' + active.map(_renderSubjectCard).join('') + '</div>';
    }
    if (past.length) {
      html += '<details style="margin-top:32px"><summary style="cursor:pointer;color:var(--muted);font-size:.9375rem;font-weight:500;padding:8px 0;list-style:none;display:flex;align-items:center;gap:8px">' +
        ic(IC.chev, 16) + 'Прошедшие (' + past.length + ')</summary>' +
        '<div class="card-grid" style="margin-top:16px">' + past.map(_renderSubjectCard).join('') + '</div></details>';
    }
    if (!active.length && !past.length) {
      html = '<div class="empty">' + ic(IC.flask, 40) + '<b>Предметов нет</b><span>Нажмите «+ Новый предмет».</span></div>';
    }
    content.innerHTML = html;
  }

  window.dashSetSem = function(sem) {
    activeSem = sem;
    try { if (sem > 0) localStorage.setItem('sl-semester', sem); } catch(e) {}
    var sems = getSemesters(allSubjects);
    renderTabs(sems, activeSem);
    var q = '';
    var si = document.getElementById('dash-search');
    if (si) q = si.value.trim();
    renderContent(allSubjects, activeSem, q);
  };

  document.getElementById('dash-search').addEventListener('input', function() {
    renderContent(allSubjects, activeSem, this.value.trim());
  });

  try {
    const r = await api('/api/subjects');
    allSubjects = await r.json();
    allSubjects.forEach(function(s) { S.titles[s.slug] = s.title; });

    var storedSem = 0;
    try { storedSem = parseInt(localStorage.getItem('sl-semester') || '0') || 0; } catch(e) {}
    if (storedSem > 0 && allSubjects.some(function(s) { return s.semester === storedSem; })) {
      activeSem = storedSem;
    } else {
      activeSem = detectSemester(allSubjects);
      if (activeSem > 0) { try { localStorage.setItem('sl-semester', activeSem); } catch(e) {} }
    }

    var sems = getSemesters(allSubjects);
    renderTabs(sems, activeSem);
    renderContent(allSubjects, activeSem, '');
  } catch(e) { toast('Ошибка загрузки', 'error'); }
}

function showEditSubject(slug, title, semester, examDate, description) {
  var semOptions = '<option value="0">— не указан —</option>';
  for (var si = 1; si <= 12; si++) {
    semOptions += '<option value="' + si + '"' + (si === semester ? ' selected' : '') + '>' + si + ' семестр</option>';
  }
  var ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML =
    '<div class="glass modal">' +
    '<div class="modal-title">Изменить предмет</div>' +
    '<form id="edit-subj-form">' +
    '<div class="form-group"><label class="form-label">Название</label>' +
    '<input type="text" id="es-title" value="' + esc(title) + '" required></div>' +
    '<div class="form-group"><label class="form-label">Семестр</label>' +
    '<select id="es-semester">' + semOptions + '</select></div>' +
    '<div class="form-group"><label class="form-label">Дата экзамена</label>' +
    '<input type="date" id="es-exam-date" value="' + esc(examDate) + '"></div>' +
    '<div class="form-group"><label class="form-label">Описание</label>' +
    '<textarea id="es-desc" rows="2">' + esc(description) + '</textarea></div>' +
    '<div class="flex gap" style="margin-top:4px">' +
    '<button type="button" class="btn btn-ghost" id="es-cancel">Отмена</button>' +
    '<button type="submit" class="btn btn-primary">Сохранить</button>' +
    '</div></form></div>';
  document.body.appendChild(ov);
  ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
  document.getElementById('es-cancel').addEventListener('click', function() { ov.remove(); });
  document.getElementById('edit-subj-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    var fd = new FormData();
    fd.append('title', document.getElementById('es-title').value);
    fd.append('semester', document.getElementById('es-semester').value);
    fd.append('exam_date', document.getElementById('es-exam-date').value);
    fd.append('description', document.getElementById('es-desc').value);
    var r = await api('/api/subjects/' + slug, {method:'PUT', body:fd});
    if (r.ok) {
      toast('Предмет обновлён', 'success');
      ov.remove();
      vDashboard(document.getElementById('main'));
    } else {
      var err = await r.json();
      toast(err.detail || 'Ошибка', 'error');
    }
  });
  setTimeout(function() { var t = document.getElementById('es-title'); if(t) t.focus(); }, 50);
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
  S.titles[slug] = subject.title || slug;
  updateNav('subject', slug);
  main.innerHTML =
    '<div class="page">' +
    '<div class="section-header">' +
    '<div style="display:flex;flex-direction:column;gap:12px;min-width:0">' +
    '<h1 class="section-title">' + esc(subject.title) + '</h1>' +
    (subject.year ? '<div class="chips"><span class="badge badge-blue">' + subject.year + ' курс</span></div>' : '') +
    '</div>' +
    '<div class="flex gap" style="flex-wrap:wrap">' +
    '<a href="#/reader/' + slug + '" class="btn btn-ghost btn-sm">Читалка</a>' +
    '<a href="#/chat/' + slug + '" class="btn btn-ghost btn-sm">Чат</a>' +
    '<a href="#/tickets/' + slug + '" class="btn btn-ghost btn-sm">Билеты</a>' +
    '</div></div>' +
    '<div class="tabs" role="tablist" aria-label="Разделы предмета">' +
    '<button class="tab active" id="tab-btn-src" role="tab" aria-selected="true" onclick="switchTab(\'src\',this)">Источники</button>' +
    '<button class="tab" id="tab-btn-srch" role="tab" aria-selected="false" onclick="switchTab(\'srch\',this)">Поиск</button>' +
    '</div>' +
    '<div id="tab-src"></div>' +
    '<div id="tab-srch" class="hidden">' +
    '<input type="text" id="srch-input" aria-label="Поисковый запрос" placeholder="Семантический поиск по источникам… (Enter)">' +
    '<div id="srch-res" class="mt"></div>' +
    '</div>' +
    '</div>';
  setupSearch(slug);
  await loadSources(slug);
}

function switchTab(tab, btn) {
  document.querySelectorAll('.tab').forEach(function(t) {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
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
            '<span class="search-score">Совпадение ' + Math.round(h.score * 100) + '%</span>' +
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
    const [srcR, imgR] = await Promise.all([
      api('/api/subjects/' + slug + '/sources'),
      api('/api/subjects/' + slug + '/images').catch(function() { return null; })
    ]);
    const srcs = await srcR.json();
    var imgsBySource = {};
    if (imgR && imgR.ok) {
      try {
        var imgs = await imgR.json();
        imgs.forEach(function(img) {
          if (!imgsBySource[img.source_slug]) imgsBySource[img.source_slug] = {total:0, described:0, pending:0};
          imgsBySource[img.source_slug].total++;
          if (img.status === 'described') imgsBySource[img.source_slug].described++;
          if (img.status === 'pending') imgsBySource[img.source_slug].pending++;
        });
      } catch(e) {}
    }
    let html = '';
    html += '<div class="drop-zone" id="drop-zone" role="button" tabindex="0" aria-label="Загрузить файлы">' +
      '<div class="drop-zone-icon">' + ic(IC.upload, 28) + '</div>' +
      '<div><strong>Перетащите файлы сюда</strong> или нажмите для выбора</div>' +
      '<div class="drop-zone-sub">PDF, DOCX, TXT, MD · можно сразу много</div>' +
      '<input type="file" id="file-input" style="display:none" accept=".pdf,.docx,.doc,.txt,.md" multiple>' +
      '</div>';
    html += '<div class="source-list mt" id="src-list">';
    if (!srcs.length) {
      html += '<div class="empty">' + ic(IC.doc, 36) + '<b>Источников пока нет</b><span>Загрузите файлы выше.</span></div>';
    } else {
      html += srcs.map(function(s) { return renderSrc(s, slug, imgsBySource[s.slug]); }).join('');
    }
    html += '</div>';
    el.innerHTML = html;
    setupDrop(slug);
    var needPoll = srcs.some(function(s) { return s.status.startsWith('indexing') || s.status === 'uploaded'; });
    // Also poll if any images are still pending description
    if (!needPoll) {
      needPoll = Object.values(imgsBySource).some(function(v) { return v.pending > 0; });
    }
    if (needPoll) {
      pollLater(function() { loadSources(slug); }, 3000);
      S._resume = function() { loadSources(slug); };
    }
  } catch(e) { console.error('loadSources error:', e); el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки: ' + esc(e.message || e) + '</p>'; }
}

function renderSrc(s, slug, imgInfo) {
  const ext = (s.original_name || '').split('.').pop().toLowerCase();
  const st = s.status;
  const P = '\'' + slug + '\',\'' + s.slug + '\'';
  var statusBadge;
  if (st.startsWith('indexing:')) {
    var parts = st.split(':')[1].split(' ');
    var phase = parts[0];
    if (phase === 'embed' && parts[1]) {
      var nums = parts[1].split('/');
      var done = parseInt(nums[0]) || 0;
      var total = parseInt(nums[1]) || 1;
      var pct = Math.round(done / total * 100);
      statusBadge = '<span class="badge badge-yellow" style="min-width:150px"><span class="spinner" style="width:10px;height:10px"></span>' +
        '<span style="flex:1"><span class="progress" style="display:block;margin:0"><span class="progress-bar" style="display:block;width:' + pct + '%;background:var(--yellow)"></span></span></span>' +
        '<span style="font-size:.75rem">Читаю… ' + pct + '%</span></span>';
    } else {
      statusBadge = '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> Читаю…</span>';
    }
  } else if (st === 'error') {
    statusBadge = '<span class="badge badge-red badge-dot">Не удалось прочитать</span>';
  } else {
    statusBadge = {
      uploaded: '<span class="badge badge-blue badge-dot">Загружен</span>',
      indexing: '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> Читаю…</span>',
      indexed: '<span class="badge badge-green badge-dot">Прочитан</span>',
      active: '<span class="badge badge-green badge-dot">Прочитан</span>',
      inactive: '<span class="badge badge-dim badge-dot">Отключён</span>'
    }[st] || '<span class="badge badge-blue">' + esc(st) + '</span>';
  }
  var primary = '', toggle = '', items = '';
  var canRead = (st === 'active' || st === 'indexed' || st === 'inactive');
  if (st === 'error') {
    primary = '<button class="btn btn-primary btn-sm" type="button" onclick="srcAction(' + P + ',\'index\')">Попробовать снова</button>';
  }
  if (canRead) {
    var on = st === 'active';
    toggle = '<button class="sw" type="button" role="switch" aria-checked="' + on + '" aria-label="Использовать источник в ответах" onclick="srcAction(' + P + ',\'' + (on ? 'deactivate' : 'activate') + '\')"><span class="knob"></span><span>' + (on ? 'Включён' : 'Выключен') + '</span></button>';
    items += '<button type="button" role="menuitem" onclick="closeMenus(null);srcAction(' + P + ',\'index\')">Прочитать заново</button>';
  }
  items += '<button type="button" role="menuitem" onclick="closeMenus(null);renameSrc(' + P + ',\'' + esc(s.title).replace(/'/g,'\\&#39;') + '\')">Переименовать</button>';
  items += '<button type="button" role="menuitem" class="danger" onclick="closeMenus(null);delSrc(' + P + ')">Удалить</button>';
  var readerLink = canRead ? '<a href="#/reader/' + slug + '" class="btn btn-ghost btn-sm">Читать</a>' : '';
  var kebab = '<div class="menuwrap"><button class="icon-btn" type="button" aria-haspopup="true" aria-expanded="false" aria-label="Действия с источником" onclick="toggleMenu(this,event)">' + ic(IC.dots, 20, true) + '</button>' +
    '<div class="menu hidden" role="menu">' + items + '</div></div>';
  var imgBadge = '';
  if (imgInfo && imgInfo.total > 0 && (st === 'active' || st === 'indexed' || st === 'inactive')) {
    if (imgInfo.pending > 0) {
      imgBadge = ' · <span style="color:var(--yellow);font-size:.8125rem"><span class="spinner" style="width:8px;height:8px;border-width:1.5px;vertical-align:middle;margin-right:3px"></span>Иллюстрации: ' + imgInfo.described + '/' + imgInfo.total + '</span>';
    } else if (imgInfo.described > 0) {
      imgBadge = ' · <span style="color:var(--muted);font-size:.8125rem">Иллюстрации: ' + imgInfo.described + '</span>';
    }
  }
  return '<div class="glass source-item" id="si-' + s.slug + '">' +
    '<div class="source-icon">' + esc((ext || 'file').slice(0, 4).toUpperCase()) + '</div>' +
    '<div class="source-info">' +
    '<div class="source-name">' + esc(s.title) + '</div>' +
    '<div class="source-meta">' + esc(s.original_name) + (s.chunk_count ? ' · ' + s.chunk_count + ' чанков' : '') + imgBadge + '</div>' +
    '</div>' +
    statusBadge +
    '<div class="source-actions">' + primary + toggle + readerLink + kebab + '</div>' +
    '</div>';
}

function setupDrop(slug) {
  const zone = document.getElementById('drop-zone');
  const inp = document.getElementById('file-input');
  if (!zone || !inp) return;
  zone.addEventListener('click', function(e) { if (e.target !== inp) inp.click(); });
  zone.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inp.click(); }
  });
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
    '<div class="three-col" style="min-height:calc(100vh - var(--nav-h))">' +
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
    '<div class="chat-shell" id="chat-shell">' +
    '<div class="chat-scrim" onclick="chatSide(false)"></div>' +
    '<aside class="conv-sidebar" id="conv-sidebar" aria-label="Беседы">' +
    '<div class="conv-head">' +
    '<div class="flex gap"><button class="btn btn-primary btn-sm" style="flex:1" id="btn-new-conv">Новая беседа</button>' +
    '<button class="icon-btn chat-close" type="button" onclick="chatSide(false)" aria-label="Закрыть список бесед">' + ic(IC.close) + '</button></div>' +
    '<input type="text" id="conv-search" aria-label="Поиск по беседам" placeholder="Поиск по беседам…">' +
    '</div>' +
    '<div id="conv-list" style="flex:1;overflow-y:auto;padding:6px 0"></div>' +
    '<div class="conv-foot">' +
    '<button class="btn btn-danger btn-sm" style="width:100%" id="btn-del-all-conv">Удалить все беседы</button>' +
    '</div>' +
    '</aside>' +
    '<div class="chat-layout">' +
    '<div class="chat-bar"><button class="btn btn-ghost btn-sm" type="button" onclick="chatSide(true)">' + ic(IC.menu, 18) + 'Беседы</button></div>' +
    '<div class="chat-messages" id="chat-msgs">' +
    '<p class="text-muted text-sm" style="text-align:center;padding:20px">Выберите беседу или начните новую</p>' +
    '</div>' +
    '<div class="chat-input-area">' +
    '<div class="chat-scope"><span class="dot" aria-hidden="true"></span><b>Ищу по всем предметам</b><span>в активных источниках</span></div>' +
    '<div id="img-bar" class="img-preview-bar hidden"></div>' +
    '<div class="chat-input-row">' +
    '<button class="icon-btn" type="button" id="btn-photo" title="Прикрепить фото конспекта" aria-label="Прикрепить фото конспекта">' + ic(IC.camera) + '</button>' +
    '<input type="file" id="photo-inp" accept="image/*" style="display:none">' +
    '<textarea id="chat-inp" placeholder="Задайте вопрос по материалам…" rows="1" aria-label="Вопрос ассистенту"></textarea>' +
    '<button class="btn btn-primary" id="btn-send" style="flex-shrink:0;min-height:48px" aria-label="Отправить">' + ic(IC.send, 18) + '<span class="send-label">Отправить</span></button>' +
    '</div>' +
    '<div class="chat-hint">' +
    '<span>Shift+Enter — отправить</span>' +
    '</div></div></div></div>';

  await loadConvList(slug);

  document.getElementById('btn-new-conv').addEventListener('click', function() {
    chatSide(false);
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
        bar.innerHTML = '<span class="badge badge-blue" style="font-size:.75rem">OCR</span>' +
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
  chatSide(false);
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
    '<div class="msg-avatar" aria-hidden="true">' + (role === 'user' ? esc(((S.user && S.user.username) || 'Я').charAt(0).toUpperCase()) : 'S') + '</div>' +
    '<div class="msg-bubble">' + (content ? md(content) : '') + '</div>';
  msgsEl.appendChild(div);
  if (content) renderMath(div.querySelector('.msg-bubble'));
  return div;
}

// ── Tickets ────────────────────────────────────────────────────────────

// State for ticket list screen
var _TK = { all: [], selected: new Set(), filter: 'all', query: '' };

function _tkStatusBadge(t) {
  var st = t.status;
  var hasAnswer = t.answer && t.answer.length > 0;
  if (st === 'generating') return '<span class="badge badge-yellow badge-dot">Пишу\u2026</span>';
  if (st === 'queued')     return '<span class="badge badge-blue badge-dot">В очереди</span>';
  if (st === 'error')      return '<span class="badge badge-red badge-dot">Ошибка</span>';
  if (hasAnswer)           return '<span class="badge badge-green badge-dot">Готов</span>';
  return '<span class="badge badge-dim badge-dot">Нет ответа</span>';
}

function _tkMatchFilter(t) {
  var hasAnswer = t.answer && t.answer.length > 0;
  if (_TK.filter === 'noanswer' && hasAnswer) return false;
  if (_TK.filter === 'ready' && !hasAnswer) return false;
  if (_TK.query) {
    var q = _TK.query.toLowerCase();
    if (t.question.toLowerCase().indexOf(q) === -1) return false;
  }
  return true;
}

function _tkUpdateBulkBar(slug) {
  var bar = document.getElementById('tk-bulk-bar');
  if (!bar) return;
  var n = _TK.selected.size;
  var total = _TK.all.length;
  var selCounter = document.getElementById('tk-sel-counter');
  if (selCounter) selCounter.textContent = n > 0 ? ('Выбрано ' + n + ' из ' + total) : '';
  if (n > 0) {
    bar.classList.remove('hidden');
    var prepBtn = document.getElementById('tk-btn-prep');
    if (prepBtn) prepBtn.textContent = 'Подготовить ответы (' + n + ')';
  } else {
    bar.classList.add('hidden');
  }
}

function _tkUpdateSelectAllState() {
  var cb = document.getElementById('tk-sel-all');
  if (!cb) return;
  var visible = _TK.all.filter(_tkMatchFilter);
  var allChecked = visible.length > 0 && visible.every(function(t) { return _TK.selected.has(t.id); });
  cb.checked = allChecked;
  cb.indeterminate = !allChecked && visible.some(function(t) { return _TK.selected.has(t.id); });
}

function _tkRenderList(slug) {
  var el = document.getElementById('t-list');
  if (!el) return;
  var visible = _TK.all.filter(_tkMatchFilter);
  if (!_TK.all.length) {
    el.innerHTML = '<div class="empty">' + ic(IC.doc, 36) + '<b>Билетов пока нет. Вставьте список вопросов или загрузите файл</b></div>';
    return;
  }
  if (!visible.length) {
    el.innerHTML = '<div class="empty">' + ic(IC.doc, 28) + '<b>Ничего не найдено</b><span>Попробуйте другой фильтр или запрос</span></div>';
    return;
  }
  el.innerHTML = visible.map(function(t, idx) {
    var hasAnswer = t.answer && t.answer.length > 0;
    var checked = _TK.selected.has(t.id) ? ' checked' : '';
    var pos = t.position || (idx + 1);
    var P = '\'' + slug + '\',' + t.id;
    var menuItems =
      '<button type="button" role="menuitem" onclick="closeMenus(null);tkEditInline(' + t.id + ')">Редактировать</button>' +
      (hasAnswer ? '<button type="button" role="menuitem" onclick="closeMenus(null);genTicket(' + P + ')">Обновить ответ</button>' : '') +
      (hasAnswer ? '<a role="menuitem" href="/api/subjects/' + slug + '/tickets/' + t.id + '/export" target="_blank" onclick="closeMenus(null)">Скачать HTML</a>' : '') +
      '<button type="button" role="menuitem" class="danger" onclick="closeMenus(null);delTicket(' + P + ')">Удалить</button>';
    return '<div class="glass ticket-item" id="tk-' + t.id + '" data-id="' + t.id + '">' +
      '<div class="ticket-head">' +
      '<input type="checkbox" class="tk-cb" data-id="' + t.id + '"' + checked + ' style="width:20px;height:20px;flex:0 0 auto;cursor:pointer;accent-color:var(--accent)" aria-label="Выбрать билет ' + pos + '">' +
      '<span style="min-width:28px;text-align:right;font-size:.8125rem;color:var(--dim);flex-shrink:0">' + pos + '</span>' +
      '<div class="ticket-q" id="tkq-' + t.id + '" ondblclick="tkEditInline(' + t.id + ')" style="-webkit-line-clamp:2;display:-webkit-box;-webkit-box-orient:vertical;overflow:hidden;cursor:text" title="Двойной клик — редактировать">' + esc(t.question) + '</div>' +
      _tkStatusBadge(t) +
      '<div class="menuwrap"><button class="icon-btn" type="button" aria-haspopup="true" aria-expanded="false" aria-label="Действия с билетом" onclick="toggleMenu(this,event)">' + ic(IC.dots, 20, true) + '</button>' +
      '<div class="menu hidden" role="menu">' + menuItems + '</div></div>' +
      '</div>' +
      (hasAnswer ? '<div class="ticket-answer" style="display:none">' + md(t.answer) + '</div>' : '') +
      '</div>';
  }).join('');
  // Attach checkbox listeners
  el.querySelectorAll('.tk-cb').forEach(function(cb) {
    cb.addEventListener('change', function() {
      var id = parseInt(this.dataset.id);
      if (this.checked) { _TK.selected.add(id); } else { _TK.selected.delete(id); }
      _tkUpdateBulkBar(slug);
      _tkUpdateSelectAllState();
    });
  });
  // Click on answer text toggles expand
  el.querySelectorAll('.ticket-answer').forEach(function(ans) {
    ans.style.cursor = 'pointer';
    ans.addEventListener('click', function() {
      var hidden = ans.style.display === 'none' || ans.style.display === '';
      // find toggle in same ticket-item
      var item = ans.closest('.ticket-item');
      var togBtn = item && item.querySelector('.toggle-answer');
      if (togBtn) { toggleAnswer(togBtn); return; }
      ans.style.display = (ans.style.display === 'none') ? '' : 'none';
    });
  });
  renderMath(el);
  _tkUpdateSelectAllState();
}

function tkEditInline(tid) {
  var qEl = document.getElementById('tkq-' + tid);
  if (!qEl) return;
  var current = qEl.textContent;
  var inp = document.createElement('input');
  inp.type = 'text';
  inp.value = current;
  inp.style.cssText = 'flex:1;min-width:0;font-size:.9375rem;font-family:inherit;padding:4px 8px;min-height:36px';
  qEl.replaceWith(inp);
  inp.focus();
  inp.select();
  var slug = (location.hash.match(/\/tickets\/([^/?]+)/) || [])[1] || '';
  async function saveTkEdit() {
    var newQ = inp.value.trim();
    if (!newQ || newQ === current) {
      // restore
      var restored = document.createElement('div');
      restored.className = 'ticket-q';
      restored.id = 'tkq-' + tid;
      restored.setAttribute('ondblclick', 'tkEditInline(' + tid + ')');
      restored.style.cssText = '-webkit-line-clamp:2;display:-webkit-box;-webkit-box-orient:vertical;overflow:hidden;cursor:text';
      restored.setAttribute('title', 'Двойной клик — редактировать');
      restored.textContent = current;
      inp.replaceWith(restored);
      return;
    }
    var fd = new FormData(); fd.append('question', newQ);
    var r = await api('/api/subjects/' + slug + '/tickets/' + tid, {method:'PUT', body:fd});
    if (r.ok) {
      var t = _TK.all.find(function(x) { return x.id === tid; });
      if (t) t.question = newQ;
      toast('Сохранено', 'success');
      _tkRenderList(slug);
    } else {
      toast('Ошибка сохранения', 'error');
      var restEl = document.createElement('div');
      restEl.className = 'ticket-q';
      restEl.id = 'tkq-' + tid;
      restEl.setAttribute('ondblclick', 'tkEditInline(' + tid + ')');
      restEl.style.cssText = '-webkit-line-clamp:2;display:-webkit-box;-webkit-box-orient:vertical;overflow:hidden;cursor:text';
      restEl.setAttribute('title', 'Двойной клик — редактировать');
      restEl.textContent = current;
      if (inp.parentNode) inp.replaceWith(restEl);
    }
  }
  inp.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); saveTkEdit(); }
    if (e.key === 'Escape') {
      var r2 = document.createElement('div'); r2.className = 'ticket-q'; r2.id = 'tkq-' + tid;
      r2.setAttribute('ondblclick', 'tkEditInline(' + tid + ')');
      r2.style.cssText = '-webkit-line-clamp:2;display:-webkit-box;-webkit-box-orient:vertical;overflow:hidden;cursor:text';
      r2.setAttribute('title', 'Двойной клик — редактировать');
      r2.textContent = current; inp.replaceWith(r2);
    }
  });
  inp.addEventListener('blur', saveTkEdit);
}

function showPasteListModal(slug) {
  var ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML =
    '<div class="glass modal" style="max-width:580px">' +
    '<div class="modal-title">Вставить список</div>' +
    '<p class="text-sm text-muted" style="margin-bottom:12px">Проверьте и поправьте перед сохранением</p>' +
    '<textarea id="paste-q" rows="10" placeholder="1. Первый вопрос\n2. Второй вопрос\n\u2014 или любой формат нумерации" style="font-size:.875rem"></textarea>' +
    '<div id="paste-preview" class="text-muted text-sm" style="margin-top:8px;min-height:1.4em"></div>' +
    '<div class="flex gap" style="margin-top:14px">' +
    '<button type="button" class="btn btn-ghost" id="paste-cancel">Отмена</button>' +
    '<button type="button" class="btn btn-primary" id="paste-save" disabled>Добавить билеты</button>' +
    '</div></div>';
  document.body.appendChild(ov);
  ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
  document.getElementById('paste-cancel').addEventListener('click', function() { ov.remove(); });

  var _pasteTimer = null;
  var _parsedList = [];

  function updatePreview() {
    var text = document.getElementById('paste-q').value;
    // Client-side quick count (split on numbered lines)
    var lines = text.split('\n').map(function(l) { return l.trim(); }).filter(Boolean);
    var count = lines.length;
    var prevEl = document.getElementById('paste-preview');
    var saveBtn = document.getElementById('paste-save');
    if (!text.trim()) {
      if (prevEl) prevEl.textContent = '';
      if (saveBtn) saveBtn.disabled = true;
      return;
    }
    if (prevEl) prevEl.textContent = 'Строк: ' + count + ' — нажмите «Добавить»';
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Добавить ' + count + ' билетов'; }
    _parsedList = lines;
  }

  var ta = document.getElementById('paste-q');
  ta.addEventListener('input', function() {
    clearTimeout(_pasteTimer);
    _pasteTimer = setTimeout(updatePreview, 200);
  });

  document.getElementById('paste-save').addEventListener('click', async function() {
    var text = document.getElementById('paste-q').value.trim();
    if (!text) return;
    var btn = this; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
    var fd = new FormData(); fd.append('questions', text);
    var r = await api('/api/subjects/' + slug + '/tickets/batch', {method:'POST', body:fd});
    if (r.ok) {
      var data = await r.json();
      var msg = 'Найдено ' + (data.count + (data.skipped || 0)) + ' вопросов';
      if (data.skipped) msg += ', добавлено ' + data.count + ', пропущено ' + data.skipped + ' дублей';
      else msg += ', добавлено ' + data.count;
      toast(msg, 'success');
      ov.remove();
      loadTickets(slug);
    } else {
      var err = await r.json();
      toast(err.detail || 'Ошибка', 'error');
      btn.disabled = false; btn.textContent = 'Добавить билеты';
    }
  });
  setTimeout(function() { ta.focus(); }, 50);
}

function showImportFileModal(slug) {
  var inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.txt,.md,.pdf,.docx,.doc,.jpg,.jpeg,.png,.webp';
  inp.style.display = 'none';
  document.body.appendChild(inp);
  inp.addEventListener('change', async function() {
    var file = inp.files[0];
    inp.remove();
    if (!file) return;
    toast('Загружаю и разбираю файл…', 'info');
    var fd = new FormData(); fd.append('file', file);
    var r;
    try {
      r = await api('/api/subjects/' + slug + '/tickets/import', {method:'POST', body:fd});
    } catch(e) { toast('Ошибка сети', 'error'); return; }
    if (!r.ok) {
      var err = await r.json();
      toast(err.detail || 'Ошибка разбора файла', 'error');
      return;
    }
    var data = await r.json();
    var qs = data.questions || [];
    if (!qs.length) { toast('Вопросов не найдено', 'error'); return; }
    // Detect flags: duplicates within file, duplicates vs existing, too short
    var existing = (_TK.all || []).map(function(t) { return t.question.trim().toLowerCase(); });
    var seenInFile = {};
    var flags = qs.map(function(q, i) {
      var low = q.trim().toLowerCase();
      var f = [];
      if (q.trim().length < 8) f.push('short');
      if (seenInFile[low]) f.push('dup-file');
      else if (existing.indexOf(low) >= 0) f.push('dup-existing');
      seenInFile[low] = true;
      return f;
    });
    var flagCount = flags.filter(function(f) { return f.length > 0; }).length;
    // Show preview/edit modal
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    var listHtml = qs.map(function(q, i) {
      var hasFlag = flags[i].length > 0;
      var checked = !hasFlag;
      var warn = '';
      if (flags[i].indexOf('dup-existing') >= 0) warn = '<span style="color:var(--yellow);font-size:.75rem">уже есть</span>';
      else if (flags[i].indexOf('dup-file') >= 0) warn = '<span style="color:var(--yellow);font-size:.75rem">дубль</span>';
      else if (flags[i].indexOf('short') >= 0) warn = '<span style="color:var(--yellow);font-size:.75rem">короткий</span>';
      return '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px' + (hasFlag ? ';opacity:.6' : '') + '">' +
        '<input type="checkbox" class="import-q-check" data-idx="' + i + '"' + (checked ? ' checked' : '') + ' style="margin-top:8px;min-width:18px;min-height:18px">' +
        '<span style="color:var(--dim);font-size:.8125rem;min-width:24px;padding-top:4px">' + (i+1) + '</span>' +
        '<input type="text" class="import-q-inp" value="' + esc(q) + '" style="flex:1;min-height:36px;font-size:.875rem">' +
        warn +
        '</div>';
    }).join('');
    var subtitle = flagCount > 0 ? '<div style="color:var(--yellow);font-size:.8125rem;margin-bottom:12px">' + flagCount + ' строк помечены (дубли или слишком короткие) — снимите галочку, чтобы пропустить</div>' : '';
    ov.innerHTML =
      '<div class="glass modal wide">' +
      '<div class="modal-title">Найдено ' + qs.length + ' вопросов — проверьте и поправьте перед сохранением</div>' +
      subtitle +
      '<div style="max-height:55vh;overflow-y:auto;padding-right:4px">' + listHtml + '</div>' +
      '<div class="flex gap" style="margin-top:16px">' +
      '<button type="button" class="btn btn-ghost" id="imp-cancel">Отмена</button>' +
      '<button type="button" class="btn btn-primary" id="imp-save">Добавить билеты</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
    document.getElementById('imp-cancel').addEventListener('click', function() { ov.remove(); });
    document.getElementById('imp-save').addEventListener('click', async function() {
      var inputs = ov.querySelectorAll('.import-q-inp');
      var checks = ov.querySelectorAll('.import-q-check');
      var lines = [];
      inputs.forEach(function(inp2, idx) { if (checks[idx] && checks[idx].checked) { var v = inp2.value.trim(); if (v) lines.push(v); } });
      if (!lines.length) { toast('Нет выбранных вопросов', 'info'); return; }
      var btn = this; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
      var fd2 = new FormData(); fd2.append('questions', lines.join('\n'));
      var r2 = await api('/api/subjects/' + slug + '/tickets/batch', {method:'POST', body:fd2});
      if (r2.ok) {
        var d2 = await r2.json();
        toast('Добавлено ' + d2.count + ' билетов' + (d2.skipped ? ', пропущено ' + d2.skipped + ' дублей' : ''), 'success');
        ov.remove();
        loadTickets(slug);
      } else {
        var e2 = await r2.json();
        toast(e2.detail || 'Ошибка', 'error');
        btn.disabled = false; btn.textContent = 'Добавить ' + qs.length + ' билетов';
      }
    });
  });
  inp.click();
}

async function vTickets(main, slug) {
  _TK.all = []; _TK.selected = new Set(); _TK.filter = 'all'; _TK.query = '';
  let subject = {title: slug};
  try { const r = await api('/api/subjects/' + slug); subject = await r.json(); } catch(e) {}
  S.titles[slug] = subject.title || slug;
  updateNav('tickets', slug);
  main.innerHTML =
    '<div class="page">' +
    // ── Header row
    '<div class="section-header" style="flex-wrap:wrap;gap:12px 24px">' +
    '<div style="display:flex;flex-direction:column;gap:8px">' +
    '<h1 class="section-title">' + esc(subject.title) + '</h1>' +
    '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">' +
    '<span id="tk-sel-counter" class="text-muted text-sm"></span>' +
    '<label style="display:flex;align-items:center;gap:8px;min-height:44px;cursor:pointer;font-size:.9375rem">' +
    '<input type="checkbox" id="tk-sel-all" style="width:18px;height:18px;accent-color:var(--accent)"> Все без ответа' +
    '</label>' +
    '<button type="button" class="btn btn-ghost btn-sm" id="tk-btn-desel" style="display:none">Снять выбор</button>' +
    '</div></div>' +
    '<div class="flex gap" style="flex-wrap:wrap">' +
    '<button class="btn btn-ghost btn-sm" type="button" id="btn-preview">Превью</button>' +
    '<a href="/api/subjects/' + slug + '/tickets/export" class="btn btn-ghost btn-sm" target="_blank">Скачать HTML</a>' +
    '</div></div>' +
    // ── Search + filter tabs
    '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:16px 0">' +
    '<input type="text" id="tk-search" placeholder="Поиск по билетам…" style="flex:1 1 200px;min-width:140px;max-width:400px">' +
    '<div class="chips">' +
    '<button type="button" class="btn btn-ghost btn-sm tk-filter-btn active" data-f="all">Все</button>' +
    '<button type="button" class="btn btn-ghost btn-sm tk-filter-btn" data-f="noanswer">Без ответа</button>' +
    '<button type="button" class="btn btn-ghost btn-sm tk-filter-btn" data-f="ready">Готовы</button>' +
    '</div></div>' +
    // ── Add area
    '<div class="ticket-add">' +
    '<input type="text" id="new-q" aria-label="Добавить вопрос" placeholder="Добавить вопрос…">' +
    '<button class="btn btn-primary btn-sm" style="flex-shrink:0" id="btn-add-t">Добавить</button>' +
    '<button class="btn btn-ghost btn-sm" style="flex-shrink:0" id="btn-paste-t">Вставить список</button>' +
    '<button class="btn btn-ghost btn-sm" style="flex-shrink:0" id="btn-import-t">Загрузить файл со списком</button>' +
    '</div>' +
    '<div id="t-list"><div class="text-muted text-sm"><div class="spinner"></div></div></div>' +
    // ── Bulk action bar
    '<div id="tk-bulk-bar" class="hidden" style="position:sticky;bottom:0;background:var(--nav-bg);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);border-top:1px solid var(--border);padding:12px 0;display:flex;gap:10px;align-items:center;margin-top:16px">' +
    '<button type="button" class="btn btn-primary" id="tk-btn-prep">Подготовить ответы</button>' +
    '<button type="button" class="btn btn-danger" id="tk-btn-bulk-del">Удалить</button>' +
    '</div>' +
    '</div>';

  // Add ticket
  async function addTicket() {
    var q = document.getElementById('new-q').value.trim();
    if (!q) return;
    var fd = new FormData(); fd.append('question', q);
    var r = await api('/api/subjects/' + slug + '/tickets', {method:'POST', body:fd});
    if (r.ok) { document.getElementById('new-q').value = ''; toast('Билет добавлен', 'success'); loadTickets(slug); }
    else toast('Ошибка', 'error');
  }
  document.getElementById('btn-add-t').addEventListener('click', addTicket);
  document.getElementById('new-q').addEventListener('keydown', function(e) { if (e.key === 'Enter') addTicket(); });

  // Paste list
  document.getElementById('btn-paste-t').addEventListener('click', function() { showPasteListModal(slug); });

  // Import from file
  document.getElementById('btn-import-t').addEventListener('click', function() { showImportFileModal(slug); });

  // Preview export
  document.getElementById('btn-preview').addEventListener('click', function() {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML =
      '<div class="glass modal wide">' +
      '<div class="flex" style="justify-content:space-between;align-items:center;margin-bottom:14px">' +
      '<div class="modal-title" style="margin:0">Превью экспорта</div>' +
      '<button class="icon-btn" type="button" id="pv-close" aria-label="Закрыть">' + ic(IC.close) + '</button></div>' +
      '<iframe class="preview-frame" title="Превью экспорта билетов" src="/api/subjects/' + slug + '/tickets/export?inline=1"></iframe>' +
      '</div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) { if (e.target === ov) ov.remove(); });
    document.getElementById('pv-close').addEventListener('click', function() { ov.remove(); });
  });

  // Select all (without answer)
  document.getElementById('tk-sel-all').addEventListener('change', function() {
    var visible = _TK.all.filter(_tkMatchFilter);
    if (this.checked) {
      // select all without answer in visible
      visible.forEach(function(t) { if (!t.answer || !t.answer.length) _TK.selected.add(t.id); });
    } else {
      _TK.selected.clear();
    }
    _tkRenderList(slug);
    _tkUpdateBulkBar(slug);
  });

  // Deselect
  var deselBtn = document.getElementById('tk-btn-desel');
  if (deselBtn) deselBtn.addEventListener('click', function() {
    _TK.selected.clear();
    _tkRenderList(slug);
    _tkUpdateBulkBar(slug);
  });

  // Filter tabs
  document.querySelectorAll('.tk-filter-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.tk-filter-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      _TK.filter = btn.dataset.f;
      _tkRenderList(slug);
      _tkUpdateSelectAllState();
    });
  });

  // Search
  var searchTimer = null;
  document.getElementById('tk-search').addEventListener('input', function() {
    clearTimeout(searchTimer);
    var val = this.value;
    searchTimer = setTimeout(function() {
      _TK.query = val.trim();
      _tkRenderList(slug);
      _tkUpdateSelectAllState();
    }, 120);
  });

  // Bulk prepare (stub for now — tasks 04/06)
  var prepBtn = document.getElementById('tk-btn-prep');
  if (prepBtn) prepBtn.addEventListener('click', function() {
    toast('Генерация ответов по ' + _TK.selected.size + ' билетам — будет доступна в следующем обновлении', 'info');
  });

  // Bulk delete
  var bulkDelBtn = document.getElementById('tk-btn-bulk-del');
  if (bulkDelBtn) bulkDelBtn.addEventListener('click', async function() {
    if (!_TK.selected.size) return;
    if (!confirm('Удалить ' + _TK.selected.size + ' билетов?')) return;
    var ids = Array.from(_TK.selected);
    var r = await api('/api/subjects/' + slug + '/tickets/bulk-delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ids: ids})
    });
    if (r.ok) {
      _TK.selected.clear();
      toast('Удалено билетов: ' + ids.length, 'success');
      loadTickets(slug);
    } else { toast('Ошибка удаления', 'error'); }
  });

  // Show desel button when selection changes
  function updateDeselBtn() {
    var b = document.getElementById('tk-btn-desel');
    if (b) b.style.display = _TK.selected.size > 0 ? '' : 'none';
  }
  var _origUpdateBulkBar = _tkUpdateBulkBar;
  window._tkUpdateBulkBar_orig = _tkUpdateBulkBar;

  await loadTickets(slug);
}

async function loadTickets(slug) {
  try {
    var r = await api('/api/subjects/' + slug + '/tickets');
    _TK.all = await r.json();
  } catch(e) {
    var el = document.getElementById('t-list');
    if (el) el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>';
    return;
  }
  // Remove stale selection ids
  _TK.selected = new Set(Array.from(_TK.selected).filter(function(id) {
    return _TK.all.some(function(t) { return t.id === id; });
  }));
  _tkRenderList(slug);
  _tkUpdateBulkBar(slug);
  _tkUpdateSelectAllState();
  // Update counter in header
  var counter = document.getElementById('tk-sel-counter');
  if (counter && _TK.selected.size === 0) counter.textContent = _TK.all.length + ' ' + plural(_TK.all.length, ['билет','билета','билетов']);
}

function toggleAnswer(btn) {
  var ticket = btn.closest('.ticket-item');
  var answer = ticket.querySelector('.ticket-answer');
  if (!answer) return;
  var hidden = answer.style.display === 'none';
  answer.style.display = hidden ? '' : 'none';
  btn.setAttribute('aria-expanded', hidden ? 'true' : 'false');
  btn.classList.toggle('open', hidden);
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
  ansEl.style.display = '';
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

// ── New Subject Wizard ─────────────────────────────────────────────────
function vNewSubject(main) {
  var wizSlug = null;
  var step = 1;

  function wizHTML(stepN, body, btns) {
    var pct = Math.round(stepN / 3 * 100);
    return '<div class="page" style="max-width:680px;margin:0 auto">' +
      '<div style="margin-bottom:24px">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">' +
      '<span class="text-muted text-sm">Шаг ' + stepN + ' из 3</span>' +
      '<a href="#/dashboard" class="btn btn-ghost btn-sm" style="min-height:36px;padding:0 12px">Отмена</a>' +
      '</div>' +
      '<div class="progress"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
      '</div>' +
      '<div class="glass" style="padding:28px 32px">' +
      body +
      '<div class="flex gap" style="margin-top:24px;flex-wrap:wrap">' + btns + '</div>' +
      '</div></div>';
  }

  function renderStep1() {
    var storedSem = 0;
    try { storedSem = parseInt(localStorage.getItem('sl-semester') || '0') || 0; } catch(e) {}
    var semOptions = '<option value="0">— не указан —</option>';
    for (var si = 1; si <= 12; si++) {
      semOptions += '<option value="' + si + '"' + (si === storedSem ? ' selected' : '') + '>' + si + ' семестр</option>';
    }
    main.innerHTML = wizHTML(1,
      '<h2 class="section-title" style="font-size:1.375rem;margin-bottom:20px">Новый предмет</h2>' +
      '<div class="form-group"><label class="form-label">Название</label>' +
      '<input type="text" id="wiz-title" placeholder="Микробиология" required></div>' +
      '<div class="form-group"><label class="form-label">Семестр</label>' +
      '<select id="wiz-semester">' + semOptions + '</select></div>' +
      '<div class="form-group"><label class="form-label">Дата экзамена</label>' +
      '<input type="date" id="wiz-exam-date"></div>' +
      '<div id="wiz-err" class="form-error hidden"></div>',
      '<span style="flex:1"></span>' +
      '<button class="btn btn-primary" id="wiz-next1">Дальше: материалы</button>'
    );
    setTimeout(function() {
      var inp = document.getElementById('wiz-title');
      if (inp) inp.focus();
    }, 50);
    document.getElementById('wiz-next1').addEventListener('click', async function() {
      var title = (document.getElementById('wiz-title').value || '').trim();
      if (!title) {
        var errEl = document.getElementById('wiz-err');
        errEl.textContent = 'Введите название предмета';
        errEl.classList.remove('hidden');
        return;
      }
      var semVal = parseInt(document.getElementById('wiz-semester').value) || 0;
      var examVal = (document.getElementById('wiz-exam-date').value || '').trim();
      var btn = this;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Создаю…';
      var fd = new FormData();
      fd.append('title', title);
      fd.append('description', '');
      fd.append('year', '0');
      fd.append('semester', semVal);
      fd.append('exam_date', examVal);
      try {
        var r = await api('/api/subjects', {method:'POST', body:fd});
        if (r.ok) {
          var data = await r.json();
          wizSlug = data.slug;
          S.titles[wizSlug] = title;
          if (semVal > 0) { try { localStorage.setItem('sl-semester', semVal); } catch(e) {} }
          step = 2;
          renderStep2();
        } else {
          var err = await r.json();
          var errEl = document.getElementById('wiz-err');
          errEl.textContent = err.detail || 'Ошибка создания предмета';
          errEl.classList.remove('hidden');
          btn.disabled = false;
          btn.textContent = 'Дальше: материалы';
        }
      } catch(e) {
        var errEl2 = document.getElementById('wiz-err');
        errEl2.textContent = 'Ошибка сети';
        errEl2.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = 'Дальше: материалы';
      }
    });
  }

  function renderStep2() {
    main.innerHTML = wizHTML(2,
      '<h2 class="section-title" style="font-size:1.375rem;margin-bottom:20px">Материалы</h2>' +
      '<div class="drop-zone" id="wiz-drop" role="button" tabindex="0" aria-label="Загрузить файлы">' +
      '<div class="drop-zone-icon">' + ic(IC.upload, 28) + '</div>' +
      '<div><strong>Перетащите файлы сюда</strong> или нажмите для выбора</div>' +
      '<div class="drop-zone-sub">PDF, DOCX, TXT, MD · можно сразу много</div>' +
      '<input type="file" id="wiz-file" style="display:none" accept=".pdf,.docx,.doc,.txt,.md" multiple>' +
      '</div>' +
      '<div class="source-list mt" id="wiz-src-list"></div>',
      '<button class="btn btn-ghost" id="wiz-back2">Назад</button>' +
      '<span style="flex:1"></span>' +
      '<button class="btn btn-ghost btn-sm" id="wiz-skip2">Пропустить</button>' +
      '<button class="btn btn-primary" id="wiz-next2" disabled>Дальше: список билетов</button>'
    );
    var wizPollTimer = null;

    function wizStatusBadge(st) {
      if (!st) return '';
      if (st.startsWith('indexing:')) {
        var parts = st.split(':')[1].split(' ');
        var phase = parts[0];
        if (phase === 'embed' && parts[1]) {
          var nums = parts[1].split('/');
          var pct = Math.round((parseInt(nums[0])||0) / (parseInt(nums[1])||1) * 100);
          return '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> Читаю… ' + pct + '%</span>';
        }
        return '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> Читаю…</span>';
      }
      return {
        uploaded: '<span class="badge badge-blue badge-dot">Загружен</span>',
        active: '<span class="badge badge-green badge-dot">Прочитан</span>',
        indexed: '<span class="badge badge-green badge-dot">Прочитан</span>',
        inactive: '<span class="badge badge-dim badge-dot">Отключён</span>',
        error: '<span class="badge badge-red badge-dot">Не удалось прочитать</span>'
      }[st] || '<span class="badge badge-blue">' + esc(st) + '</span>';
    }

    function checkNext() {
      var btn = document.getElementById('wiz-next2');
      if (!btn) return;
      var list = document.getElementById('wiz-src-list');
      var hasReady = list && (list.querySelector('.badge-green') !== null);
      btn.disabled = !hasReady;
    }

    async function wizPollSources() {
      if (!wizSlug || !document.getElementById('wiz-src-list')) return;
      try {
        var r = await api('/api/subjects/' + wizSlug + '/sources');
        var srcs = await r.json();
        var list = document.getElementById('wiz-src-list');
        if (!list) return;
        var needPoll = false;
        srcs.forEach(function(s) {
          var el = document.getElementById('wiz-si-' + s.slug);
          if (el) {
            var badgeEl = el.querySelector('.badge');
            if (badgeEl) badgeEl.outerHTML = wizStatusBadge(s.status);
          }
          if (s.status === 'uploaded' || s.status.startsWith('indexing')) needPoll = true;
        });
        checkNext();
        if (needPoll && document.getElementById('wiz-src-list')) {
          wizPollTimer = pollLater(wizPollSources, 2000);
          S._resume = wizPollSources;
        }
      } catch(e) {}
    }

    function addSrcRow(file, status, slug) {
      var list = document.getElementById('wiz-src-list');
      if (!list) return;
      var id = 'wiz-si-' + (slug || file.name.replace(/[^a-z0-9]/gi, '-'));
      var existing = document.getElementById(id);
      var badge = status === 'uploading'
        ? '<span class="badge badge-blue"><span class="spinner" style="width:10px;height:10px"></span> Загружается…</span>'
        : wizStatusBadge(status);
      var html = '<div class="glass source-item" id="' + id + '">' +
        '<div class="source-icon">' + esc((file.name.split('.').pop() || 'file').slice(0,4).toUpperCase()) + '</div>' +
        '<div class="source-info"><div class="source-name">' + esc(file.name) + '</div>' +
        '<div class="source-meta">' + file.name + '</div></div>' +
        badge + '</div>';
      if (existing) { existing.outerHTML = html; }
      else { list.insertAdjacentHTML('beforeend', html); }
    }

    async function wizUpload(files) {
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        addSrcRow(file, 'uploading', null);
        var fd = new FormData();
        fd.append('file', file);
        fd.append('title', file.name.replace(/\.[^.]+$/, ''));
        try {
          var r = await api('/api/subjects/' + wizSlug + '/upload', {method:'POST', body:fd});
          if (r.ok) {
            var data = await r.json();
            addSrcRow(file, 'uploaded', data.slug);
            checkNext();
            // Start polling for indexing progress
            clearTimeout(wizPollTimer);
            wizPollTimer = pollLater(wizPollSources, 2000);
          } else {
            toast(file.name + ': ошибка загрузки', 'error');
          }
        } catch(e) { toast(file.name + ': ошибка сети', 'error'); }
      }
    }

    var zone = document.getElementById('wiz-drop');
    var inp = document.getElementById('wiz-file');
    zone.addEventListener('click', function(e) { if (e.target !== inp) inp.click(); });
    zone.addEventListener('keydown', function(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inp.click(); } });
    zone.addEventListener('dragover', function(e) { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', function() { zone.classList.remove('drag-over'); });
    zone.addEventListener('drop', function(e) { e.preventDefault(); zone.classList.remove('drag-over'); wizUpload(e.dataTransfer.files); });
    inp.addEventListener('change', function() { wizUpload(inp.files); });

    document.getElementById('wiz-back2').addEventListener('click', function() {
      step = 1; renderStep1();
    });
    document.getElementById('wiz-skip2').addEventListener('click', function() {
      step = 3; renderStep3();
    });
    document.getElementById('wiz-next2').addEventListener('click', function() {
      step = 3; renderStep3();
    });
  }

  function renderStep3() {
    main.innerHTML = wizHTML(3,
      '<h2 class="section-title" style="font-size:1.375rem;margin-bottom:8px">Список билетов</h2>' +
      '<p class="text-muted text-sm" style="margin-bottom:16px">Один вопрос на строку. Нумерация удаляется автоматически. Можно пропустить и вернуться позже.</p>' +
      '<textarea id="wiz-tickets" rows="10" placeholder="1. Первый вопрос&#10;2. Второй вопрос&#10;3. Третий вопрос" style="font-size:.9375rem"></textarea>' +
      '<div id="wiz-t-err" class="form-error hidden"></div>',
      '<button class="btn btn-ghost" id="wiz-back3">Назад</button>' +
      '<span style="flex:1"></span>' +
      '<button class="btn btn-ghost btn-sm" id="wiz-skip3">Пропустить</button>' +
      '<button class="btn btn-primary" id="wiz-save3">Сохранить</button>'
    );
    document.getElementById('wiz-back3').addEventListener('click', function() {
      step = 2; renderStep2();
    });
    document.getElementById('wiz-skip3').addEventListener('click', function() {
      location.hash = '#/subject/' + wizSlug;
    });
    document.getElementById('wiz-save3').addEventListener('click', async function() {
      var text = (document.getElementById('wiz-tickets').value || '').trim();
      if (!text) { location.hash = '#/subject/' + wizSlug; return; }
      var btn = this;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Сохраняю…';
      var fd = new FormData();
      fd.append('questions', text);
      try {
        var r = await api('/api/subjects/' + wizSlug + '/tickets/batch', {method:'POST', body:fd});
        if (r.ok) {
          var data = await r.json();
          toast(data.count + ' ' + plural(data.count, ['вопрос', 'вопроса', 'вопросов']) + ' сохранено', 'success');
        } else {
          var err = await r.json();
          toast(err.detail || 'Ошибка сохранения', 'error');
        }
      } catch(e) { toast('Ошибка сети', 'error'); }
      location.hash = '#/subject/' + wizSlug;
    });
  }

  renderStep1();
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
