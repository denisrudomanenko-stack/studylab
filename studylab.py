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

import bcrypt
import jwt
from fastapi import (Cookie, Depends, FastAPI, File, Form, HTTPException,
                     Request, Response, UploadFile)
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
            status        TEXT NOT NULL DEFAULT 'pending',
            chunk_count   INTEGER      DEFAULT 0,
            created_at    TEXT         NOT NULL,
            UNIQUE(subject_slug, slug)
        );
        CREATE TABLE IF NOT EXISTS chat_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_slug TEXT NOT NULL,
            user_id      INTEGER NOT NULL,
            role         TEXT    NOT NULL,
            content      TEXT    NOT NULL,
            created_at   TEXT    NOT NULL
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
        db.execute("UPDATE sources SET status='processing' WHERE subject_slug=? AND slug=?",
                   (subject_slug, source_slug))
        db.commit()

        subj_dir = subject_dir(subject_slug)
        md_dir = subj_dir / "md"

        def _run():
            if not MKLIB_OK:
                raise RuntimeError("mklib недоступен")
            mk_convert(upload_path, source_slug, md_dir)
            text = mk_read_text(md_dir, source_slug)
            if not text:
                raise RuntimeError("Текст не извлечён")
            segs = segment_text(text)
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
            for i in range(0, len(records), 32):
                vecs = embed_texts(payloads[i:i+32])
                for r, v in zip(records[i:i+32], vecs):
                    r["embedding"] = v
                db_upsert(vec_db, "chunks", records[i:i+32])
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
                          user: dict = Depends(admin_user)):
    slug = _slug(title)
    if not slug:
        raise HTTPException(400, "Некорректное название")
    subject_dir(slug)
    db = get_db()
    try:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO subjects (slug,title,description,created_at,created_by) VALUES (?,?,?,?,?)",
            (slug, title, description, now, int(user["sub"]))
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
        "SELECT slug,title,description,created_at FROM subjects ORDER BY created_at DESC"
    ).fetchall()]
    for s in subjects:
        rows = db.execute(
            "SELECT status, chunk_count FROM sources WHERE subject_slug=?", (s["slug"],)
        ).fetchall()
        s["source_count"] = len(rows)
        s["indexed_count"] = sum(1 for r in rows if r["status"] == "indexed")
        s["total_chunks"] = sum(r["chunk_count"] for r in rows)
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
            "VALUES (?,?,?,?,?,'pending',0,?)",
            (slug, src_slug, upload_path.name, file.filename, src_title, now)
        )
        db.commit()
    finally:
        db.close()

    asyncio.create_task(_index_source(slug, src_slug, upload_path, src_title))
    return {"ok": True, "slug": src_slug, "title": src_title, "status": "pending"}


@app.get("/api/subjects/{slug}/sources")
async def list_sources(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? ORDER BY created_at DESC", (slug,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.delete("/api/subjects/{slug}/sources/{src_slug}")
async def delete_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    db = get_db()
    row = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Источник не найден")
    upload_path = subject_dir(slug) / "uploads" / row["filename"]
    if upload_path.exists():
        upload_path.unlink(missing_ok=True)
    db.execute("DELETE FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug))
    db.commit()
    db.close()
    return {"ok": True}


@app.post("/api/subjects/{slug}/reindex/{src_slug}")
async def reindex_source(slug: str, src_slug: str, user: dict = Depends(admin_user)):
    db = get_db()
    row = db.execute(
        "SELECT * FROM sources WHERE subject_slug=? AND slug=?", (slug, src_slug)
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Источник не найден")
    upload_path = subject_dir(slug) / "uploads" / row["filename"]
    asyncio.create_task(_index_source(slug, src_slug, upload_path, row["title"]))
    return {"ok": True, "message": "Переиндексация запущена"}


# ─── Stage 4: Search + Reader ─────────────────────────────────────────

@app.get("/api/subjects/{slug}/search")
async def search_subject(slug: str, q: str, k: int = 8,
                          user: dict = Depends(current_user)):
    if not MKLIB_OK:
        raise HTTPException(503, "Поисковый движок недоступен")
    db_path = subject_dir(slug) / "index.db"
    if not db_path.exists():
        return []

    def _search():
        vec = embed_query(q)
        vdb = mk_open_db(db_path)
        hits = db_search(vdb, "chunks", vec, k=k)
        vdb.close()
        return hits

    hits = await asyncio.to_thread(_search)
    return [
        {
            "score": h["score"],
            "slug": h["slug"],
            "segment": h["segment"],
            "title": h["title"],
            "text": h["text"][:400],
        }
        for h in hits
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

TIMEWEB_URL = "https://api.timeweb.cloud/api/v1/cloud-ai/chat/completions"
CHAT_MODEL  = "gemini/gemini-3.5-flash"

SYSTEM_BIO = (
    "Ты — интеллектуальный ассистент по биологии и микробиологии для студентки МГУ. "
    "Отвечай строго по предоставленным фрагментам источников. "
    "Используй правильные латинские названия организмов. "
    "К каждому факту добавляй провенанс в формате [источник: название | раздел: заголовок]. "
    "Если ответа в источниках нет — скажи честно и не придумывай."
)


async def _rag_context(subject_slug: str, question: str, k: int = 8) -> list[dict]:
    """Retrieve top-k relevant chunks from the subject's vector index."""
    if not MKLIB_OK:
        return []
    db_path = subject_dir(subject_slug) / "index.db"
    if not db_path.exists():
        return []

    def _fetch():
        vec = embed_query(question)
        vdb = mk_open_db(db_path)
        hits = db_search(vdb, "chunks", vec, k=k)
        vdb.close()
        return hits

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
            parts.append(f"[{i}] {h['text'][:600]}")
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
async def chat_history(slug: str, limit: int = 50,
                        user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT role,content,created_at FROM chat_history "
        "WHERE subject_slug=? AND user_id=? ORDER BY id DESC LIMIT ?",
        (slug, int(user["sub"]), limit)
    ).fetchall()
    db.close()
    return list(reversed([dict(r) for r in rows]))


@app.delete("/api/subjects/{slug}/chat/history")
async def clear_chat_history(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    db.execute("DELETE FROM chat_history WHERE subject_slug=? AND user_id=?",
               (slug, int(user["sub"])))
    db.commit()
    db.close()
    return {"ok": True}


@app.get("/api/subjects/{slug}/chat/stream")
async def chat_stream(slug: str, q: str, user: dict = Depends(current_user),
                       image: Optional[str] = None):
    if not TIMEWEB_API_KEY:
        raise HTTPException(503, "TIMEWEB_API_KEY не задан")

    uid = int(user["sub"])
    now = datetime.now(timezone.utc).isoformat()

    db = get_db()
    history = [dict(r) for r in db.execute(
        "SELECT role,content FROM chat_history "
        "WHERE subject_slug=? AND user_id=? ORDER BY id DESC LIMIT 20",
        (slug, uid)
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
                    "INSERT INTO chat_history (subject_slug,user_id,role,content,created_at) "
                    "VALUES (?,?,?,?,?)",
                    (slug, uid, "user", q, now)
                )
                save_db.execute(
                    "INSERT INTO chat_history (subject_slug,user_id,role,content,created_at) "
                    "VALUES (?,?,?,?,?)",
                    (slug, uid, "assistant", answer_text,
                     datetime.now(timezone.utc).isoformat())
                )
                save_db.commit()
                save_db.close()
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
        "Ты — преподаватель биологии и микробиологии МГУ. "
        "Напиши развёрнутый ответ на экзаменационный билет, используя ТОЛЬКО предоставленные источники. "
        "Структурируй ответ: введение, основная часть с подзаголовками, заключение. "
        "Используй правильные латинские названия. "
        "Добавляй провенанс [источник | раздел] после каждого ключевого утверждения. "
        "Объём: 300-600 слов."
    )

    ctx = ""
    if context_chunks:
        parts = [f"[{i+1}] {h['text'][:800]}" for i, h in enumerate(context_chunks)]
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


@app.get("/api/subjects/{slug}/tickets/export")
async def export_tickets(slug: str, user: dict = Depends(current_user)):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM exam_tickets WHERE subject_slug=? ORDER BY id", (slug,)
    ).fetchall()
    db.close()
    subject_row = get_db().execute(
        "SELECT title FROM subjects WHERE slug=?", (slug,)
    ).fetchone()
    title = subject_row["title"] if subject_row else slug

    lines = [f"# Экзаменационные билеты: {title}\n"]
    for i, r in enumerate(rows, 1):
        lines.append(f"\n## Билет {i}: {r['question']}\n")
        if r["answer"]:
            lines.append(r["answer"])
        else:
            lines.append("_(ответ не сгенерирован)_")
    text = "\n".join(lines)
    return Response(text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="tickets_{slug}.txt"'})


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
            json={"model": CHAT_MODEL, "messages": messages,
                  "stream": False, "max_tokens": 2048, "temperature": 0.1}
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
    return {"text": text}


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
const S = { user: null, chatES: null, pendingImg: null };

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
  let h = esc(text);
  h = h.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  h = h.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/^# (.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  h = h.replace(/\[([^\]]+)\]/g, '<span class="prov">[$1]</span>');
  h = h.replace(/\n\n+/g, '</p><p>');
  h = h.replace(/\n/g, '<br>');
  return '<p>' + h + '</p>';
}

// ── Router ─────────────────────────────────────────────────────────────
function route() {
  const hash = location.hash.slice(1) || '/login';
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
    '<button class="btn btn-ghost btn-sm" onclick="doLogout()">Выйти</button>' +
    '</div>';
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
    '</form></div></div>';
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
      const pct = s.source_count ? Math.round(s.indexed_count / s.source_count * 100) : 0;
      return '<div class="glass subject-card" onclick="location.hash=\'#/subject/' + s.slug + '\'">' +
        '<div class="card-title">' + esc(s.title) + '</div>' +
        '<div class="card-meta">' + s.source_count + ' источников · ' + s.total_chunks + ' чанков</div>' +
        '<div class="progress"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
        '<div class="card-meta" style="margin-top:6px">' + s.indexed_count + '/' + s.source_count + ' проиндексировано</div>' +
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
    if (srcs.some(function(s) { return s.status === 'pending' || s.status === 'processing'; })) {
      setTimeout(function() { loadSources(slug); }, 3000);
    }
  } catch(e) { el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>'; }
}

function renderSrc(s, slug, isAdmin) {
  const extIcon = {pdf:'📄', docx:'📝', doc:'📝', txt:'📄', md:'📋'};
  const ext = (s.original_name || '').split('.').pop().toLowerCase();
  const statusBadge = {
    indexed: '<span class="badge badge-green">✓ готов</span>',
    processing: '<span class="badge badge-yellow"><span class="spinner" style="width:10px;height:10px"></span> обработка</span>',
    error: '<span class="badge badge-red">⚠ ошибка</span>',
    pending: '<span class="badge badge-blue">⏳ ожидание</span>'
  }[s.status] || '<span class="badge badge-blue">' + esc(s.status) + '</span>';
  return '<div class="glass2 source-item" id="si-' + s.slug + '">' +
    '<div class="source-icon">' + (extIcon[ext] || '📄') + '</div>' +
    '<div class="source-info">' +
    '<div class="source-name">' + esc(s.title) + '</div>' +
    '<div class="source-meta">' + esc(s.original_name) + ' · ' + s.chunk_count + ' чанков</div>' +
    '</div>' +
    statusBadge +
    (isAdmin ? '<button class="btn btn-danger btn-sm" onclick="delSrc(\'' + slug + '\',\'' + s.slug + '\')">✕</button>' : '') +
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
    toast('Загрузка: ' + file.name + '…', 'info');
    try {
      const r = await api('/api/subjects/' + slug + '/upload', {method:'POST', body:fd});
      if (r.ok) {
        toast(file.name + ' загружен, индексирование…', 'success');
        setTimeout(function() { loadSources(slug); }, 600);
      } else {
        const err = await r.json();
        toast(err.detail || 'Ошибка загрузки', 'error');
      }
    } catch(e) { toast('Ошибка сети', 'error'); }
  }
}

async function delSrc(slug, srcSlug) {
  if (!confirm('Удалить источник и его индекс?')) return;
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
        html += '<div class="toc-item" onclick="loadSeg(\'' + slug + '\',\'' + srcSlug + '\',' + seg.index + ',this)">' +
          '<span class="toc-num">' + (seg.index + 1) + '</span>' +
          '<span>' + esc(seg.title) + '</span>' +
          '</div>';
      });
    }
    toc.innerHTML = html;
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
  } catch(e) {
    content.innerHTML = '<p style="color:var(--red)">Ошибка загрузки сегмента</p>';
  }
}

// ── Chat ───────────────────────────────────────────────────────────────
async function vChat(main, slug) {
  S.pendingImg = null;
  main.innerHTML =
    '<div class="chat-layout">' +
    '<div class="chat-messages" id="chat-msgs">' +
    '<div class="text-muted text-sm" style="text-align:center;padding:20px"><div class="spinner"></div></div>' +
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
    '<span>Shift+Enter — отправить · Enter — новая строка</span>' +
    '<button class="btn btn-ghost btn-sm" id="btn-clr" style="font-size:.75rem;padding:3px 8px">🗑 Очистить</button>' +
    '</div></div></div>';

  const msgsEl = document.getElementById('chat-msgs');
  const inpEl = document.getElementById('chat-inp');

  // Load history
  try {
    const r = await api('/api/subjects/' + slug + '/chat/history');
    const hist = await r.json();
    msgsEl.innerHTML = '';
    if (!hist.length) {
      msgsEl.innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Новый чат · Задайте вопрос по материалам предмета</p>';
    } else {
      hist.forEach(function(m) { appendMsg(m.role, m.content); });
      msgsEl.scrollTop = msgsEl.scrollHeight;
    }
  } catch(e) {
    msgsEl.innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">Новый чат</p>';
  }

  // Photo OCR
  document.getElementById('btn-photo').addEventListener('click', function() {
    document.getElementById('photo-inp').click();
  });
  document.getElementById('photo-inp').addEventListener('change', async function(e) {
    const file = e.target.files[0];
    if (!file) return;
    toast('Распознавание текста на фото…', 'info');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await api('/api/subjects/' + slug + '/chat/ocr-image', {method:'POST', body:fd});
      if (r.ok) {
        const data = await r.json();
        const bar = document.getElementById('img-bar');
        bar.innerHTML =
          '<span class="badge badge-blue" style="font-size:.75rem">📷 OCR</span>' +
          '<span class="text-sm text-muted" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(data.text.slice(0, 80)) + '…</span>' +
          '<button class="btn btn-ghost btn-sm" style="flex-shrink:0" onclick="clearOcr()">✕</button>';
        bar.classList.remove('hidden');
        S.pendingImg = data.text;
        inpEl.placeholder = 'OCR добавлен. Уточните вопрос или отправьте как есть…';
        toast('Текст распознан', 'success');
      } else { toast('Ошибка OCR', 'error'); }
    } catch(err) { toast('Ошибка распознавания', 'error'); }
  });

  async function sendMsg() {
    const q = inpEl.value.trim();
    if (!q && !S.pendingImg) return;
    const fullQ = S.pendingImg ? 'Содержимое конспекта:\n' + S.pendingImg + (q ? '\n\nВопрос: ' + q : '') : q;
    inpEl.value = '';
    inpEl.style.height = '';
    clearOcr();

    const msgsDiv = document.getElementById('chat-msgs');
    msgsDiv.querySelector('.text-muted.text-sm') && (msgsDiv.innerHTML = '');
    appendMsg('user', fullQ);
    msgsDiv.scrollTop = msgsDiv.scrollHeight;

    const msgEl = appendMsg('assistant', '');
    const bubble = msgEl.querySelector('.msg-bubble');
    bubble.innerHTML = '<div class="spinner"></div>';

    let full = '';
    const es = new EventSource('/api/subjects/' + slug + '/chat/stream?q=' + encodeURIComponent(fullQ));
    S.chatES = es;

    es.onmessage = function(ev) {
      if (ev.data === '[DONE]') {
        es.close(); S.chatES = null;
        bubble.innerHTML = md(full);
        msgsDiv.scrollTop = msgsDiv.scrollHeight;
        return;
      }
      try {
        const d = JSON.parse(ev.data);
        if (d.error) { bubble.innerHTML = '<span style="color:var(--red)">' + esc(d.error) + '</span>'; es.close(); return; }
        if (d.content) {
          full += d.content;
          bubble.innerHTML = md(full) + '<span class="spinner" style="width:10px;height:10px;margin-left:4px"></span>';
          msgsDiv.scrollTop = msgsDiv.scrollHeight;
        }
      } catch(e2) {}
    };
    es.onerror = function() {
      es.close(); S.chatES = null;
      if (!full) bubble.innerHTML = '<span style="color:var(--red)">Ошибка соединения. Проверьте подключение.</span>';
    };
  }

  document.getElementById('btn-send').addEventListener('click', sendMsg);
  inpEl.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.shiftKey) { e.preventDefault(); sendMsg(); }
  });
  inpEl.addEventListener('input', function() {
    inpEl.style.height = 'auto';
    inpEl.style.height = Math.min(inpEl.scrollHeight, 120) + 'px';
  });
  document.getElementById('btn-clr').addEventListener('click', async function() {
    if (!confirm('Очистить историю чата?')) return;
    await api('/api/subjects/' + slug + '/chat/history', {method:'DELETE'});
    document.getElementById('chat-msgs').innerHTML = '<p class="text-muted text-sm" style="text-align:center;padding:20px">История очищена</p>';
    toast('История очищена', 'success');
  });
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
    '<div style="display:flex;gap:10px;margin-bottom:24px">' +
    '<input type="text" id="new-q" placeholder="Новый вопрос для билета… (Enter)">' +
    '<button class="btn btn-primary btn-sm" style="flex-shrink:0" id="btn-add-t">+ Добавить</button>' +
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
      return '<div class="glass ticket-item" id="tk-' + t.id + '">' +
        '<div style="display:flex;align-items:flex-start;gap:10px">' +
        '<div class="ticket-q" style="flex:1">' + esc(t.question) + '</div>' +
        '<div class="flex gap" style="flex-shrink:0">' +
        '<button class="btn btn-primary btn-sm" onclick="genTicket(\'' + slug + '\',' + t.id + ')">' +
        (t.status === 'generated' ? '🔄' : '⚡') + ' Ответить</button>' +
        '<button class="btn btn-danger btn-sm" onclick="delTicket(\'' + slug + '\',' + t.id + ')">✕</button>' +
        '</div></div>' +
        (t.answer ? '<div class="ticket-answer">' + md(t.answer) + '</div>' : '') +
        '</div>';
    }).join('');
  } catch(e) { el.innerHTML = '<p style="color:var(--red)" class="text-sm">Ошибка загрузки</p>'; }
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
    if (ev.data === '[DONE]') { es.close(); ansEl.innerHTML = md(full); return; }
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
