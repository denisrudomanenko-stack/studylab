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


# ─── ROUTES END ────────────────────────────────────────────────────────


# ─── Frontend ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_SPA


HTML_SPA = """<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>StudyLab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#060610;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     min-height:100vh;display:flex;align-items:center;justify-content:center}
</style>
</head><body>
<p style="font-size:1.5rem;opacity:.5">StudyLab инициализируется…</p>
</body></html>"""


if __name__ == "__main__":
    uvicorn.run("studylab:app", host="0.0.0.0", port=8201, reload=False)
