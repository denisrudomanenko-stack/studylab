#!/usr/bin/env python3
"""mklib — конструктор тематических библиотек с семантическим поиском.

Создаёт из папки с PDF индексированную библиотеку с векторным поиском
и скиллом для Claude Code. Использует ollama + EmbeddingGemma + sqlite-vec.

Требует интерпретатор из library-kit: ~/library-kit/.venv/bin/python

Форматы: PDF, EPUB, DJVU, DOCX, HTML, Markdown, TXT, RTF.

Команды:
    mklib init <путь> --name <id> --title <название>
    mklib add <файл> --topic <тема> [--priority 1] [--images]
    mklib convert                    # источники → markdown
    mklib build                      # сегментация + индексация
    mklib install                    # установить скилл в ~/.claude/skills/
    mklib search <запрос>            # семантический поиск
    mklib route <запрос>             # поиск по всем темам с квотой
    mklib read <slug> [номер]        # прочитать сегмент
    mklib stats                      # статистика базы
    mklib doctor                     # диагностика здоровья
    mklib topic add <id> <название>  # добавить тему

Примеры:
    PY=~/library-kit/.venv/bin/python

    $PY mklib.py init ~/Projects/Cardiology --name cardio --title "Кардиология"
    $PY mklib.py add ~/Downloads/ecg_review.pdf --topic ecg --priority 1
    $PY mklib.py topic add ecg "Электрокардиография"
    $PY mklib.py convert
    $PY mklib.py build
    $PY mklib.py install
    $PY mklib.py route "аритмия при нагрузке"
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

import numpy as np
import requests
import sqlite_vec

# ═══════════════════════════════════════════════════════════════════════
# Конфиг
# ═══════════════════════════════════════════════════════════════════════

def _find_lib_dir() -> Path:
    """Найти корень библиотеки — поднимаемся вверх от CWD до library.yaml."""
    d = Path.cwd().resolve()
    for _ in range(10):
        if (d / "library.yaml").exists():
            return d
        if d.parent == d:
            break
        d = d.parent
    # Если не нашли — текущая папка
    return Path.cwd().resolve()


def load_config(lib_dir: Path | None = None) -> dict:
    if lib_dir is None:
        lib_dir = _find_lib_dir()
    cfg_path = lib_dir / "library.yaml"
    if not cfg_path.exists():
        print(f"Конфиг не найден: {cfg_path}", file=sys.stderr)
        print("Создай библиотеку: mklib init <путь> --name <id> --title <название>", file=sys.stderr)
        sys.exit(1)
    # Простой YAML-парсер (без зависимости от pyyaml)
    return _parse_yaml(cfg_path.read_text(encoding="utf-8")), lib_dir


def _parse_yaml(text: str) -> dict:
    """Минимальный парсер YAML для нашего формата конфига."""
    result: dict = {}
    current_section = None
    current_item = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and stripped.endswith(":"):
            # Секция верхнего уровня без значения
            current_section = stripped[:-1]
            result[current_section] = {}
            current_item = None
            continue

        if indent == 0 and ":" in stripped:
            key, _, val = stripped.partition(":")
            result[key.strip()] = val.strip().strip('"').strip("'")
            current_section = None
            current_item = None
            continue

        if current_section is not None:
            if indent == 2 and stripped.endswith(":"):
                # Ключ подсекции
                current_item = stripped[:-1]
                result[current_section][current_item] = {}
                continue

            if indent == 2 and ":" in stripped:
                key, _, val = stripped.partition(":")
                val = val.strip().strip('"').strip("'")
                result[current_section][key.strip()] = val
                current_item = None
                continue

            if indent == 4 and current_item and ":" in stripped:
                key, _, val = stripped.partition(":")
                val = val.strip().strip('"').strip("'")
                # Приведение типов
                if val.lower() in ("true", "yes"):
                    val = True
                elif val.lower() in ("false", "no"):
                    val = False
                elif val.isdigit():
                    val = int(val)
                result[current_section][current_item][key.strip()] = val
                continue

    return result


def save_config(cfg: dict, lib_dir: Path):
    lines = []
    simple_keys = [k for k in cfg if not isinstance(cfg[k], dict)]
    dict_keys = [k for k in cfg if isinstance(cfg[k], dict)]

    for k in simple_keys:
        lines.append(f'{k}: "{cfg[k]}"' if isinstance(cfg[k], str) else f"{k}: {cfg[k]}")

    for section in dict_keys:
        lines.append(f"\n{section}:")
        data = cfg[section]
        for item_key, item_val in data.items():
            if isinstance(item_val, dict):
                lines.append(f"  {item_key}:")
                for k, v in item_val.items():
                    if isinstance(v, str):
                        lines.append(f'    {k}: "{v}"')
                    elif isinstance(v, bool):
                        lines.append(f"    {k}: {'true' if v else 'false'}")
                    else:
                        lines.append(f"    {k}: {v}")
            else:
                if isinstance(item_val, str):
                    lines.append(f'  {item_key}: "{item_val}"')
                else:
                    lines.append(f"  {item_key}: {item_val}")

    (lib_dir / "library.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════
# Эмбеддер
# ═══════════════════════════════════════════════════════════════════════

def _emb_config(key: str) -> str:
    cfg = os.path.expanduser("~/.library/config")
    try:
        with open(cfg, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""

EMB_URL = (os.environ.get("LMSTUDIO_BASE_URL")
           or _emb_config("LMSTUDIO_BASE_URL")
           or "http://127.0.0.1:11434/v1").rstrip("/")
EMB_MODEL = (os.environ.get("LMSTUDIO_MODEL")
             or _emb_config("LMSTUDIO_MODEL")
             or "bge-m3")

DOC_PREFIX = ""
QUERY_PREFIX = ""
DIM = 1024


def embed_texts(texts: list[str]) -> list[list[float]]:
    out = []
    for i in range(0, len(texts), 32):
        batch = [DOC_PREFIX + (t or "") for t in texts[i:i+32]]
        resp = requests.post(f"{EMB_URL}/embeddings",
                             json={"model": EMB_MODEL, "input": batch}, timeout=600)
        resp.raise_for_status()
        vecs = [it["embedding"] for it in sorted(resp.json()["data"], key=lambda x: x["index"])]
        for v in vecs:
            a = np.asarray(v, dtype=np.float32)
            n = float(np.linalg.norm(a))
            out.append((a / n).tolist() if n > 0 else a.tolist())
    return out


def embed_query(query: str) -> list[float]:
    resp = requests.post(f"{EMB_URL}/embeddings",
                         json={"model": EMB_MODEL, "input": [QUERY_PREFIX + query]}, timeout=300)
    resp.raise_for_status()
    v = resp.json()["data"][0]["embedding"]
    a = np.asarray(v, dtype=np.float32)
    n = float(np.linalg.norm(a))
    return (a / n).tolist() if n > 0 else a.tolist()


# ═══════════════════════════════════════════════════════════════════════
# Конвертация источников (мультиформат)
# ═══════════════════════════════════════════════════════════════════════

FORMAT_MAP = {
    ".pdf": "pdf", ".epub": "epub", ".djvu": "djvu",
    ".docx": "docx", ".doc": "docx",
    ".html": "html", ".htm": "html",
    ".md": "copy", ".markdown": "copy",
    ".txt": "copy", ".text": "copy",
    ".rtf": "rtf",
}

MIN_IMG_SIDE = 100
MIN_IMG_AREA = 20000


def convert_pdf(pdf_path: Path, slug: str, md_dir: Path, with_images: bool = False) -> bool:
    import pymupdf
    out_dir = md_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    doc = pymupdf.open(str(pdf_path))
    pages_text = []

    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text("text")
        if not text.strip():
            continue

        img_refs = ""
        if with_images:
            media_dir = out_dir / "media"
            media_dir.mkdir(parents=True, exist_ok=True)
            for img_idx, img_info in enumerate(page.get_images(full=True)):
                xref = img_info[0]
                try:
                    pix = pymupdf.Pixmap(doc, xref)
                except Exception:
                    continue
                w, h = pix.width, pix.height
                if min(w, h) < MIN_IMG_SIDE or w * h < MIN_IMG_AREA:
                    continue
                try:
                    if pix.n - pix.alpha > 3:
                        pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                    elif pix.alpha:
                        pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                except Exception:
                    continue
                fname = f"page{page_num + 1}_img{img_idx + 1}.png"
                try:
                    pix.save(str(media_dir / fname))
                    img_refs += f"\n\n![](media/{fname})\n"
                except Exception:
                    continue

        pages_text.append(text + img_refs)

    num_pages = len(doc)
    doc.close()

    if not pages_text:
        return False

    full_text = "\n\n---\n\n".join(pages_text)
    full_text = re.sub(r"\n{4,}", "\n\n\n", full_text)
    (out_dir / "book.md").write_text(full_text, encoding="utf-8")

    img_count = len(list((out_dir / "media").glob("*.png"))) if (out_dir / "media").exists() else 0
    word_count = len(full_text.split())
    print(f"  {slug}: {word_count} слов, {num_pages} стр., {img_count} изобр.")
    return True


def convert_pandoc(src_path: Path, slug: str, md_dir: Path, fmt: str) -> bool:
    """Конвертация через pandoc: EPUB, DOCX, HTML, RTF."""
    out_dir = md_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    media_dir = out_dir / "media"
    media_dir.mkdir(exist_ok=True)

    cmd = ["pandoc", str(src_path), "-t", "markdown", "--wrap=none",
           f"--extract-media={media_dir}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print(f"  SKIP: {slug} — pandoc не найден (brew install pandoc)")
        return False
    except Exception as e:
        print(f"  ERROR: {slug} — {e}")
        return False

    if r.returncode != 0:
        print(f"  ERROR: {slug} — pandoc: {r.stderr[:200]}")
        return False

    text = r.stdout
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    (out_dir / "book.md").write_text(text, encoding="utf-8")

    # Подсчитать извлечённые медиа
    imgs = list(media_dir.rglob("*.*")) if media_dir.exists() else []
    word_count = len(text.split())
    print(f"  {slug}: {word_count} слов, {len(imgs)} медиа ({fmt})")
    return True


def convert_djvu(src_path: Path, slug: str, md_dir: Path) -> bool:
    """Конвертация DJVU: ddjvu → текст, опционально OCR через tesseract."""
    out_dir = md_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    # Сначала попробуем текстовый слой
    try:
        r = subprocess.run(["ddjvu", "-format=utf8", str(src_path), "-"],
                           capture_output=True, text=True, timeout=120)
        text = r.stdout.strip()
    except FileNotFoundError:
        print(f"  SKIP: {slug} — ddjvu не найден (brew install djvulibre)")
        return False
    except Exception as e:
        print(f"  ERROR: {slug} — {e}")
        return False

    if len(text.split()) < 100:
        # Текстового слоя нет — OCR через tesseract
        print(f"  {slug}: текстового слоя нет, запускаю OCR...")
        try:
            # Конвертируем в TIFF, потом OCR
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                tiff = Path(tmp) / "pages.tiff"
                subprocess.run(["ddjvu", "-format=tiff", str(src_path), str(tiff)],
                               capture_output=True, timeout=300)
                r = subprocess.run(["tesseract", str(tiff), "-", "-l", "rus+eng"],
                                   capture_output=True, text=True, timeout=600)
                text = r.stdout.strip()
        except Exception as e:
            print(f"  ERROR: {slug} OCR — {e}")
            return False

    if not text or len(text.split()) < 50:
        print(f"  SKIP: {slug} — текст не извлечён")
        return False

    text = re.sub(r"\n{4,}", "\n\n\n", text)
    (out_dir / "book.md").write_text(text, encoding="utf-8")
    word_count = len(text.split())
    print(f"  {slug}: {word_count} слов (djvu)")
    return True


def convert_copy(src_path: Path, slug: str, md_dir: Path) -> bool:
    """MD и TXT — просто копируем."""
    out_dir = md_dir / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    text = src_path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    (out_dir / "book.md").write_text(text, encoding="utf-8")
    word_count = len(text.split())
    print(f"  {slug}: {word_count} слов (copy)")
    return True


def convert_source(src_path: Path, slug: str, md_dir: Path,
                   with_images: bool = False, fmt: str | None = None) -> bool:
    """Универсальный конвертер — определяет формат и вызывает нужный метод."""
    if fmt is None:
        fmt = FORMAT_MAP.get(src_path.suffix.lower(), "")
    if not fmt:
        print(f"  SKIP: {slug} — неизвестный формат {src_path.suffix}")
        return False

    if fmt == "pdf":
        return convert_pdf(src_path, slug, md_dir, with_images)
    elif fmt in ("epub", "docx", "html", "rtf"):
        return convert_pandoc(src_path, slug, md_dir, fmt)
    elif fmt == "djvu":
        return convert_djvu(src_path, slug, md_dir)
    elif fmt == "copy":
        return convert_copy(src_path, slug, md_dir)
    else:
        print(f"  SKIP: {slug} — формат {fmt} не поддерживается")
        return False


# ═══════════════════════════════════════════════════════════════════════
# Сегментация
# ═══════════════════════════════════════════════════════════════════════

TARGET_SEGMENT_WORDS = 2000
MIN_SEGMENT_WORDS = 500
CHUNK_WORDS = 500
HEADING_RE = re.compile(r"(?m)^(#{1,6})\s+(\S.*)$")


def read_text(md_dir: Path, slug: str) -> str:
    p = md_dir / slug / "book.md"
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8")
    return re.sub(r"\A---\n.*?\n---\n", "", text, count=1, flags=re.S)


def segment_text(text: str) -> list[dict]:
    heads = HEADING_RE.findall(text)
    wph = len(text.split()) / len(heads) if heads else float("inf")

    if heads and wph <= 1500:
        positions = [m.start() for m in HEADING_RE.finditer(text)]
        positions.append(len(text))
        segments = []
        for i in range(len(positions) - 1):
            start, end = positions[i], positions[i + 1]
            body = text[start:end].strip()
            words = len(body.split())
            if words < 50:
                continue
            if segments and words < MIN_SEGMENT_WORDS:
                segments[-1]["end_char"] = end
                segments[-1]["words"] += words
                continue
            m = HEADING_RE.match(body)
            title = m.group(2).strip()[:160] if m else f"сегмент {len(segments)+1}"
            segments.append({"index": len(segments), "start_char": start,
                             "end_char": end, "words": words, "title": title})
        return segments
    else:
        total_words = len(text.split())
        want = max(1, round(total_words / TARGET_SEGMENT_WORDS))
        paras = [(m.start(), m.end()) for m in re.finditer(r"[^\n]+(?:\n(?!\n)[^\n]+)*", text)]
        if not paras:
            return [{"index": 0, "start_char": 0, "end_char": len(text),
                     "words": total_words, "title": "полный текст"}]
        target_per = total_words / want
        segments, cur_start, cur_words = [], 0, 0
        for s, e in paras:
            cur_words += len(text[s:e].split())
            if cur_words >= target_per and len(segments) < want - 1:
                tw = text[cur_start:cur_start+200].split()
                title = " ".join(tw[:8]) + "…" if tw else f"сегмент {len(segments)+1}"
                segments.append({"index": len(segments), "start_char": cur_start,
                                 "end_char": e, "words": cur_words, "title": title})
                cur_start, cur_words = e, 0
        if cur_words > 0 or not segments:
            tw = text[cur_start:cur_start+200].split()
            title = " ".join(tw[:8]) + "…" if tw else f"сегмент {len(segments)+1}"
            segments.append({"index": len(segments), "start_char": cur_start,
                             "end_char": len(text), "words": cur_words or total_words, "title": title})
        return segments


def chunk_segment(text: str, seg: dict) -> list[tuple[int, int]]:
    body = text[seg["start_char"]:seg["end_char"]]
    marks = [0] + [m.end() for m in re.finditer(r"\n\n", body)] + [len(body)]
    out, start, words = [], 0, 0
    for a, b in zip(marks, marks[1:]):
        words += len(body[a:b].split())
        if words >= CHUNK_WORDS:
            out.append((seg["start_char"] + start, seg["start_char"] + b))
            start, words = b, 0
    if words > 0:
        out.append((seg["start_char"] + start, seg["end_char"]))
    return [(a, b) for a, b in out if b > a]


# ═══════════════════════════════════════════════════════════════════════
# База sqlite-vec
# ═══════════════════════════════════════════════════════════════════════

def open_db(db_path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(db_path))
    db.enable_load_extension(True)
    sqlite_vec.load(db)
    db.enable_load_extension(False)
    db.row_factory = sqlite3.Row
    return db


def init_db(db: sqlite3.Connection, table: str):
    db.execute(f"""CREATE VIRTUAL TABLE IF NOT EXISTS {table} USING vec0(
        chunk_id text primary key,
        embedding float[{DIM}] distance_metric=cosine,
        slug text, topic text, priority integer,
        +segment integer, +title text, +text text, +meta text
    )""")
    db.execute("CREATE TABLE IF NOT EXISTS lib_meta (key text primary key, value text)")
    db.commit()


def db_upsert(db: sqlite3.Connection, table: str, records: list[dict]):
    ids = [(r["chunk_id"],) for r in records]
    rows = [(r["chunk_id"], sqlite_vec.serialize_float32(r["embedding"]),
             r["slug"], r["topic"], r["priority"], r["segment"],
             r["title"], r["text"],
             json.dumps(r.get("meta", {}), ensure_ascii=False)) for r in records]
    db.executemany(f"DELETE FROM {table} WHERE chunk_id = ?", ids)
    db.executemany(f"INSERT INTO {table}(chunk_id, embedding, slug, topic, priority,"
                   " segment, title, text, meta) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    db.commit()


def db_search(db: sqlite3.Connection, table: str, vec, k: int = 10,
              topic: str | None = None) -> list[dict]:
    where = ["embedding MATCH ?", "k = ?"]
    params: list = [sqlite_vec.serialize_float32(vec), k]
    if topic:
        where.append("topic = ?")
        params.append(topic)
    sql = (f"SELECT chunk_id, distance, slug, topic, priority, segment, title, text, meta "
           f"FROM {table} WHERE " + " AND ".join(where) + " ORDER BY distance")
    out = []
    for row in db.execute(sql, params):
        d = dict(row)
        d["score"] = round(1.0 - d["distance"], 4)
        try:
            d["meta"] = json.loads(d["meta"]) if d["meta"] else {}
        except Exception:
            d["meta"] = {}
        out.append(d)
    return out


# ═══════════════════════════════════════════════════════════════════════
# Генератор скилла
# ═══════════════════════════════════════════════════════════════════════

SKILL_TEMPLATE = '''# {title}

Ты отвечаешь на вопросы, опираясь на научные и методические источники из локальной
библиотеки. Не отвечай по памяти модели — читай источники.

## Инструменты

Интерпретатор — из library-kit: `~/library-kit/.venv/bin/python`

```bash
PY=~/library-kit/.venv/bin/python
cd "{lib_dir}"

$PY mklib.py route "описание вопроса"          # поиск по всем темам
$PY mklib.py search "запрос" --topic <тема>     # поиск по теме
$PY mklib.py read <slug>                        # список сегментов
$PY mklib.py read <slug> <номер>                # прочитать сегмент
$PY mklib.py stats                              # статистика
```

Темы: {topics_list}

## Каталог

{catalog_table}

## Порядок ответа

1. Вызови `route` с вопросом. Посмотри, какие темы набрали высокий скор.
2. Прочитай нужный фрагмент через `read <slug> <номер>`.
3. Ответь, разделяя: что говорит источник, что известно из контекста, в чём ограничения.
4. Провенанс: `[источник: slug | положение из текста]`
5. Если ответа в библиотеке нет — скажи честно.
'''


def generate_skill(cfg: dict, lib_dir: Path) -> str:
    topics = cfg.get("topics", {})
    sources = cfg.get("sources", {})

    topics_list = ", ".join(f"`{k}`" for k in topics)

    rows = []
    for slug, info in sources.items():
        if isinstance(info, dict):
            t = info.get("title", slug)
            topic = info.get("topic", "—")
            pri = info.get("priority", "—")
            rows.append(f"| `{slug}` | {t} | {topic} | {pri} |")

    catalog_table = "| Slug | Название | Тема | Пр. |\n|---|---|---|---|\n" + "\n".join(rows)

    return SKILL_TEMPLATE.format(
        title=cfg.get("title", "Библиотека"),
        lib_dir=str(lib_dir),
        topics_list=topics_list,
        catalog_table=catalog_table,
    )


# ═══════════════════════════════════════════════════════════════════════
# Команды
# ═══════════════════════════════════════════════════════════════════════

def cmd_init(args):
    target = Path(args[0]).expanduser().resolve()
    name = _arg(args, "--name") or target.name.lower().replace(" ", "_")
    title = _arg(args, "--title") or target.name

    target.mkdir(parents=True, exist_ok=True)
    (target / "pdf").mkdir(exist_ok=True)
    (target / "md").mkdir(exist_ok=True)

    cfg = {"name": name, "title": title, "topics": {}, "sources": {}}
    save_config(cfg, target)

    # Копировать mklib.py в папку библиотеки
    src = Path(__file__).resolve()
    dst = target / "mklib.py"
    if not dst.exists():
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    print(f"Библиотека создана: {target}")
    print(f"  Конфиг: {target / 'library.yaml'}")
    print(f"  PDF:    {target / 'pdf'}/")
    print(f"  MD:     {target / 'md'}/")
    print(f"\nСледующие шаги:")
    print(f"  1. Положи PDF в {target / 'pdf'}/")
    print(f"  2. $PY mklib.py topic add <id> <название>")
    print(f"  3. $PY mklib.py add <pdf> --topic <тема>")
    print(f"  4. $PY mklib.py convert && $PY mklib.py build && $PY mklib.py install")


def cmd_topic(args):
    cfg, lib_dir = load_config()
    if not args or args[0] != "add" or len(args) < 3:
        print("Использование: mklib topic add <id> <название>")
        return
    tid = args[1]
    tname = " ".join(args[2:])
    cfg.setdefault("topics", {})[tid] = tname
    save_config(cfg, lib_dir)
    print(f"Тема добавлена: {tid} → {tname}")


def cmd_add(args):
    cfg, lib_dir = load_config()
    pdf_path = Path(args[0]).expanduser().resolve()
    if not pdf_path.exists():
        print(f"Файл не найден: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    topic = _arg(args, "--topic") or "general"
    priority = int(_arg(args, "--priority") or "2")
    images = "--images" in args
    title = _arg(args, "--title") or pdf_path.stem

    # slug из имени файла
    slug = re.sub(r"[^a-z0-9]+", "_", pdf_path.stem.lower()).strip("_")[:60]

    # Скопировать PDF в pdf/
    pdf_dir = lib_dir / "pdf"
    pdf_dir.mkdir(exist_ok=True)
    dst = pdf_dir / pdf_path.name
    if not dst.exists():
        dst.write_bytes(pdf_path.read_bytes())
        print(f"PDF скопирован: {dst}")

    cfg.setdefault("sources", {})[slug] = {
        "file": pdf_path.name,
        "title": title,
        "topic": topic,
        "priority": priority,
        "images": images,
    }
    save_config(cfg, lib_dir)
    print(f"Добавлен: {slug} → тема {topic}, приоритет {priority}")


def cmd_convert(args):
    cfg, lib_dir = load_config()
    pdf_dir = lib_dir / "pdf"
    md_dir = lib_dir / "md"
    sources = cfg.get("sources", {})

    print(f"Конвертация {len(sources)} источников\n")
    ok = 0
    for slug, info in sources.items():
        if not isinstance(info, dict):
            continue
        src_file = info.get("file", "")
        src_path = pdf_dir / src_file
        if not src_path.exists():
            print(f"  SKIP: {src_file} не найден в {pdf_dir}")
            continue
        images = info.get("images", False)
        fmt = info.get("format")  # явный формат или auto по расширению
        if convert_source(src_path, slug, md_dir, with_images=images, fmt=fmt):
            ok += 1

    print(f"\nСконвертировано: {ok}")


def cmd_build(args):
    cfg, lib_dir = load_config()
    md_dir = lib_dir / "md"
    name = cfg.get("name", "lib")
    db_path = lib_dir / f"{name}_index.db"
    seg_path = lib_dir / f"{name}_segments.json"
    sources = cfg.get("sources", {})
    topics = cfg.get("topics", {})
    table = f"{name}_chunks"

    print(f"Эмбеддер: {EMB_MODEL} на {EMB_URL}")
    print(f"База: {db_path}\n")

    # Сегментация
    print("== Сегментация ==")
    all_segments = {}
    for slug, info in sources.items():
        if not isinstance(info, dict):
            continue
        text = read_text(md_dir, slug)
        if not text:
            print(f"  SKIP: {slug}")
            continue
        segs = segment_text(text)
        all_segments[slug] = {"segments": segs, "words": len(text.split())}
        print(f"  {slug}: {len(segs)} сегм., {len(text.split())} слов")

    seg_path.write_text(json.dumps(all_segments, ensure_ascii=False, indent=1), encoding="utf-8")

    # Индексация
    print("\n== Индексация ==")
    db = open_db(db_path)
    init_db(db, table)
    try:
        db.execute(f"DELETE FROM {table}")
    except Exception:
        pass
    db.commit()

    total = 0
    for slug, info in sources.items():
        if not isinstance(info, dict) or slug not in all_segments:
            continue
        text = read_text(md_dir, slug)
        segs = all_segments[slug]["segments"]
        src_title = info.get("title", slug)
        src_topic = info.get("topic", "general")
        src_pri = info.get("priority", 2)
        topic_name = topics.get(src_topic, src_topic)
        header = f"Тема: {topic_name}. Статья: «{src_title}»."

        records, payloads = [], []
        for seg in segs:
            for ci, (a, b) in enumerate(chunk_segment(text, seg)):
                body = text[a:b].strip()
                if len(body.split()) < 20:
                    continue
                full = f"{header} Раздел: «{seg['title']}».\n\n{body}"
                cid = "s_" + hashlib.sha1(f"{slug}|{a}|{b}".encode()).hexdigest()[:16]
                records.append({"chunk_id": cid, "slug": slug, "topic": src_topic,
                                "priority": src_pri, "segment": seg["index"],
                                "title": seg["title"], "text": full,
                                "meta": {"start_char": a, "end_char": b}})
                payloads.append(full)

        if not records:
            continue
        for i in range(0, len(records), 32):
            vecs = embed_texts(payloads[i:i+32])
            for r, v in zip(records[i:i+32], vecs):
                r["embedding"] = v
            db_upsert(db, table, records[i:i+32])
            sys.stdout.write(".")
            sys.stdout.flush()

        total += len(records)
        print(f"  {slug}: {len(records)} чанков")

    db.execute("INSERT OR REPLACE INTO lib_meta(key,value) VALUES (?,?)", ("embedder", EMB_MODEL))
    db.execute("INSERT OR REPLACE INTO lib_meta(key,value) VALUES (?,?)",
               ("built_at", time.strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    db.close()

    print(f"\nГотово: {total} чанков, {db_path.stat().st_size/1024/1024:.1f} МБ")


def cmd_install(args):
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    title = cfg.get("title", "Библиотека")
    skill_dir = Path.home() / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_text = generate_skill(cfg, lib_dir)
    (skill_dir / "SKILL.md").write_text(skill_text, encoding="utf-8")
    print(f"Скилл /{name} установлен: {skill_dir / 'SKILL.md'}")


def cmd_search(args):
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    db_path = lib_dir / f"{name}_index.db"
    table = f"{name}_chunks"
    sources = cfg.get("sources", {})
    topics = cfg.get("topics", {})

    query = args[0] if args else ""
    topic = _arg(args, "--topic")

    db = open_db(db_path)
    vec = embed_query(query)
    hits = db_search(db, table, vec, k=8, topic=topic)
    db.close()

    for h in hits:
        src = sources.get(h["slug"], {})
        t = src.get("title", h["slug"]) if isinstance(src, dict) else h["slug"]
        tn = topics.get(h["topic"], h["topic"])
        print(f"[{h['score']:.3f}] {t}")
        print(f"  тема: {tn} | раздел: {h['title']}")
        body = h["text"].split("\n\n", 1)[-1].replace("\n", " ")
        print(f"  {body[:250]}…\n")


def cmd_route(args):
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    db_path = lib_dir / f"{name}_index.db"
    table = f"{name}_chunks"
    sources = cfg.get("sources", {})
    topics = cfg.get("topics", {})

    query = args[0] if args else ""
    db = open_db(db_path)
    vec = embed_query(query)

    by_topic: dict[str, list] = {}
    for tid in topics:
        hits = db_search(db, table, vec, k=4, topic=tid)
        if hits:
            by_topic[tid] = hits[:2]
    db.close()

    if not by_topic:
        print("Ничего не найдено")
        return

    best = {k: v[0]["score"] for k, v in by_topic.items()}
    order = sorted(by_topic, key=lambda k: -best[k])
    spread = ", ".join(f"{k} {best[k]:.3f}" for k in order)
    print(f"Лучший кандидат каждой темы — {spread}\n")

    for tid in order:
        print(f"## {topics.get(tid, tid)}")
        for h in by_topic[tid]:
            src = sources.get(h["slug"], {})
            t = src.get("title", h["slug"]) if isinstance(src, dict) else h["slug"]
            print(f"  [{h['score']:.3f}] {t}")
            print(f"    раздел: {h['title']}")
        print()


def cmd_read(args):
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    md_dir = lib_dir / "md"
    seg_path = lib_dir / f"{name}_segments.json"
    sources = cfg.get("sources", {})

    slug = args[0] if args else ""
    seg_num = int(args[1]) if len(args) > 1 else None

    segs = json.loads(seg_path.read_text(encoding="utf-8"))
    if slug not in segs:
        print(f"Статья {slug} не найдена. Доступные:")
        for s in segs:
            print(f"  {s}")
        return
    text = read_text(md_dir, slug)
    info = segs[slug]
    if seg_num is None:
        for s in info["segments"]:
            print(f"{s['index']:>3}  {s['words']:>5} сл.  {s['title']}")
        return
    s = info["segments"][seg_num]
    src = sources.get(slug, {})
    title = src.get("title", slug) if isinstance(src, dict) else slug
    print(f"# {title} · раздел {s['index']}: {s['title']} ({s['words']} слов)\n")
    print(text[s["start_char"]:s["end_char"]])


def cmd_stats(args):
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    db_path = lib_dir / f"{name}_index.db"
    table = f"{name}_chunks"

    db = open_db(db_path)
    total = db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    built = db.execute("SELECT value FROM lib_meta WHERE key='built_at'").fetchone()
    agg = lambda col: {r[0] or "?": r[1] for r in db.execute(
        f"SELECT {col}, count(*) c FROM {table} GROUP BY {col} ORDER BY c DESC")}
    print(json.dumps({
        "name": name, "title": cfg.get("title", ""),
        "db": str(db_path), "total_chunks": total,
        "built_at": built[0] if built else "—",
        "db_size_mb": round(db_path.stat().st_size / 1024 / 1024, 1),
        "by_topic": agg("topic"), "by_slug": agg("slug"),
    }, ensure_ascii=False, indent=1))
    db.close()


def cmd_doctor(args):
    """Диагностика здоровья библиотеки."""
    cfg, lib_dir = load_config()
    name = cfg.get("name", "lib")
    sources = cfg.get("sources", {})
    topics = cfg.get("topics", {})
    md_dir = lib_dir / "md"
    pdf_dir = lib_dir / "pdf"
    db_path = lib_dir / f"{name}_index.db"
    seg_path = lib_dir / f"{name}_segments.json"
    skill_path = Path.home() / ".claude" / "skills" / name / "SKILL.md"

    checks = []

    def check(name, ok, detail=""):
        status = "ок" if ok else "ПРОВАЛ"
        checks.append((name, status, detail))

    # 1. Конфиг
    check("library.yaml", (lib_dir / "library.yaml").exists())

    # 2. Источники в конфиге
    n_src = len([s for s in sources.values() if isinstance(s, dict)])
    check("Источники в конфиге", n_src > 0, f"{n_src} источников")

    # 3. PDF на месте
    missing_pdf = []
    for slug, info in sources.items():
        if isinstance(info, dict):
            f = info.get("file", "")
            if f and not (pdf_dir / f).exists():
                missing_pdf.append(f)
    check("PDF/исходники на месте", len(missing_pdf) == 0,
          f"не найдено: {', '.join(missing_pdf[:3])}" if missing_pdf else f"все {n_src} на месте")

    # 4. Markdown сконвертирован
    converted = sum(1 for s in sources if (md_dir / s / "book.md").exists())
    check("Markdown сконвертирован", converted == n_src,
          f"{converted}/{n_src} сконвертировано")

    # 5. Сегменты
    check("Сегменты", seg_path.exists(),
          f"{seg_path.name}" if seg_path.exists() else "запусти build")

    # 6. Индекс
    check("Индекс (sqlite-vec)", db_path.exists(),
          f"{db_path.stat().st_size / 1024 / 1024:.1f} МБ" if db_path.exists() else "запусти build")

    # 7. Чанки в индексе
    n_chunks = 0
    if db_path.exists():
        try:
            import sqlite_vec as sv
            db = sqlite3.connect(str(db_path))
            db.enable_load_extension(True); sv.load(db); db.enable_load_extension(False)
            n_chunks = db.execute(f"SELECT count(*) FROM {name}_chunks").fetchone()[0]
            db.close()
        except Exception:
            pass
    check("Чанки в индексе", n_chunks > 0, f"{n_chunks} чанков")

    # 8. Эмбеддер (ollama)
    emb_ok = False
    try:
        r = requests.get(f"{EMB_URL}/models", timeout=3)
        models = [m.get("id", "") for m in r.json().get("data", [])]
        emb_ok = EMB_MODEL in models
    except Exception:
        pass
    check("Эмбеддер (ollama)", emb_ok,
          f"{EMB_MODEL} на {EMB_URL}" if emb_ok else f"не отвечает: {EMB_URL}")

    # 9. sqlite-vec
    sv_ok = False
    try:
        import sqlite_vec; sv_ok = True
    except ImportError:
        pass
    check("sqlite-vec", sv_ok,
          "импортируется" if sv_ok else "pip install sqlite-vec")

    # 10. Скилл
    check(f"Скилл /{name}", skill_path.exists(),
          str(skill_path) if skill_path.exists() else "запусти install")

    # 11. Темы
    check("Темы", len(topics) > 0, f"{len(topics)} тем")

    # Вывод
    print(f"\n{'Проверка':<35} {'Статус':<8} Детали")
    print("─" * 75)
    ok_count = 0
    for name_c, status, detail in checks:
        mark = "✓" if status == "ок" else "✗"
        print(f"  {mark} {name_c:<33} {status:<8} {detail}")
        if status == "ок":
            ok_count += 1
    print(f"\n{ok_count}/{len(checks)} проверок пройдено")


# ═══════════════════════════════════════════════════════════════════════

def _arg(args, flag: str) -> str | None:
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]
    rest = sys.argv[2:]

    commands = {
        "init": cmd_init, "topic": cmd_topic, "add": cmd_add,
        "convert": cmd_convert, "build": cmd_build, "install": cmd_install,
        "search": cmd_search, "route": cmd_route, "read": cmd_read,
        "stats": cmd_stats, "doctor": cmd_doctor,
    }

    fn = commands.get(cmd)
    if fn:
        fn(rest)
    else:
        print(f"Неизвестная команда: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
