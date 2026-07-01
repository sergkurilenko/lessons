#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svacer_common.py — общий модуль для пайплайна классификации вердиктов Svacer.

Содержит код, разделяемый между:
  - build_dataset.py     (сбор датасета из локальных .snap-файлов)
  - train_verdict_model.py (обучение/дообучение модели)
  - predict_verdicts.py    (проставление вердиктов новым срабатываниям)

Только стандартная библиотека — модуль не тянет torch/transformers,
поэтому build_dataset.py запускается в лёгком окружении без GPU-стека.

Главное по сравнению со старой логикой:
  * Источник — НЕ Svacer API, а локальные .snap-файлы. Формат определяется
    автоматически (JSON/SARIF, gzip, zip, tar, SQLite); см. parse_snap().
  * Признаки модели НЕ содержат пост-ревью полей (комментарии, reviewed_by,
    review_ts, action, severity-от-ревьюера) — это утечка метки и train/serve
    skew. Эти поля сохраняются в сэмпле для аналитики/меток, но НЕ идут на вход.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import sqlite3
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

log = logging.getLogger("svacer")

# ============================================================
# Признаки, доступные ДО ревью (без утечки метки)
# ============================================================
# Эти спец-токены добавляются в токенизатор и используются в format_input_text.
# ВНИМАНИЕ: [COMMENT] намеренно убран — человеческие комментарии пишет ревьюер
# одновременно со статусом и на инференсе их нет.
FEATURE_SPECIAL_TOKENS = [
    "[RULE]", "[CLASS]", "[SEVERITY]", "[RELIABILITY]",
    "[TOOL]", "[LANG]", "[MSG]", "[DESC]", "[FUNC]", "[FILE]",
    "[CODE]", "[TRACE]",
]

# ============================================================
# Маппинг статусов в метки
# ============================================================
# Значения по умолчанию повторяют старый скрипт. В реальном развёртывании
# статусы могут отличаться (в т.ч. русские/числовые) — переопределяйте через
# --label-map config.json. build_dataset/train громко сообщат о неучтённых.
BINARY_LABEL_MAP_DEFAULT: Dict[str, int] = {
    "False Positive": 0, "False positive": 0, "FP": 0, "Not a bug": 0,
    "Confirmed": 1, "Critical": 1, "Open": 1,
}
BINARY_LABEL_MAP_WONTFIX_TP: Dict[str, int] = {
    **BINARY_LABEL_MAP_DEFAULT, "Won't fix": 1, "Wontfix": 1,
}
BINARY_LABEL_NAMES = ["FALSE_POSITIVE", "TRUE_POSITIVE"]

# Префиксы/теги авторазметки, которые надо исключать из обучающих данных.
AI_TAGS = {"AI", "ai", "auto", "llm"}
AI_COMMENT_PREFIX = "[AI]"


# ============================================================
# Ошибки парсинга
# ============================================================

class SnapError(Exception):
    """Базовая ошибка чтения .snap-файла."""


class SnapFormatError(SnapError):
    """Неопознанный (вероятно бинарный/проприетарный) формат."""


class SnapSchemaError(SnapError):
    """Формат опознан (например SQLite), но схема не распознана."""


# ============================================================
# Определение формата по содержимому
# ============================================================

def detect_format_bytes(data: bytes) -> str:
    """Грубое определение формата по сигнатуре. Возвращает один из:
    'sqlite' | 'zip' | 'gzip' | 'zstd' | 'xz' | 'bzip2' | 'tar' | 'json' | 'unknown'."""
    if data[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:4] == b"\x28\xb5\x2f\xfd":   # Zstandard (нативный формат .snap Svace)
        return "zstd"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:3] == b"BZh":
        return "bzip2"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    head = data[:64].lstrip()
    if head[:1] in (b"{", b"["):
        return "json"
    return "unknown"


def hexdump_head(data: bytes, n: int = 32) -> str:
    chunk = data[:n]
    hx = " ".join(f"{b:02x}" for b in chunk)
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{hx}    |{printable}|"


# ============================================================
# SARIF -> нормализованные сэмплы
# ============================================================

def _loc_fields(result: dict, run: dict) -> dict:
    """Извлекает локацию, сниппет, имя функции, контекст из артефактов и трассу."""
    out = {
        "file_path": "", "start_line": 0, "end_line": 0, "snippet": "",
        "func_signature": "", "file_content_snippet": "", "trace": [],
    }
    locs = result.get("locations") or []
    if not locs:
        return out

    phys = locs[0].get("physicalLocation", {}) or {}
    out["file_path"] = (phys.get("artifactLocation", {}) or {}).get("uri", "")
    region = phys.get("region", {}) or {}
    out["start_line"] = region.get("startLine", 0) or 0
    out["end_line"] = region.get("endLine", out["start_line"]) or out["start_line"]

    ctx = phys.get("contextRegion", {}) or {}
    if ctx.get("snippet"):
        out["snippet"] = ctx["snippet"].get("text", "")
    elif region.get("snippet"):
        out["snippet"] = region["snippet"].get("text", "")

    for ll in locs[0].get("logicalLocations", []) or []:
        if ll.get("kind") == "function":
            out["func_signature"] = ll.get("fullyQualifiedName", "")
            break

    # Код из embedded-артефактов (when exported with_contents)
    art_idx = (phys.get("artifactLocation", {}) or {}).get("index")
    if art_idx is not None:
        artifacts = run.get("artifacts", []) or []
        if 0 <= art_idx < len(artifacts):
            full_text = (artifacts[art_idx].get("contents") or {}).get("text", "")
            if full_text and out["start_line"] > 0:
                lines = full_text.split("\n")
                lo = max(0, out["start_line"] - 11)
                hi = min(len(lines), out["end_line"] + 10)
                out["file_content_snippet"] = "\n".join(lines[lo:hi])

    # Трасса (первый codeFlow / threadFlow, до 20 шагов)
    for cf in (result.get("codeFlows") or [])[:1]:
        for tf in (cf.get("threadFlows") or [])[:1]:
            for tfl in (tf.get("locations") or [])[:20]:
                loc = tfl.get("location", {}) or {}
                pl = loc.get("physicalLocation", {}) or {}
                out["trace"].append({
                    "file": (pl.get("artifactLocation", {}) or {}).get("uri", ""),
                    "line": (pl.get("region", {}) or {}).get("startLine", 0),
                    "column": (pl.get("region", {}) or {}).get("startColumn", 0),
                    "message": (loc.get("message") or {}).get("text", ""),
                })
    return out


def iter_findings_from_sarif(sarif: dict) -> Iterator[dict]:
    """Возвращает нормализованные сэмплы из SARIF-документа.

    Возвращает ВСЕ срабатывания (в т.ч. без статуса и с AI-тегом). Фильтрацию
    под обучение/инференс делает вызывающий код (см. is_human_labeled / is_ai)."""
    for run in sarif.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules_map = {r.get("id"): r for r in (driver.get("rules") or [])}

        for result in run.get("results", []) or []:
            props = result.get("properties") or {}
            rule_id = result.get("ruleId", "") or ""
            rule = rules_map.get(rule_id, {}) or {}

            loc = _loc_fields(result, run)

            # Человеческие комментарии (исключая [AI]) — храним для аналитики,
            # на вход модели НЕ идут.
            human_comments = []
            for c in props.get("comments", []) or []:
                text = c.get("text", "") or ""
                if text.startswith(AI_COMMENT_PREFIX):
                    continue
                human_comments.append({
                    "text": text,
                    "author": c.get("createdBy", ""),
                    "timestamp": c.get("createTs", ""),
                })

            yield {
                # --- идентификация / группировка ---
                "invariant": props.get("invariant", "") or "",
                "snapshot_id": props.get("snapshot_id", "") or "",
                # --- признаки модели (доступны до ревью) ---
                "rule_id": rule_id,
                "message": (result.get("message") or {}).get("text", "") or "",
                "full_description": (rule.get("fullDescription") or {}).get("text", "") or "",
                "short_description": (rule.get("shortDescription") or {}).get("text", "") or "",
                "warn_class": props.get("warnClass", "") or "",
                "tool": props.get("tool", "") or "",
                "mtid": props.get("mtid", "") or "",
                "lang": props.get("lang", "") or "",
                "checker_severity": props.get("checker_severity", "") or "",
                "checker_reliability": props.get("checker_reliability", "") or "",
                "orig_func": props.get("origFunc", "") or "",
                **loc,
                # --- метка и пост-ревью поля (НЕ признаки) ---
                "status": props.get("status", "") or "",
                "tags": list(props.get("tags") or []),
                "action": props.get("action", "") or "",
                "review_severity": props.get("severity", "") or "",
                "reviewed_by": props.get("reviewed_by", "") or "",
                "review_ts": props.get("review_ts", "") or "",
                "human_comments": human_comments,
            }


# ============================================================
# Нативный (не-SARIF) JSON Svacer — best-effort
# ============================================================
# Схема нативного дампа точно не известна, поэтому это эвристика: ищем список
# срабатываний под распространёнными ключами и маппим имена полей с фолбэками.
_NATIVE_LIST_KEYS = ("results", "findings", "warnings", "warns", "issues", "markers")
_FIELD_ALIASES = {
    "invariant": ("invariant", "inv", "fingerprint", "hash"),
    "rule_id": ("ruleId", "rule_id", "rule", "checker", "checkerId"),
    "message": ("message", "msg", "text", "title"),
    "warn_class": ("warnClass", "warn_class", "class", "category"),
    "tool": ("tool", "analyzer", "engine"),
    "lang": ("lang", "language"),
    "checker_severity": ("checker_severity", "severity", "sev"),
    "checker_reliability": ("checker_reliability", "reliability", "confidence"),
    "file_path": ("file", "filePath", "file_path", "path", "uri"),
    "start_line": ("line", "startLine", "start_line", "lineNumber"),
    "status": ("status", "verdict", "mark", "state"),
}


def _first_alias(d: dict, names: Tuple[str, ...], default=""):
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return default


def _find_finding_lists(obj: Any) -> Iterator[List[dict]]:
    """Рекурсивно ищет в JSON списки словарей под характерными ключами."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _NATIVE_LIST_KEYS and isinstance(v, list) and v and isinstance(v[0], dict):
                yield v
            else:
                yield from _find_finding_lists(v)
    elif isinstance(obj, list):
        # Список словарей на верхнем уровне тоже считаем findings.
        if obj and isinstance(obj[0], dict) and any(
            a in obj[0] for a in ("ruleId", "rule", "warnClass", "status", "message")
        ):
            yield obj
        else:
            for it in obj:
                yield from _find_finding_lists(it)


def iter_findings_from_native(obj: Any) -> Iterator[dict]:
    found_any = False
    for lst in _find_finding_lists(obj):
        for it in lst:
            if not isinstance(it, dict):
                continue
            found_any = True
            sample = {
                "invariant": str(_first_alias(it, _FIELD_ALIASES["invariant"])),
                "snapshot_id": "",
                "rule_id": str(_first_alias(it, _FIELD_ALIASES["rule_id"])),
                "message": str(_first_alias(it, _FIELD_ALIASES["message"])),
                "full_description": "", "short_description": "",
                "warn_class": str(_first_alias(it, _FIELD_ALIASES["warn_class"])),
                "tool": str(_first_alias(it, _FIELD_ALIASES["tool"])),
                "mtid": "", "lang": str(_first_alias(it, _FIELD_ALIASES["lang"])),
                "checker_severity": str(_first_alias(it, _FIELD_ALIASES["checker_severity"])),
                "checker_reliability": str(_first_alias(it, _FIELD_ALIASES["checker_reliability"])),
                "orig_func": "",
                "file_path": str(_first_alias(it, _FIELD_ALIASES["file_path"])),
                "start_line": int(_first_alias(it, _FIELD_ALIASES["start_line"], 0) or 0),
                "end_line": 0, "snippet": "", "func_signature": "",
                "file_content_snippet": "", "trace": [],
                "status": str(_first_alias(it, _FIELD_ALIASES["status"])),
                "tags": list(it.get("tags") or []),
                "action": "", "review_severity": "",
                "reviewed_by": str(it.get("reviewed_by", "") or ""),
                "review_ts": str(it.get("review_ts", "") or ""),
                "human_comments": [],
            }
            yield sample
    if not found_any:
        log.debug("native JSON: список срабатываний не найден")


# ============================================================
# SQLite-снапшоты — диагностика + best-effort
# ============================================================

# Сигналы имён колонок, по которым угадываем таблицу срабатываний.
_SQLITE_COL_SIGNALS = ("invariant", "warn", "rule", "checker", "status", "msg", "message", "verdict")


def sqlite_schema(path: str) -> str:
    """Возвращает текстовое описание схемы (для --inspect)."""
    out = []
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        for (name,) in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall():
            cols = cur.execute(f'PRAGMA table_info("{name}")').fetchall()
            colnames = ", ".join(c[1] for c in cols)
            try:
                n = cur.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            except sqlite3.Error:
                n = "?"
            out.append(f"  {name} ({n} rows): {colnames}")
    finally:
        con.close()
    return "\n".join(out) if out else "  (таблиц не найдено)"


def iter_findings_from_sqlite(path: str) -> Iterator[dict]:
    """Best-effort извлечение из SQLite. Берёт таблицу с максимальным числом
    «сигнальных» колонок. Если ничего похожего — SnapSchemaError со схемой."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        best, best_score = None, 0
        for t in tables:
            cols = [c[1].lower() for c in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            score = sum(any(sig in c for c in cols) for sig in _SQLITE_COL_SIGNALS)
            if score > best_score:
                best, best_score = t, score
        if best is None or best_score < 3:
            raise SnapSchemaError(
                "SQLite-схема не распознана. Таблицы:\n" + sqlite_schema(path)
            )
        log.debug("SQLite: таблица срабатываний = %s (score=%d)", best, best_score)
        for row in cur.execute(f'SELECT * FROM "{best}"'):
            d = {k.lower(): row[k] for k in row.keys()}
            yield {
                "invariant": str(_first_alias(d, _FIELD_ALIASES["invariant"])),
                "snapshot_id": "",
                "rule_id": str(_first_alias(d, _FIELD_ALIASES["rule_id"])),
                "message": str(_first_alias(d, _FIELD_ALIASES["message"])),
                "full_description": "", "short_description": "",
                "warn_class": str(_first_alias(d, _FIELD_ALIASES["warn_class"])),
                "tool": str(_first_alias(d, _FIELD_ALIASES["tool"])),
                "mtid": "", "lang": str(_first_alias(d, _FIELD_ALIASES["lang"])),
                "checker_severity": str(_first_alias(d, _FIELD_ALIASES["checker_severity"])),
                "checker_reliability": str(_first_alias(d, _FIELD_ALIASES["checker_reliability"])),
                "orig_func": "",
                "file_path": str(_first_alias(d, _FIELD_ALIASES["file_path"])),
                "start_line": int(_first_alias(d, _FIELD_ALIASES["start_line"], 0) or 0),
                "end_line": 0, "snippet": "", "func_signature": "",
                "file_content_snippet": "", "trace": [],
                "status": str(_first_alias(d, _FIELD_ALIASES["status"])),
                "tags": [], "action": "", "review_severity": "",
                "reviewed_by": "", "review_ts": "", "human_comments": [],
            }
    finally:
        con.close()


# ============================================================
# Диспетчер парсинга .snap
# ============================================================

_MAX_RECURSION = 4
# Имена членов архива, которые имеет смысл парсить.
_ARCHIVE_PARSE_EXT = (".sarif", ".json", ".jsonl", ".snap", ".sqlite", ".db")


# ============================================================
# Распаковка контейнеров (zstd/xz/bzip2)
# ============================================================

def _zstd_decompress(data: bytes) -> bytes:
    """Распаковка zstd. Перебирает бэкенды: zstandard -> pyzstd ->
    stdlib(compression.zstd, 3.14+) -> утилита zstd. Кадры без указанного
    размера и несколько кадров подряд обрабатываются потоково."""
    # 1) zstandard (наиболее распространён)
    try:
        import zstandard as _zstd
    except ImportError:
        _zstd = None
    if _zstd is not None:
        dctx = _zstd.ZstdDecompressor()
        try:
            try:  # потоковое чтение через границы кадров (новые версии)
                return dctx.stream_reader(io.BytesIO(data), read_across_frames=True).read()
            except TypeError:
                return dctx.stream_reader(io.BytesIO(data)).read()
        except Exception:  # noqa: BLE001 — пробуем мультикадровую склейку
            out, off = bytearray(), 0
            while off < len(data):
                rdr = dctx.stream_reader(io.BytesIO(data[off:]))
                chunk = rdr.read()
                if not chunk:
                    break
                out += chunk
                off += rdr.tell() if hasattr(rdr, "tell") else len(data)
            if out:
                return bytes(out)
    # 2) pyzstd
    try:
        import pyzstd
        return pyzstd.decompress(data)
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass
    # 3) stdlib (Python 3.14+)
    try:
        from compression import zstd as _czstd  # type: ignore
        return _czstd.decompress(data)
    except Exception:  # noqa: BLE001
        pass
    # 4) утилита zstd
    import shutil
    import subprocess
    exe = shutil.which("zstd")
    if exe:
        p = subprocess.run([exe, "-d", "-c"], input=data, capture_output=True)
        if p.returncode == 0:
            return p.stdout
    raise SnapFormatError(
        "zstd: нет доступного декомпрессора. Установите `pip install zstandard` "
        "(или утилиту командной строки `zstd`).")


def _decompress(fmt: str, data: bytes) -> bytes:
    if fmt == "zstd":
        return _zstd_decompress(data)
    if fmt == "gzip":
        return gzip.decompress(data)
    if fmt == "xz":
        import lzma
        return lzma.decompress(data)
    if fmt == "bzip2":
        import bz2
        return bz2.decompress(data)
    raise SnapFormatError(f"неизвестный компрессор: {fmt}")


# ============================================================
# Schema-less декодер protobuf (нативный формат снапшота Svace)
# ============================================================
# Внутри распакованного .snap лежит protobuf без публичной .proto-схемы.
# Декодируем wire-format «вслепую» (как `protoc --decode_raw`): этого хватает,
# чтобы (а) показать структуру полей в --inspect и (б) после ручного маппинга
# номеров полей извлечь срабатывания. Маппинг задаётся ниже, после --inspect.

def _read_varint(data: bytes, i: int) -> Tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(data):
            raise ValueError("varint вышел за границу буфера")
        b = data[i]; i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 70:
            raise ValueError("слишком длинный varint")


def decode_protobuf_raw(data: bytes) -> List[Tuple[int, int, Any]]:
    """Декодирует один уровень protobuf -> список (field_number, wire_type, value).
    Для wire_type 2 (length-delimited) value — это сырые bytes (нестрого: строка
    или вложенное сообщение; различаются на этапе обхода). Бросает ValueError,
    если байты не похожи на корректный protobuf."""
    out: List[Tuple[int, int, Any]] = []
    i, n = 0, len(data)
    while i < n:
        key, i = _read_varint(data, i)
        fnum, wt = key >> 3, key & 7
        if fnum == 0:
            raise ValueError("field number 0")
        if wt == 0:
            val, i = _read_varint(data, i)
        elif wt == 1:
            if i + 8 > n:
                raise ValueError("обрезанный i64")
            val = int.from_bytes(data[i:i + 8], "little"); i += 8
        elif wt == 5:
            if i + 4 > n:
                raise ValueError("обрезанный i32")
            val = int.from_bytes(data[i:i + 4], "little"); i += 4
        elif wt == 2:
            ln, i = _read_varint(data, i)
            if i + ln > n:
                raise ValueError("обрезанное length-delimited поле")
            val = data[i:i + ln]; i += ln
        else:  # 3/4 (groups, deprecated), 6/7 — не поддерживаем
            raise ValueError(f"неподдерживаемый wire type {wt}")
        out.append((fnum, wt, val))
    return out


def _bytes_repr(b: bytes) -> Optional[str]:
    """Если bytes — это «в основном печатный» UTF-8 текст, вернуть строку, иначе None."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return ""
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return s if printable / len(s) >= 0.85 else None


def _decode_level(buf: bytes) -> Dict[int, List[Tuple[int, Any]]]:
    """raw bytes -> {field_number: [(wire_type, value), ...]} (или пусто, если не protobuf)."""
    lvl: Dict[int, List[Tuple[int, Any]]] = defaultdict(list)
    try:
        for fnum, wt, val in decode_protobuf_raw(buf):
            lvl[fnum].append((wt, val))
    except ValueError:
        return {}
    return lvl


def protobuf_skeleton(data: bytes, max_samples: int = 3, max_depth: int = 6) -> Optional[str]:
    """Текстовое описание структуры protobuf для ручного маппинга полей.
    Для каждого пути field выводит: тип(ы), число вхождений и примеры значений."""
    agg: Dict[str, Dict[str, Any]] = {}

    def walk(buf: bytes, prefix: str, depth: int) -> bool:
        try:
            fields = decode_protobuf_raw(buf)
        except ValueError:
            return False
        if not fields:
            return False
        for fnum, wt, val in fields:
            path = f"{prefix}.{fnum}" if prefix else str(fnum)
            e = agg.setdefault(path, {"wt": set(), "count": 0, "samples": []})
            e["count"] += 1
            if wt == 2:
                nested = depth < max_depth and walk(val, path, depth + 1)
                if nested:
                    e["wt"].add("msg")
                else:
                    s = _bytes_repr(val)
                    if s is not None:
                        e["wt"].add("str")
                        if len(e["samples"]) < max_samples:
                            e["samples"].append(repr(s[:60]))
                    else:
                        e["wt"].add("bytes")
                        if len(e["samples"]) < max_samples:
                            e["samples"].append(f"<{len(val)}B>")
            else:
                e["wt"].add({0: "varint", 1: "i64", 5: "i32"}[wt])
                if len(e["samples"]) < max_samples:
                    e["samples"].append(str(val))
        return True

    if not walk(data, "", 0):
        return None
    lines = []
    for path in sorted(agg, key=lambda p: [int(x) for x in p.split(".")]):
        e = agg[path]
        wt = "/".join(sorted(e["wt"]))
        lines.append(f"    field {path:<10s} {wt:<10s} ×{e['count']:<6d} "
                     f"{'; '.join(e['samples'])}")
    return "\n".join(lines)


# --- Маппинг полей нативного снапшота Svace -------------------------------
# ЗАПОЛНЯЕТСЯ после просмотра вывода `--inspect`. Пока пусто — извлечение из
# protobuf невозможно, и parse_snap честно сообщит об этом со скелетом схемы.
#   _PROTO_RECORD_PATH — путь до ПОВТОРЯЮЩЕГОСЯ сообщения-срабатывания,
#                        например "1" или "1.2".
#   SVACE_PROTO_FIELDS — пути ОТНОСИТЕЛЬНО записи -> каноническое имя поля
#                        (rule_id/message/file_path/start_line/status/...).
_PROTO_RECORD_PATH: str = ""
SVACE_PROTO_FIELDS: Dict[str, str] = {}
# Опционально: декодирование числовых enum-полей в строки. Заполняется вместе
# с маппингом, если поле хранится как int (часто так со status/severity).
#   _PROTO_ENUMS = {"status": {0: "False Positive", 1: "Confirmed"}}
_PROTO_ENUMS: Dict[str, Dict[int, str]] = {}


def _proto_leaf(buf: bytes, path: str) -> Any:
    """Спускается по пути ('3' или '7.1') и возвращает лист (str/int) или None."""
    cur = buf
    parts = [int(p) for p in path.split(".")]
    for depth, fnum in enumerate(parts):
        lvl = _decode_level(cur)
        if fnum not in lvl:
            return None
        wt, val = lvl[fnum][0]
        if depth == len(parts) - 1:
            if wt == 2:
                s = _bytes_repr(val)
                return s if s is not None else None
            return val
        if wt != 2:
            return None
        cur = val
    return None


def _iter_records(buf: bytes, record_path: str) -> Iterator[bytes]:
    """Возвращает сырые bytes каждого повторяющегося record по пути record_path."""
    parts = [int(p) for p in record_path.split(".")]

    def descend(b: bytes, ps: List[int]) -> Iterator[bytes]:
        lvl = _decode_level(b)
        fnum = ps[0]
        if fnum not in lvl:
            return
        if len(ps) == 1:
            for wt, val in lvl[fnum]:
                if wt == 2:
                    yield val
        else:
            wt, val = lvl[fnum][0]
            if wt == 2:
                yield from descend(val, ps[1:])

    yield from descend(buf, parts)


def iter_findings_from_protobuf(data: bytes) -> Iterator[dict]:
    """Извлекает срабатывания из распакованного protobuf по маппингу.
    Если маппинг не задан — бросает SnapSchemaError со скелетом схемы."""
    if not (_PROTO_RECORD_PATH and SVACE_PROTO_FIELDS):
        skel = protobuf_skeleton(data) or "(структура не распозналась как protobuf)"
        raise SnapSchemaError(
            "Нативный protobuf-снапшот Svace распакован, но схема полей неизвестна. "
            "Запустите `build_dataset.py --root <dir> --inspect` и пришлите вывод — "
            "по нему задаются _PROTO_RECORD_PATH и SVACE_PROTO_FIELDS.\n"
            "Обнаруженная структура:\n" + skel)
    for rec in _iter_records(data, _PROTO_RECORD_PATH):
        canon: Dict[str, Any] = {}
        for rel_path, name in SVACE_PROTO_FIELDS.items():
            v = _proto_leaf(rec, rel_path)
            if v is None or v == "":
                continue
            if name in _PROTO_ENUMS and isinstance(v, int):
                v = _PROTO_ENUMS[name].get(v, str(v))
            canon[name] = v
        if canon:
            # нормализуем тем же путём, что и нативный JSON (алиасы совпадают)
            yield from iter_findings_from_native([canon])


# ============================================================
# Нативный снапшот Svace (zstd → JSON-реляционный контейнер)
# ============================================================
# Реальный .snap — zstd-сжатый контейнер с бинарной обвязкой, ВНУТРИ которой
# лежат JSON-документы нескольких типов, связанные по id. Обвязка нестрогая
# (фиксированные поля, выравнивание), поэтому надёжнее всего извлечь top-level
# JSON-объекты брейс-матчингом и сшить их — формат обвязки игнорируем.
#
# Граф связей (выяснен по реальному снапшоту):
#   link.markerId  == warning.id        (warning — само срабатывание)
#   link.traceId   == trace.id          (трасса данных)
#   link.invariant == marker.groupRef   (marker — вердикт ревьюера; может не быть)
# При нескольких маркерах на одном groupRef берём активный (isActive) и новейший.
# trace и warning.optional_fields хранятся как base64(JSON).

def _scan_json_objects(buf: bytes) -> List[Any]:
    """Все top-level JSON-объекты из бинарного буфера. Кандидаты ищем по '{"'
    (ключи JSON всегда строки), а сам разбор делает C-ускоренный
    JSONDecoder.raw_decode — без побайтового цикла на Python, иначе на больших
    снапшотах это O(n²) из-за стрэй-байтов '{' в бинарной обвязке.

    errors='surrogateescape' делает декодирование обратимым и 1:1 для
    невалидных байтов обвязки (мы их всё равно пропускаем); внутри валидных
    JSON-объектов UTF-8 корректен, поэтому объекты получаются с верным юникодом."""
    s = buf.decode("utf-8", errors="surrogateescape")
    dec = json.JSONDecoder()
    objs: List[Any] = []
    i, n = 0, len(s)
    while i < n:
        j = s.find('{"', i)
        if j < 0:
            break
        try:
            obj, end = dec.raw_decode(s, j)
        except ValueError:
            i = j + 2  # стрэй '{"' в бинарных данных — идём дальше
            continue
        objs.append(obj)
        i = end
    return objs


def _b64json(s: Optional[str]) -> dict:
    if not s:
        return {}
    try:
        import base64
        return json.loads(base64.b64decode(s))
    except Exception:  # noqa: BLE001
        return {}


def _svace_trace_steps(trace_field: Any) -> List[dict]:
    """trace = base64(JSON {traces:[{role, locations:[{file,line,info}]}]})."""
    data = _b64json(trace_field) if isinstance(trace_field, str) else trace_field
    steps: List[dict] = []
    if not isinstance(data, dict):
        return steps
    for grp in data.get("traces", []) or []:
        role = grp.get("role", "")
        for loc in grp.get("locations", []) or []:
            steps.append({"file": loc.get("file", ""), "line": loc.get("line", 0),
                          "message": role or loc.get("info", "")})
    return steps


def _pick_marker(ms: List[dict]) -> dict:
    """Из нескольких маркеров на groupRef выбираем активный и самый свежий."""
    pool = [m for m in ms if m.get("isActive")] or ms
    return max(pool, key=lambda m: ((m.get("createTs") or {}).get("seconds", 0)))


def looks_like_svace_snap(buf: bytes) -> bool:
    """Быстрая эвристика: в (распакованном) буфере есть записи-срабатывания Svace."""
    return b'"warnclass"' in buf and b'"mtid"' in buf


def _svace_checker_map(datas: List[dict]) -> Dict[str, dict]:
    """data-блобы (×N) — это base64(JSON) с метаданными чекеров. Возвращает
    {checker_id: {reliability, severity, cwe, group}}."""
    out: Dict[str, dict] = {}
    for d in datas:
        c = _b64json(d.get("data"))
        cid = c.get("checker_id")
        if not cid:
            continue
        det = c.get("details") or {}
        cwe = det.get("cwe")
        out[cid] = {
            "reliability": str(c.get("reliability", "")),
            "severity": str(c.get("severity", "")),
            "cwe": (cwe[0] if isinstance(cwe, list) and cwe else str(cwe or "")),
            "group": str(det.get("group", "")),
        }
    return out


def iter_findings_from_svace_snap(data: bytes) -> Iterator[dict]:
    """Извлекает срабатывания из распакованного нативного снапшота Svace,
    сшивая warnings + markers(вердикты) + traces по id. Дополнительно тянет
    метаданные чекеров (reliability/severity/CWE) и инженерные признаки в духе
    статьи ИСП РАН: теги warnclass и число предупреждений в файле/функции."""
    warnings: List[dict] = []
    links: List[dict] = []
    markers: List[dict] = []
    traces: List[dict] = []
    datas: List[dict] = []
    for o in _scan_json_objects(data):
        if not isinstance(o, dict):
            continue
        keys = o.keys()
        if {"msg", "warnclass", "file", "line", "mtid"} <= keys:
            warnings.append(o)
        elif {"invariant", "markerId", "traceId", "localId"} <= keys:
            links.append(o)
        elif {"status", "groupRef", "action"} <= keys:
            markers.append(o)
        elif keys == {"id", "trace"}:
            traces.append(o)
        elif keys == {"data", "id"}:
            datas.append(o)
    if not warnings:
        return  # не снапшот Svace

    w_by_id = {w["id"]: w for w in warnings}
    tr_by_id = {t["id"]: t.get("trace") for t in traces}
    mk_by_group: Dict[str, List[dict]] = defaultdict(list)
    for m in markers:
        mk_by_group[m["groupRef"]].append(m)
    checkers = _svace_checker_map(datas)

    # Инженерные признаки уровня снапшота (как в статье): сколько предупреждений
    # в том же файле и в той же функции. Считаем по всем срабатываниям снапшота.
    n_by_file: Counter = Counter(w.get("file", "") for w in warnings)
    n_by_func: Counter = Counter((w.get("file", ""), w.get("function", "")) for w in warnings)

    for ln in links:
        w = w_by_id.get(ln.get("markerId"))
        if not w:
            continue
        ms = mk_by_group.get(ln.get("invariant"))
        marker = _pick_marker(ms) if ms else None
        opt = _b64json(w.get("optional_fields"))
        warnclass = str(w.get("warnclass", ""))
        parts = warnclass.split(".")
        defect_type = parts[0]
        warn_tags = parts[1:]                         # .RET.STAT.LIB.PROC.TEST ...
        chk = checkers.get(defect_type, {})
        review_ts = ""
        if marker and isinstance(marker.get("createTs"), dict):
            review_ts = str(marker["createTs"].get("seconds", ""))
        file_path = str(w.get("file", ""))
        func = str(w.get("function", ""))
        yield {
            "invariant": str(ln.get("invariant", "")),
            "snapshot_id": str(ln.get("snapshotId", "")),
            "rule_id": warnclass,                       # полный класс (для target-encoding)
            "message": str(w.get("msg", "")),
            "full_description": "", "short_description": "",
            "warn_class": defect_type,                  # семейство = тип дефекта
            "defect_type": defect_type,
            "warn_tags": warn_tags,                     # теги класса (multi-hot в трейнере)
            "cwe": chk.get("cwe", ""),
            "checker_group": chk.get("group", ""),
            "tool": str(w.get("tool", "")),
            "mtid": str(w.get("mtid", "")),
            "lang": str(w.get("lang", "")),
            "checker_severity": chk.get("severity", ""),
            "checker_reliability": chk.get("reliability", ""),
            "orig_func": str(opt.get("origFunc", "") or func),
            "file_path": file_path,
            "start_line": int(w.get("line", 0) or 0),
            "end_line": 0, "snippet": "",
            "func_signature": func,
            "file_content_snippet": "",
            "n_warnings_file": int(n_by_file.get(file_path, 0)),
            "n_warnings_func": int(n_by_func.get((file_path, func), 0)),
            "trace": _svace_trace_steps(tr_by_id.get(ln.get("traceId"))),
            "status": str(marker.get("status", "")) if marker else "",
            "tags": [],
            "action": str(marker.get("action", "")) if marker else "",
            "review_severity": str(marker.get("severity", "")) if marker else "",
            "reviewed_by": str(marker.get("createdBy", "")) if marker else "",
            "review_ts": review_ts,
            "human_comments": [],
        }


def _route_json(text: str) -> List[dict]:
    """Парсит JSON/JSONL-текст и маршрутизирует на SARIF или нативный экстрактор."""
    text = text.strip()
    if not text:
        return []
    # Пытаемся как единый JSON.
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # JSONL — по объекту на строку.
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.extend(iter_findings_from_native(json.loads(line)))
            except json.JSONDecodeError:
                pass
        return out

    if isinstance(obj, dict) and ("runs" in obj or str(obj.get("$schema", "")).find("sarif") >= 0):
        return list(iter_findings_from_sarif(obj))
    return list(iter_findings_from_native(obj))


def _parse_bytes(data: bytes, name: str, depth: int) -> List[dict]:
    if depth > _MAX_RECURSION:
        raise SnapFormatError(f"{name}: превышена глубина вложенности архивов")
    fmt = detect_format_bytes(data)

    if fmt == "json":
        return _route_json(data.decode("utf-8", errors="replace"))

    if fmt == "gzip":
        return _parse_bytes(gzip.decompress(data), name + "(gz)", depth + 1)

    if fmt in ("zstd", "xz", "bzip2"):
        return _parse_bytes(_decompress(fmt, data), f"{name}({fmt})", depth + 1)

    if fmt == "zip":
        out: List[dict] = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                if member.lower().endswith(_ARCHIVE_PARSE_EXT):
                    out.extend(_parse_bytes(zf.read(member), f"{name}!{member}", depth + 1))
        return out

    if fmt == "tar":
        out = []
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                if m.name.lower().endswith(_ARCHIVE_PARSE_EXT):
                    f = tf.extractfile(m)
                    if f:
                        out.extend(_parse_bytes(f.read(), f"{name}!{m.name}", depth + 1))
        return out

    if fmt == "sqlite":
        # sqlite3 удобнее открывать с диска — пишем во временный файл.
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            return list(iter_findings_from_sqlite(tmp_path))
        finally:
            os.unlink(tmp_path)

    # Нативный снапшот Svace: zstd распакован в JSON-реляционный контейнер.
    if looks_like_svace_snap(data):
        out = list(iter_findings_from_svace_snap(data))
        if out:
            return out

    # Иначе — возможно, protobuf без схемы.
    if _decode_level(data):
        return list(iter_findings_from_protobuf(data))

    raise SnapFormatError(
        f"{name}: неопознанный формат. Первые байты:\n  {hexdump_head(data)}"
    )


def parse_snap(path: str, stamp: Optional[dict] = None) -> List[dict]:
    """Парсит один .snap-файл -> список нормализованных сэмплов.

    stamp — доп. поля (source_dir, source_snap), которые проставляются каждому
    сэмплу. Бросает SnapError при нераспознанном формате/схеме."""
    # SQLite на диске открываем напрямую (без чтения в память целиком).
    with open(path, "rb") as f:
        head = f.read(16)
    if head == b"SQLite format 3\x00":
        samples = list(iter_findings_from_sqlite(path))
    else:
        with open(path, "rb") as f:
            samples = _parse_bytes(f.read(), os.path.basename(path), 0)

    if stamp:
        for s in samples:
            s.update(stamp)
    return samples


def _introspect_bytes(data: bytes, depth: int = 0) -> str:
    """Рекурсивно описывает, что внутри: распаковывает контейнеры и доходит
    до JSON/SARIF/SQLite/protobuf."""
    fmt = detect_format_bytes(data)
    if fmt in ("zstd", "gzip", "xz", "bzip2"):
        if depth > _MAX_RECURSION:
            return f"{fmt} (слишком глубокая вложенность)"
        try:
            inner = _decompress(fmt, data)
        except SnapError as e:
            return f"{fmt} (не удалось распаковать: {e})"
        return f"{fmt} → {_introspect_bytes(inner, depth + 1)}"
    if fmt == "sqlite":
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            tmp.write(data); tmp_path = tmp.name
        try:
            return f"sqlite\n{sqlite_schema(tmp_path)}"
        finally:
            os.unlink(tmp_path)
    if fmt == "json":
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
            if isinstance(obj, dict):
                is_sarif = "runs" in obj or "sarif" in str(obj.get("$schema", ""))
                keys = ", ".join(list(obj.keys())[:12])
                return f"json ({'SARIF' if is_sarif else 'native'}); ключи: {keys}"
            return f"json (массив, {len(obj)} элементов)"
        except Exception as e:  # noqa: BLE001
            return f"json (не распарсился: {e})"
    if fmt in ("zip", "tar"):
        return f"{fmt} (архив)"
    # Нативный снапшот Svace (JSON-реляционный контейнер)?
    if looks_like_svace_snap(data):
        objs = _scan_json_objects(data)
        w = sum(1 for o in objs if isinstance(o, dict)
                and {"msg", "warnclass", "file", "line", "mtid"} <= o.keys())
        mk = sum(1 for o in objs if isinstance(o, dict)
                 and {"status", "groupRef", "action"} <= o.keys())
        tr = sum(1 for o in objs if isinstance(o, dict) and o.keys() == {"id", "trace"})
        reviewed = len(list(iter_findings_from_svace_snap(data)))
        labeled = sum(1 for s in iter_findings_from_svace_snap(data) if s["status"])
        return (f"Svace snapshot (JSON-реляционный): срабатываний={w}, "
                f"вердиктов(маркеров)={mk}, трасс={tr}; собрано сэмплов={reviewed}, "
                f"из них с вердиктом={labeled}")
    # unknown -> пробуем protobuf и показываем скелет полей
    skel = protobuf_skeleton(data)
    if skel:
        return ("protobuf (schema-less). Структура [field путь | тип | ×кол-во | "
                "примеры], нужна для маппинга полей:\n" + skel)
    return f"unknown; {hexdump_head(data)}"


def inspect_snap(path: str) -> str:
    """Диагностика формата .snap (распаковывает zstd/gzip/... и доходит до сути)."""
    with open(path, "rb") as f:
        data = f.read()
    return _introspect_bytes(data)


# ============================================================
# Фильтры обучающих данных
# ============================================================

def is_ai(sample: dict) -> bool:
    """True, если сэмпл — авторазметка (исключаем из обучения)."""
    return bool(set(sample.get("tags") or []) & AI_TAGS)


def is_human_labeled(sample: dict) -> bool:
    """True, если есть человеческий статус и это не AI-разметка."""
    return bool(sample.get("status")) and not is_ai(sample)


# ============================================================
# Дедупликация по invariant (последняя ревью — побеждает)
# ============================================================

def dedup_samples(samples: List[dict]) -> Tuple[List[dict], Dict[str, Any]]:
    by_inv: Dict[str, List[dict]] = defaultdict(list)
    no_inv: List[dict] = []
    for s in samples:
        (by_inv[s["invariant"]].append(s) if s.get("invariant") else no_inv.append(s))

    out: List[dict] = []
    stats = {
        "total_before": len(samples), "unique_invariants": len(by_inv),
        "without_invariant": len(no_inv), "duplicates_removed": 0, "conflicts": [],
    }
    for inv, group in by_inv.items():
        group.sort(key=lambda x: x.get("review_ts") or "")
        best = group[-1]
        statuses = {s["status"] for s in group}
        if len(statuses) > 1:
            stats["conflicts"].append({
                "invariant": inv, "rule_id": best.get("rule_id", ""),
                "statuses": sorted(statuses), "count": len(group),
                "chosen_status": best["status"], "chosen_review_ts": best.get("review_ts", ""),
            })
        stats["duplicates_removed"] += len(group) - 1
        out.append(best)
    out.extend(no_inv)
    stats["total_after"] = len(out)
    stats["conflict_count"] = len(stats["conflicts"])
    return out, stats


# ============================================================
# Маппинг меток
# ============================================================

def build_label_map(samples, multiclass, wontfix_as_tp=False):
    if not multiclass:
        m = BINARY_LABEL_MAP_WONTFIX_TP if wontfix_as_tp else BINARY_LABEL_MAP_DEFAULT
        return dict(m), list(BINARY_LABEL_NAMES)
    statuses = sorted({s["status"] for s in samples if s.get("status")})
    return {s: i for i, s in enumerate(statuses)}, statuses


# ============================================================
# Формирование текстового входа модели (с аугментацией)
# ============================================================

def format_input_text(sample, max_snippet_lines=30, augment=False, rng=None):
    """Единый текстовый вход. При augment=True случайно выбрасываются секции.

    Содержит ТОЛЬКО до-ревью признаки. Пост-ревью поля (комментарии, действия,
    severity ревьюера) намеренно исключены."""
    import random as _random
    if rng is None:
        rng = _random.Random()
    parts: List[str] = []

    def _maybe(tag, text, drop_p=0.15):
        if not text:
            return
        if augment and rng.random() < drop_p:
            return
        parts.append(f"{tag} {text}")

    # Ключевые поля — не дропаются.
    if sample.get("rule_id"):
        parts.append(f"[RULE] {sample['rule_id']}")
    if sample.get("message"):
        parts.append(f"[MSG] {sample['message']}")

    _maybe("[CLASS]", sample.get("warn_class", ""), 0.1)
    sev, rel = sample.get("checker_severity", ""), sample.get("checker_reliability", "")
    if sev or rel:
        _maybe("[SEVERITY]", f"{sev} [RELIABILITY] {rel}", 0.1)
    tool, lang = sample.get("tool", ""), sample.get("lang", "")
    if tool or lang:
        _maybe("[TOOL]", f"{tool} [LANG] {lang}", 0.1)
    _maybe("[DESC]", sample.get("full_description") or sample.get("short_description", ""), 0.2)
    _maybe("[FUNC]", sample.get("func_signature") or sample.get("orig_func", ""), 0.15)
    if sample.get("file_path"):
        _maybe("[FILE]", f"{sample['file_path']}:{sample.get('start_line', 0)}", 0.15)

    code = sample.get("file_content_snippet") or sample.get("snippet", "")
    if code:
        lines = code.strip().split("\n")[:max_snippet_lines]
        if augment and len(lines) > 5 and rng.random() < 0.2:
            lines = lines[:rng.randint(3, len(lines))]
        parts.append("[CODE]\n" + "\n".join(lines))

    trace = sample.get("trace", [])
    if trace and not (augment and rng.random() < 0.15):
        tl = []
        for step in trace[:10]:
            if step.get("file"):
                tl.append(f"  {step['file']}:{step.get('line', 0)} {step.get('message', '')}".strip())
        if tl:
            parts.append("[TRACE]\n" + "\n".join(tl))

    return "\n".join(parts)


# ============================================================
# I/O JSONL
# ============================================================

def load_jsonl(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def save_jsonl(samples: Iterable[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
