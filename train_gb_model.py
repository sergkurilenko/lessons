#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_gb_model.py — классификатор вердиктов на градиентном бустинге (Svacer),
построенный по методу статьи ИСП РАН (Тяжкороб и др., 2025) об автоматической
классификации предупреждений Svace, с рядом улучшений.

Признаки (в духе статьи; метрик исходного кода в экспорте Svacer нет, поэтому
вместо них — признаки, которые статья и так ставит выше всего по важности):
  * детекторная точность — историческая доля истинных по классу предупреждения.
    Это признак №1 по важности в статье. Реализован через sklearn TargetEncoder
    с КРОСС-ФИТТИНГОМ внутри fit (статья считает «на обучающем наборе» — здесь
    то же, но без утечки в валидацию: train получает out-of-fold оценки, а
    val/test — оценку, обученную на train);
  * число предупреждений в файле и в функции (признаки №2–3 в статье);
  * теги класса (.RET/.STAT/.LIB/.PROC/.TEST/...) — multi-hot, как в статье;
  * тип дефекта (warn_class), tool, lang, а также reliability/severity/CWE
    чекера из метаданных снапшота;
  * длины/структурные признаки и (опционально) TF-IDF по тексту сообщения.

Отличия от статьи (улучшения):
  * корректный out-of-fold target-encoding вместо потенциально текущей оценки;
  * group-aware валидация (по файлу) против утечки почти-дублей между train/test
    (в статье — стратификация по типу дефекта, что может смешивать клоны);
  * PR-AUC как основная метрика (честнее accuracy/AUC-ROC при дисбалансе);
  * ранняя остановка по PR-AUC (быстрее и меньше переобучения);
  * отсечение редких классов в one-hot (--ohe-min-freq).

Бэкенды: lightgbm (по умолчанию), catboost (победитель в статье; требует
`pip install catboost`), hgb (sklearn HistGradientBoosting, без доп. зависимостей;
TF-IDF в этом режиме отключается). Дисбаланс лечится ОДНОЙ стратегией
(--imbalance balanced|none) через sample_weight. Порог подбирается под цель
(--threshold-objective f1|target_recall|target_precision).

Требуется: scikit-learn>=1.3, pandas, numpy, joblib (+ опц. lightgbm/catboost).
Рядом — svacer_common.py. Датасет — из build_dataset.py.

Обучение:
    python train_gb_model.py --data training_data.jsonl --wontfix-as-tp \
        --split group --group-key file --kfold 5 \
        --threshold-objective target_recall --threshold-target 0.9
    python train_gb_model.py --data training_data.jsonl --backend catboost --wontfix-as-tp

Инференс (формат вывода как у predict_verdicts.py):
    python build_dataset.py --root ./snaps --keep-all --output all.jsonl
    python train_gb_model.py --mode predict --model gb_model.joblib --data all.jsonl --output verdicts.jsonl
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import warnings
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from scipy import sparse

from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
)
from sklearn.model_selection import (
    GroupShuffleSplit,
    StratifiedGroupKFold,
    StratifiedKFold,
    train_test_split,
)
from sklearn.preprocessing import OneHotEncoder, TargetEncoder
from sklearn.utils.class_weight import compute_sample_weight

import svacer_common as sc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("train_gb_model")
warnings.filterwarnings("ignore", message=".*does not have valid feature names.*")

# ============================================================
# Признаки (ТОЛЬКО до-ревью поля — никакой утечки метки)
# ============================================================
# Низкокардинальные категориальные -> one-hot.
CAT_COLS = ["defect_type", "tool", "lang",
            "checker_severity", "checker_reliability", "cwe", "checker_group"]
# Высококардинальный класс -> target-encoding (детекторная точность).
TARGET_COLS = ["rule_id"]
# Теги класса -> multi-hot (binary bag).
TAGS_COL = "warn_tags_str"
# Числовые/структурные.
NUM_COLS = ["n_warnings_file", "n_warnings_func", "line_span", "msg_len", "desc_len",
            "snippet_len", "snippet_lines", "n_trace",
            "has_snippet", "has_trace", "has_func_sig", "has_description"]
# Текст -> TF-IDF (опционально, только lightgbm/catboost).
TEXT_COL = "text_blob"


def _sample_to_row(s: dict) -> dict:
    """Один нормализованный сэмпл -> строка признаков. Пост-ревью поля игнорируются."""
    msg = s.get("message", "") or ""
    desc = s.get("full_description") or s.get("short_description") or ""
    code = s.get("file_content_snippet") or s.get("snippet") or ""
    func = s.get("func_signature") or s.get("orig_func") or ""
    trace = s.get("trace") or []
    warnclass = str(s.get("rule_id") or s.get("warn_class") or "NA")
    defect = str(s.get("defect_type") or warnclass.split(".")[0] or "NA")
    tags = s.get("warn_tags")
    if not tags:  # обратная совместимость: вывести теги из полного класса
        tags = warnclass.split(".")[1:]
    try:
        span = max(0, int(s.get("end_line", 0) or 0) - int(s.get("start_line", 0) or 0))
    except (TypeError, ValueError):
        span = 0
    return {
        "rule_id": warnclass,
        "defect_type": defect,
        "warn_tags_str": " ".join(tags),
        "tool": str(s.get("tool") or "NA"),
        "lang": str(s.get("lang") or "NA"),
        "checker_severity": str(s.get("checker_severity") or "NA"),
        "checker_reliability": str(s.get("checker_reliability") or "NA"),
        "cwe": str(s.get("cwe") or "NA"),
        "checker_group": str(s.get("checker_group") or "NA"),
        "n_warnings_file": int(s.get("n_warnings_file", 0) or 0),
        "n_warnings_func": int(s.get("n_warnings_func", 0) or 0),
        "line_span": span,
        "msg_len": len(msg),
        "desc_len": len(desc),
        "snippet_len": len(code),
        "snippet_lines": code.count("\n") + 1 if code else 0,
        "n_trace": len(trace),
        "has_snippet": int(bool(code)),
        "has_trace": int(bool(trace)),
        "has_func_sig": int(bool(func)),
        "has_description": int(bool(desc)),
        "text_blob": (msg + " " + desc).strip(),
    }


def build_frame(samples: List[dict]) -> pd.DataFrame:
    df = pd.DataFrame([_sample_to_row(s) for s in samples])
    for c in CAT_COLS + TARGET_COLS:
        df[c] = df[c].astype(str)
    for c in NUM_COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    df[TAGS_COL] = df[TAGS_COL].fillna("").astype(str)
    df[TEXT_COL] = df[TEXT_COL].fillna("").astype(str)
    return df


# ============================================================
# Бэкенд бустинга
# ============================================================

def make_ohe(min_freq: int) -> OneHotEncoder:
    kw = dict(handle_unknown="ignore")
    if min_freq and min_freq > 1:
        kw["min_frequency"] = min_freq
    try:
        return OneHotEncoder(sparse_output=True, **kw)
    except TypeError:  # sklearn < 1.2
        return OneHotEncoder(sparse=True, **kw)


def resolve_backend(name: str) -> str:
    if name == "catboost":
        try:
            import catboost  # noqa: F401
            return "catboost"
        except ImportError:
            raise SystemExit("Бэкенд catboost запрошен, но не установлен "
                             "(pip install catboost). Или --backend lightgbm|hgb.")
    if name in ("lightgbm", "auto"):
        try:
            import lightgbm  # noqa: F401
            return "lightgbm"
        except ImportError:
            if name == "lightgbm":
                raise SystemExit("Бэкенд lightgbm не установлен (pip install lightgbm).")
            log.warning("lightgbm не найден — откатываюсь на sklearn HistGradientBoosting.")
            return "hgb"
    return "hgb"


def make_classifier(backend: str, num_labels: int, args, early_stop: bool):
    binary = num_labels == 2
    if backend == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(
            objective="binary" if binary else "multiclass",
            n_estimators=args.n_estimators, learning_rate=args.lr,
            num_leaves=args.num_leaves, max_depth=args.max_depth,
            subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
            reg_lambda=1.0, min_child_samples=20, importance_type="gain",
            random_state=args.seed, n_jobs=-1, verbosity=-1,
        )
    if backend == "catboost":
        from catboost import CatBoostClassifier
        depth = 6 if args.max_depth < 0 else min(args.max_depth, 16)
        return CatBoostClassifier(
            iterations=args.n_estimators, learning_rate=args.lr, depth=depth,
            l2_leaf_reg=3.0, loss_function="Logloss" if binary else "MultiClass",
            eval_metric="PRAUC" if binary else "AUC",
            early_stopping_rounds=args.es_rounds if early_stop else None,
            random_seed=args.seed, allow_writing_files=False, verbose=False,
        )
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(
        max_iter=args.n_estimators, learning_rate=args.lr,
        max_leaf_nodes=args.num_leaves,
        max_depth=None if args.max_depth < 0 else args.max_depth,
        l2_regularization=1.0, random_state=args.seed,
        early_stopping=early_stop, validation_fraction=0.15,
        n_iter_no_change=args.es_rounds,
    )


def make_target_encoder(num_labels: int, seed: int) -> TargetEncoder:
    tt = "binary" if num_labels == 2 else "multiclass"
    return TargetEncoder(target_type=tt, smooth="auto", random_state=seed)


def build_ct(use_text: bool, min_freq: int, num_labels: int, seed: int) -> ColumnTransformer:
    transformers = [
        ("cat", make_ohe(min_freq), CAT_COLS),
        ("tgt", make_target_encoder(num_labels, seed), TARGET_COLS),   # детекторная точность
        ("tags", CountVectorizer(binary=True, token_pattern=r"[^ ]+"), TAGS_COL),
        ("num", "passthrough", NUM_COLS),
    ]
    if use_text:
        transformers.append((
            "txt", TfidfVectorizer(max_features=2000, ngram_range=(1, 2),
                                   min_df=2, sublinear_tf=True), TEXT_COL))
    return ColumnTransformer(transformers, remainder="drop", sparse_threshold=0.3)


def _to_dense(X):
    return X.toarray() if sparse.issparse(X) else np.asarray(X)


class Model:
    """Обёртка (ColumnTransformer + классификатор) с единым predict_proba."""
    def __init__(self, ct, clf, backend):
        self.ct, self.clf, self.backend = ct, clf, backend

    def predict_proba(self, df):
        X = self.ct.transform(df)
        if self.backend == "hgb":
            X = _to_dense(X)
        return self.clf.predict_proba(X)


def fit_model(df, y, backend, use_text, num_labels, args,
              sample_weight=None, early_stop=True) -> Model:
    ct = build_ct(use_text, args.ohe_min_freq, num_labels, args.seed)
    clf = make_classifier(backend, num_labels, args, early_stop)
    X = ct.fit_transform(df, y)
    if backend == "hgb":
        clf.fit(_to_dense(X), y, sample_weight=sample_weight)  # ранняя остановка внутренняя
    elif early_stop and backend in ("lightgbm", "catboost") and X.shape[0] >= 60:
        idx = np.arange(X.shape[0])
        tr, va = train_test_split(idx, test_size=0.15, random_state=args.seed, stratify=y)
        sw_tr = sample_weight[tr] if sample_weight is not None else None
        if backend == "lightgbm":
            from lightgbm import early_stopping
            clf.fit(X[tr], y[tr], sample_weight=sw_tr, eval_set=[(X[va], y[va])],
                    eval_metric="average_precision",
                    callbacks=[early_stopping(args.es_rounds, verbose=False)])
        else:  # catboost
            clf.fit(X[tr], y[tr], sample_weight=sw_tr, eval_set=(X[va], y[va]))
    else:
        if backend == "catboost":
            clf.fit(X, y, sample_weight=sample_weight)
        else:
            clf.fit(X, y, sample_weight=sample_weight)
    return Model(ct, clf, backend)


# ============================================================
# Порог (как в train_verdict_model.py)
# ============================================================

def optimize_threshold(probs, labels, objective="f1", target=0.95, pos_label=1):
    P, R, T = precision_recall_curve(labels, probs, pos_label=pos_label)
    P, R = P[:-1], R[:-1]
    if len(T) == 0:
        return 0.5, {"threshold": 0.5, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    if objective == "target_recall":
        ok = np.where(R >= target)[0]
        idx = ok[np.argmax(P[ok])] if len(ok) else int(np.argmax(R))
    elif objective == "target_precision":
        ok = np.where(P >= target)[0]
        idx = ok[np.argmax(R[ok])] if len(ok) else int(np.argmax(P))
    else:
        f1s = 2 * P * R / (P + R + 1e-12)
        idx = int(np.argmax(f1s))
    thr = float(T[idx])
    f1 = float(2 * P[idx] * R[idx] / (P[idx] + R[idx] + 1e-12))
    return thr, {"threshold": thr, "precision": float(P[idx]),
                 "recall": float(R[idx]), "f1": f1}


# ============================================================
# Сплиты
# ============================================================

def group_values(samples, key: str) -> np.ndarray:
    if key == "project":
        return np.array([s.get("source_dir") or s.get("project") or "?" for s in samples])
    if key == "file":
        return np.array([s.get("file_path") or s.get("source_snap") or "?" for s in samples])
    return np.array([s.get(key, "?") for s in samples])


def split_indices(n, y, groups, split, seed, frac=0.15):
    idx = np.arange(n)
    if split == "group" and groups is not None and len(set(groups)) >= 4:
        gss = GroupShuffleSplit(n_splits=1, test_size=frac, random_state=seed)
        trv, te = next(gss.split(idx, y, groups))
        g2 = groups[trv]
        gss2 = GroupShuffleSplit(n_splits=1, test_size=frac / (1 - frac), random_state=seed)
        tr_rel, va_rel = next(gss2.split(trv, y[trv], g2))
        return trv[tr_rel], trv[va_rel], te
    if split == "group":
        log.warning("Слишком мало групп для group-split — использую случайный.")
    trv, te = train_test_split(idx, test_size=frac, random_state=seed, stratify=y)
    tr, va = train_test_split(trv, test_size=frac / (1 - frac), random_state=seed, stratify=y[trv])
    return tr, va, te


# ============================================================
# Метрики / важности
# ============================================================

def report_metrics(y_true, probs, label_names, threshold, tag=""):
    binary = len(label_names) == 2
    if binary:
        pred = (probs[:, 1] >= threshold).astype(int) if threshold is not None \
            else np.argmax(probs, axis=1)
        try:
            log.info("%sPR-AUC: %.4f", tag, average_precision_score(y_true, probs[:, 1]))
        except ValueError:
            pass
    else:
        pred = np.argmax(probs, axis=1)
    log.info("%s\n%s", tag, classification_report(
        y_true, pred, target_names=label_names, digits=4, zero_division=0))
    cm = confusion_matrix(y_true, pred)
    log.info("Confusion (стр=факт):  %s", "".join(f"{n:>16s}" for n in label_names))
    for i, row in enumerate(cm):
        log.info("  %-14s%s", label_names[i], "".join(f"{v:>16d}" for v in row))


def log_importances(model: Model, top=20):
    clf = model.clf
    imp = getattr(clf, "feature_importances_", None)
    if imp is None and model.backend == "catboost":
        try:
            imp = clf.get_feature_importance()
        except Exception:  # noqa: BLE001
            imp = None
    if imp is None:
        log.info("(важности признаков для этого бэкенда недоступны)")
        return
    try:
        names = model.ct.get_feature_names_out()
    except Exception:  # noqa: BLE001
        names = np.array([f"f{i}" for i in range(len(imp))])
    order = np.argsort(imp)[::-1][:top]
    log.info("%s\nТоп-%d признаков по важности:", "-" * 60, top)
    for i in order:
        if imp[i] > 0:
            log.info("  %-48s %.4g", str(names[i])[:48], float(imp[i]))


def cross_validate(df, y, groups, backend, use_text, num_labels, label_names, args):
    if groups is not None and len(set(groups)) >= args.kfold:
        splitter = StratifiedGroupKFold(n_splits=args.kfold, shuffle=True, random_state=args.seed)
        folds = list(splitter.split(df, y, groups))
    else:
        if groups is not None:
            log.warning("Групп меньше, чем фолдов — обычный StratifiedKFold без групп.")
        splitter = StratifiedKFold(n_splits=args.kfold, shuffle=True, random_state=args.seed)
        folds = list(splitter.split(df, y))

    pr_aucs, thresholds, f1s = [], [], []
    for k, (tr, va) in enumerate(folds, 1):
        sw = compute_sample_weight("balanced", y[tr]) if args.imbalance == "balanced" else None
        model = fit_model(df.iloc[tr], y[tr], backend, use_text, num_labels, args,
                          sample_weight=sw, early_stop=not args.no_early_stopping)
        probs = model.predict_proba(df.iloc[va])
        if num_labels == 2:
            ap = average_precision_score(y[va], probs[:, 1])
            thr, info = optimize_threshold(probs[:, 1], y[va],
                                           args.threshold_objective, args.threshold_target)
            pr_aucs.append(ap); thresholds.append(thr); f1s.append(info["f1"])
            log.info("  fold %d: PR-AUC=%.4f thr=%.3f (P=%.3f R=%.3f)",
                     k, ap, thr, info["precision"], info["recall"])
        else:
            f1s.append(f1_score(y[va], np.argmax(probs, 1), average="macro"))
            log.info("  fold %d: F1-macro=%.4f", k, f1s[-1])

    log.info("%s\nCV (%d фолдов):", "-" * 60, args.kfold)
    if pr_aucs:
        log.info("  PR-AUC    %.4f ± %.4f", np.mean(pr_aucs), np.std(pr_aucs))
        log.info("  threshold %.4f ± %.4f", np.mean(thresholds), np.std(thresholds))
    log.info("  F1pos/macro %.4f ± %.4f", np.mean(f1s), np.std(f1s))
    return float(np.mean(thresholds)) if thresholds else None


# ============================================================
# Режим train
# ============================================================

def run_train(args):
    raw = sc.load_jsonl(args.data)
    log.info("Загружено %d сэмплов из %s", len(raw), args.data)
    label_map, label_names = sc.build_label_map(raw, args.multiclass, args.wontfix_as_tp)
    samples = [s for s in raw if s.get("status") in label_map]
    if len(samples) < len(raw):
        log.info("Отброшено %d сэмплов без валидного статуса", len(raw) - len(samples))
    y = np.array([label_map[s["status"]] for s in samples])
    num_labels = len(label_names)
    log.info("Классы: %s | распределение: %s", label_names, dict(Counter(y.tolist())))
    if num_labels == 2:
        pos = int(y.sum())
        log.info("Дисбаланс: TP=%d (%.1f%%) / FP=%d", pos, 100 * pos / max(len(y), 1), len(y) - pos)

    backend = resolve_backend(args.backend)
    use_text = (not args.no_text) and backend in ("lightgbm", "catboost")
    if (not args.no_text) and backend == "hgb":
        log.warning("TF-IDF отключён: бэкенд hgb не принимает разреженные признаки.")
    es = not args.no_early_stopping
    log.info("Бэкенд: %s | TF-IDF: %s | ранняя остановка: %s", backend, use_text, es)

    df = build_frame(samples)
    groups = group_values(samples, args.group_key) if args.split == "group" else None

    final_threshold = None
    if args.kfold > 1:
        final_threshold = cross_validate(df, y, groups, backend, use_text,
                                         num_labels, label_names, args)
    else:
        tr, va, te = split_indices(len(samples), y, groups, args.split, args.seed)
        log.info("Сплит: train=%d val=%d test=%d", len(tr), len(va), len(te))
        sw = compute_sample_weight("balanced", y[tr]) if args.imbalance == "balanced" else None
        model = fit_model(df.iloc[tr], y[tr], backend, use_text, num_labels, args,
                          sample_weight=sw, early_stop=es)
        if num_labels == 2:
            pv = model.predict_proba(df.iloc[va])[:, 1]
            final_threshold, info = optimize_threshold(
                pv, y[va], args.threshold_objective, args.threshold_target)
            log.info("Порог (val, %s): %.4f | P=%.3f R=%.3f F1=%.3f",
                     args.threshold_objective, final_threshold,
                     info["precision"], info["recall"], info["f1"])
        report_metrics(y[te], model.predict_proba(df.iloc[te]), label_names,
                       final_threshold, tag="ТЕСТ:")

    # Финальная модель на ВСЕХ данных (для деплоя)
    log.info("%s\nОбучение финальной модели на всех %d сэмплах...", "=" * 60, len(samples))
    sw_all = compute_sample_weight("balanced", y) if args.imbalance == "balanced" else None
    final_model = fit_model(df, y, backend, use_text, num_labels, args,
                            sample_weight=sw_all, early_stop=es)
    log_importances(final_model)

    meta = {
        "version": "gb-2.0-isp", "backend": backend, "num_labels": num_labels,
        "label_names": label_names, "label_map": label_map,
        "multiclass": args.multiclass, "wontfix_as_tp": args.wontfix_as_tp,
        "use_text": use_text, "threshold": final_threshold,
        "threshold_objective": args.threshold_objective,
        "threshold_target": args.threshold_target, "imbalance": args.imbalance,
        "split": args.split, "features": {"cat": CAT_COLS, "target": TARGET_COLS,
                                          "tags": TAGS_COL, "num": NUM_COLS},
        "dataset_stats": {"total": len(samples), "distribution": dict(Counter(y.tolist()))},
    }
    joblib.dump({"model": final_model, "meta": meta}, args.output)
    with open(os.path.splitext(args.output)[0] + "_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    log.info("%s\nГотово.\nМодель: %s\nПорог:  %s\n%s", "=" * 60, args.output,
             f"{final_threshold:.4f} ({args.threshold_objective})"
             if final_threshold is not None else "argmax", "=" * 60)


# ============================================================
# Режим predict (формат вывода идентичен predict_verdicts.py)
# ============================================================

def collect_from_snaps(root: Path, pattern: str) -> List[dict]:
    snaps = sorted(p for p in root.rglob(pattern) if p.is_file())
    if not snaps:
        log.error("Файлы не найдены: %s / %s", root, pattern)
        return []
    out: List[dict] = []
    for snap in snaps:
        rel = snap.relative_to(root)
        stamp = {"source_dir": rel.parts[0] if len(rel.parts) > 1 else ".",
                 "source_snap": snap.name}
        try:
            out.extend(sc.parse_snap(str(snap), stamp=stamp))
        except sc.SnapError as e:
            log.warning("Пропуск %s: %s", rel, e)
    return out


def run_predict(args):
    bundle = joblib.load(args.model)
    model, meta = bundle["model"], bundle["meta"]
    label_names = meta["label_names"]
    threshold = args.threshold if args.threshold is not None else meta.get("threshold")
    log.info("Модель: backend=%s | классы=%s | порог=%s", meta.get("backend"),
             label_names, f"{threshold:.4f}" if isinstance(threshold, float) else "argmax")

    if args.root:
        samples = collect_from_snaps(Path(args.root).expanduser().resolve(), args.pattern)
    else:
        samples = sc.load_jsonl(args.data)
    if not samples:
        raise SystemExit("Нет сэмплов для скоринга.")
    log.info("Скоринг %d срабатываний...", len(samples))

    probs = model.predict_proba(build_frame(samples))
    binary = len(label_names) == 2
    for s, p in zip(samples, probs):
        if binary and isinstance(threshold, float):
            pred = 1 if p[1] >= threshold else 0
        else:
            pred = int(np.argmax(p))
        s["predicted_label"] = int(pred)
        s["predicted_verdict"] = label_names[pred]
        s["confidence"] = round(float(p[pred]), 4)
        if binary:
            s["prob_true_positive"] = round(float(p[1]), 4)

    sc.save_jsonl(samples, args.output)
    dist = Counter(s["predicted_verdict"] for s in samples)
    log.info("Готово. Записано %d → %s", len(samples), args.output)
    for name in label_names:
        log.info("  %-20s %d", name, dist.get(name, 0))


# ============================================================
# CLI
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="GB-классификатор вердиктов SAST (метод ИСП РАН + улучшения).")
    ap.add_argument("--mode", choices=["train", "predict"], default="train")
    ap.add_argument("--data", help="JSONL из build_dataset.py")
    ap.add_argument("--root", help="(predict) каталог снапов вместо --data")
    ap.add_argument("--pattern", default="*.snap")
    ap.add_argument("--output", default="gb_model.joblib",
                    help="train: путь модели; predict: путь verdicts.jsonl")
    ap.add_argument("--model", help="(predict) путь к .joblib")
    ap.add_argument("--backend", choices=["auto", "lightgbm", "catboost", "hgb"], default="auto")
    ap.add_argument("--no-text", action="store_true", help="Отключить TF-IDF по тексту")
    ap.add_argument("--n-estimators", type=int, default=800)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--num-leaves", type=int, default=31)
    ap.add_argument("--max-depth", type=int, default=-1)
    ap.add_argument("--ohe-min-freq", type=int, default=5,
                    help="Сворачивать категории реже N в one-hot (0/1 — не сворачивать)")
    ap.add_argument("--no-early-stopping", action="store_true")
    ap.add_argument("--es-rounds", type=int, default=50, help="Терпение ранней остановки")
    ap.add_argument("--multiclass", action="store_true")
    ap.add_argument("--wontfix-as-tp", action="store_true")
    ap.add_argument("--imbalance", choices=["balanced", "none"], default="balanced")
    ap.add_argument("--threshold-objective",
                    choices=["f1", "target_recall", "target_precision"], default="f1")
    ap.add_argument("--threshold-target", type=float, default=0.95)
    ap.add_argument("--split", choices=["random", "group"], default="random")
    ap.add_argument("--group-key", default="file", help="file | project | <поле>")
    ap.add_argument("--kfold", type=int, default=1, help=">1 включает K-fold CV-оценку")
    ap.add_argument("--threshold", type=float, default=None,
                    help="(predict) переопределить порог из меты")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    np.random.seed(args.seed)
    if args.mode == "train":
        if not args.data:
            raise SystemExit("--data обязателен для режима train")
        run_train(args)
    else:
        if not args.model:
            raise SystemExit("--model обязателен для режима predict")
        if not (args.root or args.data):
            raise SystemExit("укажите --data или --root для режима predict")
        run_predict(args)


if __name__ == "__main__":
    main()
