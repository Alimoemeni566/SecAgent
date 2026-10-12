#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ast
import asyncio
import collections
import concurrent.futures
import contextlib
import dataclasses
import enum
import functools
import gc
import hashlib
import inspect
import io
import itertools
import json
import logging
import math
import multiprocessing
import operator
import os
import pathlib
import pickle
import queue
import random
import re
import secrets
import shutil
import signal
import sqlite3
import statistics
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
import typing as t
import unicodedata
import urllib.parse
import uuid
import warnings
import weakref
import zlib
from abc import ABC, abstractmethod
from collections import Counter, OrderedDict, defaultdict, deque, namedtuple
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, IntEnum, auto
from functools import cached_property, lru_cache, partial, reduce, singledispatch, wraps
from itertools import chain, combinations, count, cycle, groupby, islice, permutations, product, repeat, starmap, tee, zip_longest
from pathlib import Path
from typing import Any, Callable, ClassVar, Generic, Iterable, Iterator, Literal, NamedTuple, Optional, Protocol, TypeVar, Union, overload

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, IterableDataset
from torch.utils.tensorboard import SummaryWriter
from torch.cuda.amp import autocast, GradScaler

VERSION = "2.0.0"
AUTHOR = "Ali Moemeni"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
SEED = 42


def set_seed(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


set_seed()


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Language(Enum):
    CSHARP = "csharp"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PHP = "php"
    HTML = "html"
    CSS = "css"
    UNKNOWN = "unknown"

    @classmethod
    def from_path(cls, path: Path) -> Language:
        ext_map = {
            ".cs": cls.CSHARP,
            ".py": cls.PYTHON,
            ".js": cls.JAVASCRIPT,
            ".mjs": cls.JAVASCRIPT,
            ".cjs": cls.JAVASCRIPT,
            ".ts": cls.TYPESCRIPT,
            ".php": cls.PHP,
            ".phtml": cls.PHP,
            ".html": cls.HTML,
            ".htm": cls.HTML,
            ".css": cls.CSS,
        }
        return ext_map.get(path.suffix.lower(), cls.UNKNOWN)


@dataclass(frozen=True)
class Finding:
    rule: str
    cwe: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    confidence: float = 1.0

    @property
    def fingerprint(self) -> str:
        payload = f"{self.cwe}|{self.file_path}|{self.line_number}|{self.rule}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "cwe": self.cwe,
            "severity": self.severity.name,
            "severity_value": int(self.severity),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    files_scanned: int
    lines_scanned: int

    @property
    def duration(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def total(self) -> int:
        return len(self.findings)

    def count_by_severity(self) -> dict[Severity, int]:
        counter: Counter = Counter()
        for f in self.findings:
            counter[f.severity] += 1
        return dict(counter)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": self.duration,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": self.total,
            "by_severity": {
                sev.name: count for sev, count in self.count_by_severity().items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class TokenVocabulary:
    MAX_VOCAB = 8192
    PAD_TOKEN = 0
    UNK_TOKEN = 1
    CLS_TOKEN = 2
    SEP_TOKEN = 3
    SPECIAL_TOKENS = 4

    def __init__(self, max_size: int = MAX_VOCAB):
        self.max_size = max_size
        self.token_to_id: dict[str, int] = {}
        self.id_to_token: dict[int, str] = {}
        self._frozen = False
        self._init_special()

    def _init_special(self) -> None:
        specials = {
            "<pad>": self.PAD_TOKEN,
            "<unk>": self.UNK_TOKEN,
            "<cls>": self.CLS_TOKEN,
            "<sep>": self.SEP_TOKEN,
        }
        for token, idx in specials.items():
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token

    def tokenize(self, text: str) -> list[str]:
        pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\sA-Za-z0-9_]")
        return pattern.findall(text)

    def add(self, token: str) -> int:
        if self._frozen:
            return self.token_to_id.get(token, self.UNK_TOKEN)
        if token in self.token_to_id:
            return self.token_to_id[token]
        if len(self.token_to_id) >= self.max_size:
            return self.UNK_TOKEN
        idx = len(self.token_to_id)
        self.token_to_id[token] = idx
        self.id_to_token[idx] = token
        return idx

    def encode(self, text: str, max_length: int = 512) -> list[int]:
        tokens = self.tokenize(text)
        ids = [self.CLS_TOKEN]
        for token in tokens:
            ids.append(self.token_to_id.get(token, self.UNK_TOKEN))
            if len(ids) >= max_length - 1:
                break
        ids.append(self.SEP_TOKEN)
        return ids

    def freeze(self) -> None:
        self._frozen = True

    def __len__(self) -> int:
        return len(self.token_to_id)


class CodeTokenizer:
    def __init__(self) -> None:
        self.vocab = TokenVocabulary()

    def fit(self, corpus: Iterable[str]) -> None:
        for text in corpus:
            for token in self.vocab.tokenize(text):
                self.vocab.add(token)
        self.vocab.freeze()

    def transform(self, text: str, max_length: int = 512) -> torch.Tensor:
        ids = self.vocab.encode(text, max_length=max_length)
        return torch.tensor(ids, dtype=torch.long)

    def batch_transform(self, texts: list[str], max_length: int = 512, pad: bool = True) -> torch.Tensor:
        sequences = [self.transform(text, max_length) for text in texts]
        if not pad:
            return sequences
        max_len = max(seq.size(0) for seq in sequences)
        padded = torch.full((len(sequences), max_len), self.vocab.PAD_TOKEN, dtype=torch.long)
        for i, seq in enumerate(sequences):
            padded[i, : seq.size(0)] = seq
        return padded


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 1024, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(dropout)
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.pe[:, : x.size(1), :]
        return self.dropout(x)


class MultiHeadAttention(nn.Module):
    def __init__(self, d_model: int, n_heads: int, dropout: float = 0.1):
        super().__init__()
        assert d_model % n_heads == 0
        self.d_model = d_model
        self.n_heads = n_heads
        self.head_dim = d_model // n_heads
        self.scale = self.head_dim ** -0.5
        self.qkv = nn.Linear(d_model, 3 * d_model, bias=False)
        self.out = nn.Linear(d_model, d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        B, T, C = x.size()
        qkv = self.qkv(x).reshape(B, T, 3, self.n_heads, self.head_dim)
        qkv = qkv.permute(2, 0, 3, 1, 4)
        q, k, v = qkv[0], qkv[1], qkv[2]
        attn = (q @ k.transpose(-2, -1)) * self.scale
        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))
        attn = F.softmax(attn, dim=-1)
        attn = self.dropout(attn)
        out = (attn @ v).transpose(1, 2).reshape(B, T, C)
        return self.out(out)


class FeedForward(nn.Module):
    def __init__(self, d_model: int, d_ff: int, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TransformerBlock(nn.Module):
    def __init__(self, d_model: int, n_heads: int, d_ff: int, dropout: float = 0.1):
        super().__init__()
        self.norm1 = nn.LayerNorm(d_model)
        self.attn = MultiHeadAttention(d_model, n_heads, dropout)
        self.norm2 = nn.LayerNorm(d_model)
        self.ff = FeedForward(d_model, d_ff, dropout)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        x = x + self.attn(self.norm1(x), mask)
        x = x + self.ff(self.norm2(x))
        return x


class SecurityTransformer(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        d_model: int = 256,
        n_heads: int = 8,
        n_layers: int = 6,
        d_ff: int = 1024,
        max_len: int = 512,
        n_classes: int = 7,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.d_model = d_model
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_encoding = PositionalEncoding(d_model, max_len, dropout)
        self.blocks = nn.ModuleList(
            [TransformerBlock(d_model, n_heads, d_ff, dropout) for _ in range(n_layers)]
        )
        self.norm = nn.LayerNorm(d_model)
        self.classifier = nn.Linear(d_model, n_classes)
        self.confidence_head = nn.Linear(d_model, 1)

    def forward(self, input_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> tuple[torch.Tensor, torch.Tensor]:
        x = self.embedding(input_ids) * math.sqrt(self.d_model)
        x = self.pos_encoding(x)
        for block in self.blocks:
            x = block(x, attention_mask)
        x = self.norm(x)
        pooled = x.mean(dim=1)
        logits = self.classifier(pooled)
        confidence = torch.sigmoid(self.confidence_head(pooled))
        return logits, confidence


@dataclass
class Rule:
    name: str
    cwe: str
    severity: Severity
    pattern: re.Pattern
    description: str
    recommendation: str
    languages: tuple[Language, ...] = tuple(Language)

    def scan(self, file_path: str, lines: list[str], language: Language) -> Iterator[Finding]:
        if language not in self.languages:
            return
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "/*", "*", "<!--")):
                continue
            if self.pattern.search(line):
                yield Finding(
                    rule=self.name,
                    cwe=self.cwe,
                    severity=self.severity,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=stripped[:120],
                    description=self.description,
                    recommendation=self.recommendation,
                    confidence=0.85,
                )


ALL_LANGS = tuple(Language)
CODE_LANGS = (Language.CSHARP, Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.PHP)
WEB_LANGS = (Language.JAVASCRIPT, Language.TYPESCRIPT, Language.PHP, Language.HTML)


RULES: list[Rule] = [
    Rule(
        name="SQL Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(ExecuteNonQuery|ExecuteSqlRaw|\.execute|\.query)\s*\([^)]*(\+|\$\"|f\"|`)",
            re.IGNORECASE,
        ),
        description="Untrusted input concatenated into SQL query",
        recommendation="Use parameterized queries with bound parameters",
        languages=CODE_LANGS,
    ),
    Rule(
        name="Command Injection",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(Process\.Start|os\.system|subprocess\.(run|call|Popen)|shell_exec|system)\s*\([^)]*(\+|\$\"|f\"|`)",
            re.IGNORECASE,
        ),
        description="System command executed with untrusted arguments",
        recommendation="Avoid shell=True; use argument lists instead",
        languages=CODE_LANGS,
    ),
    Rule(
        name="Cross-Site Scripting",
        cwe="CWE-79",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(innerHTML\s*=|document\.write|echo\s+\$_|render_template_string)",
            re.IGNORECASE,
        ),
        description="User input rendered to HTML without escaping",
        recommendation="Use textContent or escape output; add CSP",
        languages=WEB_LANGS,
    ),
    Rule(
        name="Hardcoded Secret",
        cwe="CWE-798",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(password|passwd|apikey|api_key|secret|token|credential)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
            re.IGNORECASE,
        ),
        description="Sensitive credential hardcoded in source",
        recommendation="Load secrets from environment or a vault",
        languages=CODE_LANGS,
    ),
    Rule(
        name="Weak Cryptography",
        cwe="CWE-327",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\b(MD5|SHA1|DES|RC2|RC4|TripleDES)\b", re.IGNORECASE),
        description="Cryptographically broken algorithm in use",
        recommendation="Use SHA-256/SHA-512 for hashing and AES for encryption",
        languages=CODE_LANGS,
    ),
    Rule(
        name="Insecure Random",
        cwe="CWE-338",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"(new\s+Random\(\)|Math\.random\(\)|random\.(randint|choice)|\brand\s*\()"),
        description="Non-cryptographic random source used",
        recommendation="Use CSPRNG: secrets, crypto.randomBytes, RandomNumberGenerator",
        languages=CODE_LANGS,
    ),
    Rule(
        name="Empty Catch Block",
        cwe="CWE-390",
        severity=Severity.LOW,
        pattern=re.compile(r"(catch\s*(\([^)]*\))?\s*\{\s*\}|except\s*:\s*pass)"),
        description="Exception swallowed without logging",
        recommendation="At minimum, log the exception with context",
        languages=CODE_LANGS,
    ),
]


class LabeledCodeDataset(Dataset):
    def __init__(
        self,
        samples: list[tuple[str, int]],
        tokenizer: CodeTokenizer,
        max_length: int = 512,
    ):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        text, label = self.samples[index]
        ids = self.tokenizer.transform(text, self.max_length)
        return ids, torch.tensor(label, dtype=torch.long)


def collate_batch(batch: list[tuple[torch.Tensor, torch.Tensor]], pad_id: int = 0) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    sequences, labels = zip(*batch)
    max_len = max(seq.size(0) for seq in sequences)
    padded = torch.full((len(sequences), max_len), pad_id, dtype=torch.long)
    mask = torch.zeros((len(sequences), max_len), dtype=torch.long)
    for i, seq in enumerate(sequences):
        padded[i, : seq.size(0)] = seq
        mask[i, : seq.size(0)] = 1
    return padded, torch.stack(labels), mask


class ClassifierTrainer:
    def __init__(
        self,
        model: nn.Module,
        device: torch.device = DEVICE,
        lr: float = 3e-4,
        weight_decay: float = 1e-4,
        use_amp: bool = True,
    ):
        self.model = model.to(device)
        self.device = device
        self.optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
        self.scheduler = optim.lr_scheduler.CosineAnnealingLR(self.optimizer, T_max=50)
        self.criterion = nn.CrossEntropyLoss()
        self.use_amp = use_amp and device.type == "cuda"
        self.scaler = GradScaler(enabled=self.use_amp)
        self.history: list[dict[str, float]] = []

    def train_epoch(self, loader: DataLoader) -> dict[str, float]:
        self.model.train()
        total_loss = 0.0
        total_correct = 0
        total_samples = 0
        for input_ids, labels, mask in loader:
            input_ids = input_ids.to(self.device, non_blocking=True)
            labels = labels.to(self.device, non_blocking=True)
            mask = mask.to(self.device, non_blocking=True)
            self.optimizer.zero_grad(set_to_none=True)
            with autocast(enabled=self.use_amp):
                logits, _ = self.model(input_ids, mask)
                loss = self.criterion(logits, labels)
            self.scaler.scale(loss).backward()
            self.scaler.unscale_(self.optimizer)
            nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.scaler.step(self.optimizer)
            self.scaler.update()
            total_loss += loss.item() * labels.size(0)
            preds = logits.argmax(dim=-1)
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
        return {
            "loss": total_loss / max(1, total_samples),
            "accuracy": total_correct / max(1, total_samples),
        }

    @torch.no_grad()
    def evaluate(self, loader: DataLoader) -> dict[str, float]:
        self.model.eval()
        total_loss = 0.0
        total_correct = 0
        total_samples = 0
        for input_ids, labels, mask in loader:
            input_ids = input_ids.to(self.device, non_blocking=True)
            labels = labels.to(self.device, non_blocking=True)
            mask = mask.to(self.device, non_blocking=True)
            with autocast(enabled=self.use_amp):
                logits, _ = self.model(input_ids, mask)
                loss = self.criterion(logits, labels)
            total_loss += loss.item() * labels.size(0)
            preds = logits.argmax(dim=-1)
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
        return {
            "loss": total_loss / max(1, total_samples),
            "accuracy": total_correct / max(1, total_samples),
        }

    def fit(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 20,
        patience: int = 5,
        checkpoint_dir: Optional[Path] = None,
    ) -> None:
        best_acc = 0.0
        epochs_no_improve = 0
        for epoch in range(1, epochs + 1):
            train_metrics = self.train_epoch(train_loader)
            val_metrics = self.evaluate(val_loader)
            self.scheduler.step()
            record = {
                "epoch": epoch,
                "train_loss": train_metrics["loss"],
                "train_acc": train_metrics["accuracy"],
                "val_loss": val_metrics["loss"],
                "val_acc": val_metrics["accuracy"],
                "lr": self.optimizer.param_groups[0]["lr"],
            }
            self.history.append(record)
            print(
                f"epoch {epoch:02d} "
                f"train_loss={record['train_loss']:.4f} "
                f"train_acc={record['train_acc']:.4f} "
                f"val_loss={record['val_loss']:.4f} "
                f"val_acc={record['val_acc']:.4f}"
            )
            if val_metrics["accuracy"] > best_acc:
                best_acc = val_metrics["accuracy"]
                epochs_no_improve = 0
                if checkpoint_dir is not None:
                    checkpoint_dir.mkdir(parents=True, exist_ok=True)
                    torch.save(
                        {
                            "model_state": self.model.state_dict(),
                            "optimizer_state": self.optimizer.state_dict(),
                            "epoch": epoch,
                            "best_acc": best_acc,
                        },
                        checkpoint_dir / "best_model.pt",
                    )
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    print(f"early stopping at epoch {epoch}")
                    break


class AttentionVisualizer:
    def __init__(self, model: SecurityTransformer):
        self.model = model
        self.attention_maps: dict[int, torch.Tensor] = {}
        self._register_hooks()

    def _register_hooks(self) -> None:
        for idx, block in enumerate(self.model.blocks):
            block.attn.register_forward_hook(self._make_hook(idx))

    def _make_hook(self, layer_idx: int):
        def hook(module: nn.Module, inputs: tuple, output: torch.Tensor) -> None:
            self.attention_maps[layer_idx] = output.detach().cpu()
        return hook

    def clear(self) -> None:
        self.attention_maps.clear()


class CodeSimilarityIndex:
    def __init__(self, dim: int = 256):
        self.dim = dim
        self.index: list[tuple[str, np.ndarray]] = []

    def _hash_embedding(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        tokens = re.findall(r"\w+", text.lower())
        for token in tokens:
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            idx = h % self.dim
            sign = 1.0 if (h >> 8) & 1 else -1.0
            vec[idx] += sign
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def add(self, identifier: str, text: str) -> None:
        self.index.append((identifier, self._hash_embedding(text)))

    def query(self, text: str, top_k: int = 5) -> list[tuple[str, float]]:
        if not self.index:
            return []
        query_vec = self._hash_embedding(text)
        scores = [
            (identifier, float(np.dot(query_vec, vec)))
            for identifier, vec in self.index
        ]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


class SourceFileCollector:
    SUPPORTED_EXTENSIONS = {ext for lang in Language for ext in []} | {
        ".cs", ".py", ".js", ".mjs", ".cjs", ".ts", ".php", ".phtml", ".html", ".htm", ".css"
    }
    EXCLUDED_DIRS = {"bin", "obj", "node_modules", "__pycache__", ".git", ".vs", ".idea", "dist", "build", "target", ".venv", "venv", "env"}

    @classmethod
    def collect(cls, root: Path, recursive: bool = True) -> list[Path]:
        if root.is_file():
            return [root] if root.suffix.lower() in cls.SUPPORTED_EXTENSIONS else []
        if not root.is_dir():
            return []
        pattern = "**/*" if recursive else "*"
        results: list[Path] = []
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            if path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
                continue
            if any(part in cls.EXCLUDED_DIRS for part in path.parts):
                continue
            results.append(path)
        return results


class StaticAnalyzer:
    def __init__(self, rules: list[Rule] = RULES):
        self.rules = rules

    def analyze_file(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        lines = content.splitlines()
        language = Language.from_path(path)
        if language is Language.UNKNOWN:
            return []
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.scan(str(path), lines, language))
        return findings

    def analyze_path(self, root: Path, recursive: bool = True) -> ScanResult:
        started = datetime.now()
        files = SourceFileCollector.collect(root, recursive)
        all_findings: list[Finding] = []
        total_lines = 0
        for file in files:
            try:
                content = file.read_text(encoding="utf-8", errors="replace")
                total_lines += len(content.splitlines())
            except OSError:
                continue
            all_findings.extend(self.analyze_file(file))
        all_findings.sort(key=lambda f: (-int(f.severity), f.file_path, f.line_number))
        return ScanResult(
            target=str(root),
            started_at=started,
            finished_at=datetime.now(),
            findings=all_findings,
            files_scanned=len(files),
            lines_scanned=total_lines,
        )


class ParallelAnalyzer:
    def __init__(self, analyzer: StaticAnalyzer, max_workers: Optional[int] = None):
        self.analyzer = analyzer
        self.max_workers = max_workers or max(1, multiprocessing.cpu_count() - 1)

    def analyze(self, root: Path, recursive: bool = True) -> ScanResult:
        started = datetime.now()
        files = SourceFileCollector.collect(root, recursive)
        all_findings: list[Finding] = []
        total_lines = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self.analyzer.analyze_file, f): f for f in files}
            for future in as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    all_findings.extend(future.result())
                    total_lines += sum(1 for _ in file.open(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
        all_findings.sort(key=lambda f: (-int(f.severity), f.file_path, f.line_number))
        return ScanResult(
            target=str(root),
            started_at=started,
            finished_at=datetime.now(),
            findings=all_findings,
            files_scanned=len(files),
            lines_scanned=total_lines,
        )


class ReportWriter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, result: ScanResult, name: str = "report.json") -> Path:
        path = self.output_dir / name
        path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def write_text(self, result: ScanResult, name: str = "report.txt") -> Path:
        path = self.output_dir / name
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append(f"SecAgent Report - {result.target}")
        lines.append("=" * 72)
        lines.append(f"Started : {result.started_at.isoformat()}")
        lines.append(f"Finished: {result.finished_at.isoformat()}")
        lines.append(f"Duration: {result.duration:.3f}s")
        lines.append(f"Files   : {result.files_scanned}")
        lines.append(f"Lines   : {result.lines_scanned}")
        lines.append(f"Findings: {result.total}")
        lines.append("")
        for severity in reversed(list(Severity)):
            count = sum(1 for f in result.findings if f.severity == severity)
            lines.append(f"  {severity.name:<10}: {count}")
        lines.append("")
        lines.append("-" * 72)
        for finding in result.findings:
            lines.append("")
            lines.append(f"[{finding.severity.name}] {finding.rule} ({finding.cwe})")
            lines.append(f"  File    : {finding.file_path}:{finding.line_number}")
            lines.append(f"  Code    : {finding.code_snippet}")
            lines.append(f"  Detail  : {finding.description}")
            lines.append(f"  Fix     : {finding.recommendation}")
            lines.append(f"  FP      : {finding.fingerprint}")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def write_sarif(self, result: ScanResult, name: str = "report.sarif") -> Path:
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecAgent",
                            "version": VERSION,
                            "informationUri": "https://github.com/alimoemeni/SecAgent",
                            "rules": [
                                {
                                    "id": rule.name,
                                    "name": rule.name,
                                    "shortDescription": {"text": rule.description},
                                    "helpUri": f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[1]}.html",
                                    "properties": {
                                        "cwe": rule.cwe,
                                        "severity": rule.severity.name,
                                    },
                                }
                                for rule in RULES
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding.rule,
                            "level": self._sarif_level(finding.severity),
                            "message": {"text": finding.description},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": finding.file_path},
                                        "region": {"startLine": finding.line_number},
                                    }
                                }
                            ],
                            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
                        }
                        for finding in result.findings
                    ],
                }
            ],
        }
        path = self.output_dir / name
        path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    @staticmethod
    def _sarif_level(severity: Severity) -> str:
        if severity >= Severity.HIGH:
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"


class ConsoleReporter:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    @classmethod
    def print_banner(cls) -> None:
        print(f"\033[96m{BANNER.format(version=VERSION, author=AUTHOR)}{cls.RESET}")

    @classmethod
    def print_summary(cls, result: ScanResult) -> None:
        print(f"\n{cls.BOLD}Scan Summary{cls.RESET}")
        print(f"  Target         : {result.target}")
        print(f"  Files scanned  : {result.files_scanned}")
        print(f"  Lines analyzed : {result.lines_scanned:,}")
        print(f"  Duration       : {result.duration:.3f}s")
        print(f"  Total findings : {result.total}")
        if result.total:
            for severity in reversed(list(Severity)):
                count = sum(1 for f in result.findings if f.severity == severity)
                if count:
                    color = cls._severity_color(severity)
                    print(f"    {color}{severity.name:<10}{cls.RESET}: {count}")

    @classmethod
    def print_finding(cls, finding: Finding) -> None:
        color = cls._severity_color(finding.severity)
        print()
        print(f"{color}[{finding.severity.name}]{cls.RESET} {cls.BOLD}{finding.rule}{cls.RESET} ({finding.cwe})")
        print(f"  {cls.DIM}{finding.file_path}:{finding.line_number}{cls.RESET}")
        print(f"  {finding.code_snippet}")
        print(f"  -> {finding.description}")
        print(f"  -> {finding.recommendation}")

    @classmethod
    def print_findings(cls, findings: list[Finding], limit: int = 50) -> None:
        for finding in findings[:limit]:
            cls.print_finding(finding)
        if len(findings) > limit:
            print(f"\n{cls.DIM}... {len(findings) - limit} more findings suppressed{cls.RESET}")

    @staticmethod
    def _severity_color(severity: Severity) -> str:
        return {
            Severity.INFO: "\033[94m",
            Severity.LOW: "\033[92m",
            Severity.MEDIUM: "\033[93m",
            Severity.HIGH: "\033[91m",
            Severity.CRITICAL: "\033[41m\033[97m",
        }[severity]


class IncrementalCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "cache.sqlite"
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_cache (
                    path TEXT PRIMARY KEY,
                    hash TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    scanned_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    @staticmethod
    def file_hash(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def get(self, path: Path) -> Optional[list[Finding]]:
        current_hash = self.file_hash(path)
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT hash, findings FROM file_cache WHERE path = ?",
                (str(path),),
            ).fetchone()
        if row is None or row[0] != current_hash:
            return None
        try:
            payload = json.loads(row[1])
        except json.JSONDecodeError:
            return None
        findings: list[Finding] = []
        for entry in payload:
            try:
                findings.append(
                    Finding(
                        rule=entry["rule"],
                        cwe=entry["cwe"],
                        severity=Severity[entry["severity"]],
                        file_path=entry["file_path"],
                        line_number=entry["line_number"],
                        code_snippet=entry["code_snippet"],
                        description=entry["description"],
                        recommendation=entry["recommendation"],
                        confidence=entry.get("confidence", 1.0),
                    )
                )
            except (KeyError, ValueError):
                continue
        return findings

    def put(self, path: Path, findings: list[Finding]) -> None:
        payload = json.dumps([f.to_dict() for f in findings], ensure_ascii=False)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_cache (path, hash, findings, scanned_at) VALUES (?, ?, ?, ?)",
                (str(path), self.file_hash(path), payload, datetime.now().isoformat()),
            )
            conn.commit()


class CachedAnalyzer:
    def __init__(self, analyzer: StaticAnalyzer, cache: IncrementalCache):
        self.analyzer = analyzer
        self.cache = cache
        self.hits = 0
        self.misses = 0

    def analyze_file(self, path: Path) -> list[Finding]:
        cached = self.cache.get(path)
        if cached is not None:
            self.hits += 1
            return cached
        self.misses += 1
        findings = self.analyzer.analyze_file(path)
        self.cache.put(path, findings)
        return findings

    def analyze(self, root: Path, recursive: bool = True) -> ScanResult:
        started = datetime.now()
        files = SourceFileCollector.collect(root, recursive)
        all_findings: list[Finding] = []
        total_lines = 0
        for file in files:
            try:
                total_lines += sum(1 for _ in file.open(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            all_findings.extend(self.analyze_file(file))
        all_findings.sort(key=lambda f: (-int(f.severity), f.file_path, f.line_number))
        return ScanResult(
            target=str(root),
            started_at=started,
            finished_at=datetime.now(),
            findings=all_findings,
            files_scanned=len(files),
            lines_scanned=total_lines,
        )


class DiffReporter:
    @staticmethod
    def compare(baseline: ScanResult, current: ScanResult) -> dict:
        baseline_fps = {f.fingerprint for f in baseline.findings}
        current_fps = {f.fingerprint for f in current.findings}
        new_findings = [f for f in current.findings if f.fingerprint not in baseline_fps]
        fixed_findings = [f for f in baseline.findings if f.fingerprint not in current_fps]
        return {
            "new": new_findings,
            "fixed": fixed_findings,
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "baseline_total": baseline.total,
            "current_total": current.total,
        }


class RuleLearningEngine:
    def __init__(self, tokenizer: CodeTokenizer, model: SecurityTransformer, device: torch.device = DEVICE):
        self.tokenizer = tokenizer
        self.model = model.to(device)
        self.model.eval()
        self.device = device

    @torch.no_grad()
    def classify(self, code: str, max_length: int = 512) -> tuple[int, float]:
        ids = self.tokenizer.transform(code, max_length).unsqueeze(0).to(self.device)
        mask = torch.ones_like(ids)
        logits, confidence = self.model(ids, mask)
        probs = F.softmax(logits, dim=-1)
        pred = int(probs.argmax(dim=-1).item())
        score = float(probs.max(dim=-1).values.item() * confidence.item())
        return pred, score

    @torch.no_grad()
    def batch_classify(self, codes: list[str], max_length: int = 512, batch_size: int = 32) -> list[tuple[int, float]]:
        results: list[tuple[int, float]] = []
        for i in range(0, len(codes), batch_size):
            batch = codes[i : i + batch_size]
            ids = self.tokenizer.batch_transform(batch, max_length).to(self.device)
            mask = (ids != self.tokenizer.vocab.PAD_TOKEN).long()
            logits, confidence = self.model(ids, mask)
            probs = F.softmax(logits, dim=-1)
            preds = probs.argmax(dim=-1).cpu().tolist()
            scores = (probs.max(dim=-1).values * confidence.squeeze(-1)).cpu().tolist()
            results.extend(zip(preds, scores))
        return results


class TrainingPipeline:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tokenizer = CodeTokenizer()
        self.model: Optional[SecurityTransformer] = None

    def prepare_data(self, samples: list[tuple[str, int]], val_split: float = 0.2) -> tuple[Dataset, Dataset]:
        self.tokenizer.fit([text for text, _ in samples])
        random.shuffle(samples)
        split = int(len(samples) * (1 - val_split))
        train_samples = samples[:split]
        val_samples = samples[split:]
        train_ds = LabeledCodeDataset(train_samples, self.tokenizer)
        val_ds = LabeledCodeDataset(val_samples, self.tokenizer)
        return train_ds, val_ds

    def train(
        self,
        samples: list[tuple[str, int]],
        n_classes: int = 7,
        epochs: int = 20,
        batch_size: int = 32,
        lr: float = 3e-4,
    ) -> SecurityTransformer:
        train_ds, val_ds = self.prepare_data(samples)
        train_loader = DataLoader(
            train_ds,
            batch_size=batch_size,
            shuffle=True,
            collate_fn=lambda b: collate_batch(b, self.tokenizer.vocab.PAD_TOKEN),
        )
        val_loader = DataLoader(
            val_ds,
            batch_size=batch_size,
            shuffle=False,
            collate_fn=lambda b: collate_batch(b, self.tokenizer.vocab.PAD_TOKEN),
        )
        self.model = SecurityTransformer(
            vocab_size=max(len(self.tokenizer.vocab), 1024),
            n_classes=n_classes,
        )
        trainer = ClassifierTrainer(self.model, lr=lr)
        trainer.fit(train_loader, val_loader, epochs=epochs, checkpoint_dir=self.output_dir)
        return self.model

    def save_tokenizer(self, path: Path) -> None:
        payload = {
            "token_to_id": self.tokenizer.vocab.token_to_id,
            "max_size": self.tokenizer.vocab.max_size,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_tokenizer(self, path: Path) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.tokenizer = CodeTokenizer()
        self.tokenizer.vocab.token_to_id = payload["token_to_id"]
        self.tokenizer.vocab.id_to_token = {v: k for k, v in payload["token_to_id"].items()}
        self.tokenizer.vocab.max_size = payload["max_size"]
        self.tokenizer.vocab.freeze()


class CommandLineInterface:
    def __init__(self) -> None:
        self.args: dict[str, Any] = {}
        self.parser = self._build_parser()

    def _build_parser(self):
        import argparse
        parser = argparse.ArgumentParser(
            prog="secagent",
            description="Multi-language static security analyzer",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("target", nargs="?", help="File or directory to scan")
        parser.add_argument("-r", "--recursive", action="store_true", help="Scan recursively")
        parser.add_argument("--json", type=Path, help="Write JSON report")
        parser.add_argument("--txt", type=Path, help="Write text report")
        parser.add_argument("--sarif", type=Path, help="Write SARIF report")
        parser.add_argument("--severity", choices=[s.name.lower() for s in Severity], default="info")
        parser.add_argument("--jobs", type=int, default=0)
        parser.add_argument("--cache-dir", type=Path, default=None)
        parser.add_argument("--no-parallel", action="store_true")
        parser.add_argument("--baseline", type=Path, help="Baseline JSON for diff")
        parser.add_argument("--fail-on", choices=[s.name.lower() for s in Severity], default=None)
        parser.add_argument("--verbose", action="store_true")
        parser.add_argument("--version", action="version", version=f"SecAgent {VERSION}")
        return parser

    def parse(self, argv: Optional[list[str]] = None) -> dict[str, Any]:
        ns = self.parser.parse_args(argv)
        self.args = vars(ns)
        return self.args

    def run(self, argv: Optional[list[str]] = None) -> int:
        self.parse(argv)
        ConsoleReporter.print_banner()
        target = self.args.get("target")
        if not target:
            self.parser.print_help()
            return 1
        target_path = Path(target).resolve()
        if not target_path.exists():
            print(f"target not found: {target_path}")
            return 2
        recursive = bool(self.args["recursive"])
        min_severity = Severity[self.args["severity"].upper()]
        analyzer = StaticAnalyzer()
        if self.args["no_parallel"]:
            engine = analyzer
        else:
            workers = self.args["jobs"] or None
            engine = ParallelAnalyzer(analyzer, max_workers=workers)
        if self.args["cache_dir"]:
            cache = IncrementalCache(Path(self.args["cache_dir"]))
            engine = CachedAnalyzer(analyzer, cache)
        result = engine.analyze_path(target_path, recursive) if isinstance(engine, StaticAnalyzer) else engine.analyze(target_path, recursive)
        filtered = [f for f in result.findings if f.severity >= min_severity]
        result = dataclasses.replace(result, findings=filtered)
        ConsoleReporter.print_findings(result.findings)
        ConsoleReporter.print_summary(result)
        if self.args["json"]:
            ReportWriter(Path(self.args["json"]).parent).write_json(result, Path(self.args["json"]).name)
        if self.args["txt"]:
            ReportWriter(Path(self.args["txt"]).parent).write_text(result, Path(self.args["txt"]).name)
        if self.args["sarif"]:
            ReportWriter(Path(self.args["sarif"]).parent).write_sarif(result, Path(self.args["sarif"]).name)
        if self.args["fail_on"]:
            threshold = Severity[self.args["fail_on"].upper()]
            if any(f.severity >= threshold for f in result.findings):
                return 3
        return 0


def demo_training_pipeline() -> None:
    samples: list[tuple[str, int]] = []
    labels = {
        "sql injection": 'query = f"SELECT * FROM users WHERE name = \'{user}\'"',
        "sql injection": 'cursor.execute("SELECT * FROM t WHERE id = " + user_id)',
        "command injection": 'os.system(f"ping {host}")',
        "command injection": 'subprocess.run(cmd, shell=True)',
        "xss": 'element.innerHTML = userInput',
        "xss": 'echo $_GET["name"]',
        "hardcoded secret": 'API_KEY = "sk_live_1234567890abcdef"',
        "hardcoded secret": 'password = "Admin123456"',
        "weak crypto": 'hashlib.md5(password.encode()).hexdigest()',
        "weak crypto": 'using var md5 = MD5.Create();',
        "insecure random": 'token = random.randint(100000, 999999)',
        "insecure random": 'Math.random().toString(36)',
        "empty catch": 'catch { }',
        "empty catch": 'except Exception:\n    pass',
        "clean": 'cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))',
        "clean": 'using var sha = SHA256.Create();',
        "clean": 'token = secrets.token_hex(16)',
    }
    for idx, (category, code) in enumerate(labels.items()):
        samples.append((code, idx % 7))
    pipeline = TrainingPipeline(Path("training_output"))
    model = pipeline.train(samples, n_classes=7, epochs=5, batch_size=4, lr=1e-3)
    pipeline.save_tokenizer(Path("training_output/tokenizer.json"))
    engine = RuleLearningEngine(pipeline.tokenizer, model)
    prediction, confidence = engine.classify('query = f"SELECT * FROM users WHERE id = {user_id}"')
    print(f"prediction={prediction} confidence={confidence:.4f}")


def demo_similarity_index() -> None:
    index = CodeSimilarityIndex(dim=128)
    snippets = [
        ("sql_injection", 'query = f"SELECT * FROM users WHERE name = \'{user}\'"'),
        ("command_injection", 'os.system(f"ping {host}")'),
        ("xss", 'element.innerHTML = userInput'),
        ("clean", 'cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))'),
    ]
    for identifier, code in snippets:
        index.add(identifier, code)
    results = index.query('cursor.execute("SELECT * FROM accounts WHERE id = " + user_id)', top_k=3)
    for identifier, score in results:
        print(f"{identifier}: {score:.4f}")


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "train":
        demo_training_pipeline()
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "similar":
        demo_similarity_index()
        return 0
    cli = CommandLineInterface()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
