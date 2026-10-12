"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])",
    re.IGNORECASE,
)
_BANK_ACCOUNT_RE = re.compile(
    r"(?:\bSTK\b|số\s+tài\s+khoản|so\s+tai\s+khoan)"
    r"\s*(?:[:#-]|là|la)?\s*(?P<value>(?<!\d)\d(?:[ -]?\d){7,15}(?!\d))",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"(?<!\d)0(?:[ -]?\d){9,10}(?!\d)")
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _overlaps(start: int, end: int, accepted: list[dict]) -> bool:
    return any(start < item["end"] and item["start"] < end for item in accepted)


def detect(text: str) -> list[dict]:
    """Return non-overlapping PII spans into the original *text*.

    Labelled bank accounts take precedence over the shape-only CCCD/phone
    recognizers.  This matters for 10- or 12-digit account numbers, whose
    shapes would otherwise produce a second, incorrect entity.
    """
    candidates: list[tuple[int, int, int, str]] = []

    for match in _EMAIL_RE.finditer(text):
        candidates.append((0, match.start(), match.end(), "EMAIL"))
    for match in _BANK_ACCOUNT_RE.finditer(text):
        candidates.append(
            (0, match.start("value"), match.end("value"), "VN_BANK_ACCOUNT")
        )
    for match in _PHONE_RE.finditer(text):
        candidates.append((1, match.start(), match.end(), "VN_PHONE"))
    for match in _CCCD_RE.finditer(text):
        candidates.append((2, match.start(), match.end(), "VN_CCCD"))

    accepted: list[dict] = []
    for _priority, start, end, entity_type in sorted(
        candidates, key=lambda item: (item[0], item[1], -(item[2] - item[1]))
    ):
        if not _overlaps(start, end, accepted):
            accepted.append({"type": entity_type, "start": start, "end": end})

    return sorted(accepted, key=lambda item: (item["start"], item["end"]))


def redact(text: str) -> str:
    redacted = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
