from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Iterable


BN_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")


def to_plain_dict(value: Any) -> Any:
    """Convert Pydantic models or nested containers into plain Python data."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, dict):
        return {k: to_plain_dict(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_plain_dict(item) for item in value]
    return value


def normalize_digits(text: str | None) -> str:
    return (text or "").translate(BN_DIGITS)


def normalize_text(text: str | None) -> str:
    text = unicodedata.normalize("NFKC", normalize_digits(text))
    text = text.replace("\u200c", "").replace("\u200d", "")
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def contains_any(text: str, keywords: Iterable[str]) -> bool:
    normalized = normalize_text(text)
    return any(normalize_text(keyword) in normalized for keyword in keywords)


def detect_language(complaint: str, explicit_language: str | None = None) -> str:
    if explicit_language in {"en", "bn", "mixed"}:
        return explicit_language

    text = complaint or ""
    bangla_count = sum(1 for ch in text if "\u0980" <= ch <= "\u09ff")
    latin_count = sum(1 for ch in text if ("a" <= ch.lower() <= "z"))
    if bangla_count and latin_count:
        return "mixed"
    if bangla_count >= 4:
        return "bn"
    return "en"


PHONE_PATTERN = re.compile(r"(?:\+?88)?01[3-9][0-9][\s\-]?[0-9]{3}[\s\-]?[0-9]{4}")


def normalize_phone(value: str) -> str:
    raw = re.sub(r"[^\d+]", "", normalize_digits(value))
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("8801"):
        return "+" + digits
    if digits.startswith("01"):
        return "+88" + digits
    if raw.startswith("+"):
        return raw
    return digits


def extract_phone_numbers(text: str | None) -> list[str]:
    normalized = normalize_digits(text or "")
    phones = []
    for match in PHONE_PATTERN.finditer(normalized):
        phone = normalize_phone(match.group(0))
        if phone and phone not in phones:
            phones.append(phone)
    return phones


def extract_amounts(text: str | None) -> list[float]:
    normalized = normalize_digits(text or "").replace(",", "")
    phone_spans = [match.span() for match in PHONE_PATTERN.finditer(normalized)]
    amounts: list[float] = []

    for match in re.finditer(r"(?<![\d+])\d{1,7}(?:\.\d+)?(?!\d)", normalized):
        start, end = match.span()
        if any(start < phone_end and end > phone_start for phone_start, phone_end in phone_spans):
            continue
        token = match.group(0)
        if len(token.split(".")[0]) >= 8:
            continue
        try:
            value = float(token)
        except ValueError:
            continue
        if value > 0 and value not in amounts:
            amounts.append(value)
    return amounts


def parse_timestamp(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        timestamp = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def transaction_datetime(transaction: dict[str, Any]) -> datetime | None:
    return parse_timestamp(transaction.get("timestamp"))


def transaction_amount(transaction: dict[str, Any]) -> float | None:
    try:
        amount = float(transaction.get("amount"))
    except (TypeError, ValueError):
        return None
    return amount


def amounts_match(left: float | None, right: float | None) -> bool:
    if left is None or right is None:
        return False
    return abs(float(left) - float(right)) < 0.01


def format_amount(value: float | int | None) -> str:
    if value is None:
        return "the reported amount"
    number = float(value)
    if number.is_integer():
        return str(int(number))
    return f"{number:.2f}".rstrip("0").rstrip(".")


def reference_date_from_transactions(transactions: list[dict[str, Any]]) -> datetime | None:
    timestamps = [transaction_datetime(tx) for tx in transactions]
    timestamps = [ts for ts in timestamps if ts is not None]
    if not timestamps:
        return None
    return max(timestamps)


def date_hint_score(complaint: str, transaction: dict[str, Any], transactions: list[dict[str, Any]]) -> float:
    normalized = normalize_text(complaint)
    tx_dt = transaction_datetime(transaction)
    ref_dt = reference_date_from_transactions(transactions)
    if not tx_dt or not ref_dt:
        return 0.0

    score = 0.0
    if any(term in normalized for term in ["today", "tonight", "আজ"]):
        if tx_dt.date() == ref_dt.date():
            score += 2.0
    if any(term in normalized for term in ["yesterday", "গতকাল"]):
        if (ref_dt.date() - tx_dt.date()).days == 1:
            score += 2.0

    for hour in extract_hour_hints(normalized):
        if abs(tx_dt.hour - hour) <= 1:
            score += 1.5
            break
    return score


def extract_hour_hints(normalized_text: str) -> list[int]:
    text = normalize_digits(normalized_text)
    hours: list[int] = []
    for match in re.finditer(r"\b(\d{1,2})(?::\d{2})?\s*(am|pm)\b", text):
        hour = int(match.group(1))
        suffix = match.group(2)
        if suffix == "pm" and hour != 12:
            hour += 12
        if suffix == "am" and hour == 12:
            hour = 0
        if 0 <= hour <= 23 and hour not in hours:
            hours.append(hour)
    return hours


def counterparty_is_mentioned(counterparty: Any, complaint: str) -> bool:
    if not counterparty:
        return False
    normalized = normalize_text(complaint)
    counterparty_text = normalize_text(str(counterparty))
    if counterparty_text and counterparty_text in normalized:
        return True
    if counterparty_text.startswith("+8801"):
        local = "0" + counterparty_text[4:]
        return local in normalized
    return False
