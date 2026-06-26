from __future__ import annotations

import re
from typing import Any

from .utils import detect_language, normalize_text


SAFE_SUFFIX_EN = "Please do not share your PIN or OTP with anyone."
SAFE_SUFFIX_BN = "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"


SECRET_TERMS = [
    "otp",
    "pin",
    "password",
    "passcode",
    "verification code",
    "full card",
    "card number",
    "পিন",
    "ওটিপি",
    "পাসওয়ার্ড",
    "পাসওয়ার্ড",
]


def _asks_for_secret(reply: str) -> bool:
    normalized = normalize_text(reply)
    request_pattern = re.compile(
        r"\b(send|provide|share|tell|give|submit|enter)\b.{0,35}"
        r"\b(otp|pin|password|passcode|verification code|full card|card number)\b"
    )
    for match in request_pattern.finditer(normalized):
        before = normalized[max(0, match.start() - 30) : match.start()]
        if any(negation in before for negation in ["do not", "don't", "never", "not "]):
            continue
        return True

    bangla_request_terms = ["শেয়ার করুন", "শেয়ার করুন", "পাঠান", "জানান"]
    bangla_secret_terms = ["পিন", "ওটিপি", "পাসওয়ার্ড", "পাসওয়ার্ড"]
    if any(term in normalized for term in bangla_request_terms) and any(
        term in normalized for term in bangla_secret_terms
    ):
        if not any(term in normalized for term in ["শেয়ার করবেন না", "শেয়ার করবেন না", "দেবেন না"]):
            return True
    return False


def _replace_unauthorized_promises(reply: str) -> str:
    replacements = [
        (
            r"\bwe will refund you\b",
            "any eligible amount will be returned through official channels",
        ),
        (
            r"\bwe will reverse (?:it|the transaction|your money)\b",
            "we will verify the transaction before taking further action",
        ),
        (
            r"\byour money has been reversed\b",
            "we will verify the transaction before taking further action",
        ),
        (
            r"\byour account has been unblocked\b",
            "our team will review the account status through official support channels",
        ),
    ]
    sanitized = reply
    for pattern, replacement in replacements:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    return sanitized


def ensure_safety_phrase(reply: str, language: str) -> str:
    suffix = SAFE_SUFFIX_BN if language == "bn" else SAFE_SUFFIX_EN
    normalized_reply = normalize_text(reply)
    if language == "bn":
        if "পিন" in normalized_reply and "ওটিপি" in normalized_reply and (
            "করবেন না" in normalized_reply or "দেবেন না" in normalized_reply
        ):
            return reply
    else:
        if "do not share" in normalized_reply and ("pin" in normalized_reply or "otp" in normalized_reply):
            return reply
        if "never ask" in normalized_reply and ("pin" in normalized_reply or "otp" in normalized_reply):
            return reply
    return f"{reply.rstrip()} {suffix}"


def sanitize_customer_reply(reply: str | None, language: str = "en") -> str:
    language = "bn" if language == "bn" else "en"
    if not reply:
        reply = (
            "আমরা আপনার অনুরোধ পেয়েছি। আমাদের দল অফিসিয়াল চ্যানেলের মাধ্যমে বিষয়টি পর্যালোচনা করবে।"
            if language == "bn"
            else "We have received your request. Our team will review the case through official support channels."
        )

    reply = _replace_unauthorized_promises(reply)
    if _asks_for_secret(reply):
        reply = (
            "আমরা কখনো আপনার পিন, ওটিপি বা পাসওয়ার্ড চাই না। আমাদের দল অফিসিয়াল চ্যানেলের মাধ্যমে বিষয়টি পর্যালোচনা করবে।"
            if language == "bn"
            else "We never ask for your PIN, OTP, or password. Our team will review the case through official support channels."
        )
    return ensure_safety_phrase(reply, language)


def response_safety_filter(response: dict[str, Any], complaint: str = "", language: str | None = None) -> dict[str, Any]:
    safe = dict(response)
    reply_language = detect_language(complaint, language)
    if reply_language == "mixed":
        reply_language = "en"

    safe["customer_reply"] = sanitize_customer_reply(safe.get("customer_reply"), reply_language)

    if safe.get("case_type") == "phishing_or_social_engineering":
        safe["department"] = "fraud_risk"
        safe["severity"] = "critical"
        safe["human_review_required"] = True

    try:
        confidence = float(safe.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    safe["confidence"] = max(0.0, min(1.0, confidence))

    if not isinstance(safe.get("reason_codes"), list):
        safe["reason_codes"] = []
    return safe


def reply_has_unsafe_content(reply: str) -> bool:
    normalized = normalize_text(reply)
    if _asks_for_secret(reply):
        return True
    unsafe_promises = [
        "we will refund you",
        "your money has been reversed",
        "your account has been unblocked",
        "send us your otp",
        "send your pin",
        "provide your password",
    ]
    return any(phrase in normalized for phrase in unsafe_promises)

