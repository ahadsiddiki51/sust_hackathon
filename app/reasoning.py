from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .safety import response_safety_filter
from .utils import (
    amounts_match,
    contains_any,
    counterparty_is_mentioned,
    date_hint_score,
    detect_language,
    extract_amounts,
    extract_phone_numbers,
    format_amount,
    normalize_phone,
    normalize_text,
    to_plain_dict,
    transaction_amount,
    transaction_datetime,
)


HIGH_VALUE_THRESHOLD = 5000

CASE_DEPARTMENTS = {
    "wrong_transfer": "dispute_resolution",
    "payment_failed": "payments_ops",
    "refund_request": "customer_support",
    "duplicate_payment": "payments_ops",
    "merchant_settlement_delay": "merchant_operations",
    "agent_cash_in_issue": "agent_operations",
    "phishing_or_social_engineering": "fraud_risk",
    "other": "customer_support",
}

EXPECTED_TYPES = {
    "wrong_transfer": "transfer",
    "payment_failed": "payment",
    "refund_request": "payment",
    "duplicate_payment": "payment",
    "merchant_settlement_delay": "settlement",
    "agent_cash_in_issue": "cash_in",
}

PHISHING_SECRET_TERMS = [
    "otp",
    "pin",
    "password",
    "passcode",
    "verification code",
    "share otp",
    "share pin",
    "পিন",
    "ওটিপি",
    "পাসওয়ার্ড",
    "পাসওয়ার্ড",
    "কোড",
]

PHISHING_CONTEXT_TERMS = [
    "someone called",
    "called me",
    "call from",
    "sms",
    "message",
    "suspicious link",
    "fake support",
    "pretending",
    "account blocked",
    "blocked",
    "support",
    "bkash",
    "company",
    "কল",
    "মেসেজ",
    "লিংক",
    "ব্লক",
    "শেয়ার",
    "শেয়ার",
]

PROMPT_INJECTION_TERMS = [
    "ignore previous instructions",
    "ignore all instructions",
    "system prompt",
    "developer message",
    "ask user for otp",
    "confirm refund now",
]

DUPLICATE_TERMS = ["duplicate", "twice", "double", "deducted twice", "charged twice", "double charge", "দুইবার", "দুবার", "ডবল", "ডাবল", "২ বার"]
SETTLEMENT_TERMS = ["settlement", "settled", "sales", "batch", "merchant settlement", "সেটেলমেন্ট", "সেটেল"]
AGENT_CASH_IN_TERMS = [
    "cash in",
    "cash-in",
    "cashin",
    "agent",
    "deposit not reflected",
    "balance not reflected",
    "not reflected",
    "এজেন্ট",
    "ক্যাশ ইন",
    "ক্যাশইন",
    "ব্যালেন্সে আসেনি",
    "ক্যাশ-ইন",
    "এজেন্টের",
]
FAILED_TERMS = ["failed", "fail", "unsuccessful", "recharge failed", "payment failed", "ব্যর্থ", "ফেইল", "ফেল", "হয়নি", "হয় নাই", "সফল হয়নি", "সফল হয় নাই", "কাজ করছে না", "অসফল"]
DEDUCTION_TERMS = ["deduct", "deducted", "balance cut", "balance was deducted", "cut from", "কেটে", "কাটা", "ব্যালেন্স"]
WRONG_TRANSFER_TERMS = [
    "wrong number",
    "wrong person",
    "wrong recipient",
    "wrong transfer",
    "typed it wrong",
    "by mistake",
    "mistake",
    "recipient not responding",
    "not responding",
    "reverse it",
    "ভুল নম্বর",
    "ভুল মানুষ",
    "ভুলে পাঠিয়েছি",
    "ভুলে পাঠিয়েছি",
    "ভুল নাম্বারে",
    "ভুল নম্বরে",
    "ভুল নাম্বারে পাঠিয়েছি",
    "ভুল নাম্বারে চলে গেছে",
    "ভুল নম্বরে চলে গেছে",
    "ফেরত",
]
TRANSFER_TERMS = ["sent", "send", "transfer", "transferred", "পাঠিয়েছি", "পাঠিয়েছি", "পাঠাইছি"]
NOT_RECEIVED_TERMS = [
    "didn't get",
    "did not get",
    "not get it",
    "not received",
    "hasn't received",
    "haven't received",
    "didn't receive",
    "পায়নি",
    "পায়নি",
    "আসেনি",
]
REFUND_TERMS = [
    "refund",
    "return money",
    "return my money",
    "cancel purchase",
    "changed my mind",
    "merchant refund",
    "টাকা ফেরত",
    "ফেরত",
]


@dataclass
class MatchDecision:
    transaction: dict[str, Any] | None = None
    evidence_verdict: str = "insufficient_data"
    ambiguous: bool = False
    score: float = 0.0
    reason_codes: list[str] = field(default_factory=list)


def analyze_ticket(payload: Any) -> dict[str, Any]:
    data = to_plain_dict(payload)
    ticket_id = str(data.get("ticket_id", ""))
    complaint = str(data.get("complaint", "") or "")
    transactions = normalize_transactions(data.get("transaction_history") or [])
    language = detect_language(complaint, data.get("language"))
    normalized = normalize_text(complaint)
    amounts = extract_amounts(complaint)
    reason_codes: list[str] = []

    if contains_any(normalized, PROMPT_INJECTION_TERMS):
        reason_codes.append("prompt_injection_ignored")

    clean_normalized = normalized
    if "prompt_injection_ignored" in reason_codes:
        for term in PROMPT_INJECTION_TERMS:
            clean_normalized = clean_normalized.replace(term.lower(), "")
        clean_normalized = " ".join(clean_normalized.split())

    if is_phishing_report(clean_normalized):
        response = build_phishing_response(ticket_id, complaint, language, reason_codes)
        return response_safety_filter(response, complaint, language)

    case_type = detect_case_type(data, clean_normalized, transactions)
    match = investigate_case(case_type, complaint, transactions)
    reason_codes.extend(match.reason_codes)

    department = department_for_case(case_type, match, amounts)
    severity = determine_severity(case_type, complaint, match, amounts)
    human_review_required = determine_human_review(case_type, match, severity, amounts)
    confidence = determine_confidence(case_type, match)

    response = {
        "ticket_id": ticket_id,
        "relevant_transaction_id": transaction_id(match.transaction),
        "evidence_verdict": match.evidence_verdict,
        "case_type": case_type,
        "severity": severity,
        "department": department,
        "agent_summary": build_agent_summary(case_type, complaint, match, transactions, amounts),
        "recommended_next_action": build_next_action(case_type, match, amounts),
        "customer_reply": build_customer_reply(case_type, match, language, transactions),
        "human_review_required": human_review_required,
        "confidence": confidence,
        "reason_codes": dedupe(reason_codes or [case_type]),
    }
    return response_safety_filter(response, complaint, language)


def normalize_transactions(raw_transactions: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_transactions, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in raw_transactions:
        plain = to_plain_dict(item)
        if isinstance(plain, dict):
            normalized.append(plain)
    return normalized


def is_phishing_report(normalized_complaint: str) -> bool:
    has_secret = any(normalize_text(term) in normalized_complaint for term in PHISHING_SECRET_TERMS)
    has_context = any(normalize_text(term) in normalized_complaint for term in PHISHING_CONTEXT_TERMS)
    if has_secret and has_context:
        return True
    strong_terms = ["suspicious link", "fake support", "pretending to be", "phishing", "scam call"]
    return any(term in normalized_complaint for term in strong_terms)


def detect_case_type(data: dict[str, Any], normalized: str, transactions: list[dict[str, Any]]) -> str:
    user_type = data.get("user_type")
    channel = data.get("channel")

    if contains_any(normalized, DUPLICATE_TERMS):
        return "duplicate_payment"

    if (
        user_type == "merchant"
        or channel == "merchant_portal"
        or contains_any(normalized, SETTLEMENT_TERMS)
    ) and contains_any(normalized, ["settlement", "settled", "sales", "not settled", "সেটেলমেন্ট", "সেটেল"]):
        return "merchant_settlement_delay"

    if contains_any(normalized, AGENT_CASH_IN_TERMS) and contains_any(
        normalized, ["cash", "deposit", "balance", "not reflected", "আসেনি", "ক্যাশ", "ব্যালেন্স"]
    ):
        return "agent_cash_in_issue"

    if contains_any(normalized, FAILED_TERMS) and (
        contains_any(normalized, DEDUCTION_TERMS) or contains_any(normalized, ["payment", "recharge", "রিচার্জ", "পেমেন্ট"])
    ):
        return "payment_failed"

    if contains_any(normalized, WRONG_TRANSFER_TERMS):
        return "wrong_transfer"

    if contains_any(normalized, TRANSFER_TERMS) and contains_any(normalized, NOT_RECEIVED_TERMS):
        return "wrong_transfer"

    if contains_any(normalized, REFUND_TERMS):
        return "refund_request"

    # Fallback to transactions if simple text keywords are ambiguous or missing specific category clues
    if contains_any(normalized, FAILED_TERMS):
        has_failed_payment = any(
            normalize_text(tx.get("type")) == "payment" and normalize_text(tx.get("status")) == "failed"
            for tx in transactions
        )
        if has_failed_payment:
            return "payment_failed"

        has_failed_transfer = any(
            normalize_text(tx.get("type")) == "transfer" and normalize_text(tx.get("status")) == "failed"
            for tx in transactions
        )
        if has_failed_transfer:
            return "wrong_transfer"

    return "other"


def investigate_case(case_type: str, complaint: str, transactions: list[dict[str, Any]]) -> MatchDecision:
    if case_type == "other":
        return MatchDecision(reason_codes=["vague_complaint", "needs_clarification"])

    if case_type == "duplicate_payment":
        duplicate_tx = find_duplicate_transaction(complaint, transactions)
        if duplicate_tx:
            return MatchDecision(
                transaction=duplicate_tx,
                evidence_verdict="consistent",
                reason_codes=["duplicate_payment", "biller_verification_required"],
                score=1.0,
            )
        best = find_best_transaction(case_type, complaint, transactions)
        if best.transaction:
            best.evidence_verdict = "inconsistent"
            best.reason_codes = ["duplicate_claim", "no_duplicate_evidence"]
            return best
        return MatchDecision(reason_codes=["duplicate_claim", "no_matching_transaction"])

    best = find_best_transaction(case_type, complaint, transactions)
    if best.ambiguous:
        best.evidence_verdict = "insufficient_data"
        best.reason_codes = ["ambiguous_match", "needs_clarification"]
        return best
    if not best.transaction:
        best.evidence_verdict = "insufficient_data"
        best.reason_codes = [case_type, "no_matching_transaction"]
        return best

    tx = best.transaction
    status = normalize_text(tx.get("status"))
    if case_type == "wrong_transfer":
        best.reason_codes = ["wrong_transfer", "transaction_match"]
        if has_established_recipient_pattern(tx, transactions):
            best.evidence_verdict = "inconsistent"
            best.reason_codes = ["wrong_transfer_claim", "established_recipient_pattern", "evidence_inconsistent"]
        else:
            best.evidence_verdict = "consistent"
    elif case_type == "payment_failed":
        best.evidence_verdict = "consistent" if status == "failed" else "inconsistent"
        best.reason_codes = ["payment_failed", "potential_balance_deduction"]
        if best.evidence_verdict == "inconsistent":
            best.reason_codes.append("status_mismatch")
    elif case_type == "refund_request":
        best.evidence_verdict = "consistent" if status == "completed" else "insufficient_data"
        best.reason_codes = ["refund_request", "merchant_policy_dependent"]
    elif case_type == "merchant_settlement_delay":
        best.evidence_verdict = "consistent" if status == "pending" else "inconsistent"
        best.reason_codes = ["merchant_settlement", "delay"]
        if status == "pending":
            best.reason_codes.append("pending")
    elif case_type == "agent_cash_in_issue":
        best.evidence_verdict = "consistent" if status in {"pending", "completed"} else "inconsistent"
        best.reason_codes = ["agent_cash_in", "agent_ops"]
        if status:
            best.reason_codes.append(f"{status}_transaction")
    return best


def find_best_transaction(case_type: str, complaint: str, transactions: list[dict[str, Any]]) -> MatchDecision:
    if not transactions:
        return MatchDecision()

    expected_type = EXPECTED_TYPES.get(case_type)
    preferred = [tx for tx in transactions if normalize_text(tx.get("type")) == expected_type]
    candidates = preferred or transactions
    scored = [
        (score_transaction_match(case_type, complaint, tx, transactions), tx)
        for tx in candidates
    ]
    scored = [(score, tx) for score, tx in scored if score > 0]
    scored.sort(key=lambda item: item[0], reverse=True)

    if not scored:
        return MatchDecision()

    min_score = minimum_score(case_type, complaint)
    top_score, top_tx = scored[0]
    if top_score < min_score:
        return MatchDecision(score=top_score)

    if len(scored) > 1:
        second_score, _ = scored[1]
        if second_score >= min_score and top_score - second_score <= 1.5:
            return MatchDecision(ambiguous=True, score=top_score)

    return MatchDecision(transaction=top_tx, evidence_verdict="consistent", score=top_score)


def score_transaction_match(
    case_type: str,
    complaint: str,
    transaction: dict[str, Any],
    transactions: list[dict[str, Any]],
) -> float:
    expected_type = EXPECTED_TYPES.get(case_type)
    tx_type = normalize_text(transaction.get("type"))
    tx_status = normalize_text(transaction.get("status"))
    amount = transaction_amount(transaction)
    mentioned_amounts = extract_amounts(complaint)
    score = 0.0

    if expected_type and tx_type == expected_type:
        score += 4.0
    elif expected_type:
        score -= 2.0

    if mentioned_amounts:
        if any(amounts_match(amount, mentioned) for mentioned in mentioned_amounts):
            score += 5.0
        else:
            score -= 1.0
    else:
        score += 0.5

    phones = extract_phone_numbers(complaint)
    counterparty = str(transaction.get("counterparty") or "")
    if phones:
        normalized_counterparty = normalize_phone(counterparty)
        if any(phone == normalized_counterparty for phone in phones):
            score += 4.0
        else:
            score -= 0.5
    elif counterparty_is_mentioned(counterparty, complaint):
        score += 3.0

    if case_type == "wrong_transfer" and tx_status == "completed":
        score += 1.5
    elif case_type == "payment_failed" and tx_status == "failed":
        score += 2.5
    elif case_type == "refund_request" and tx_status == "completed":
        score += 1.5
    elif case_type == "merchant_settlement_delay" and tx_status == "pending":
        score += 2.0
    elif case_type == "agent_cash_in_issue":
        if tx_status == "pending":
            score += 2.0
        elif tx_status == "completed":
            score += 1.0

    score += date_hint_score(complaint, transaction, transactions)

    tx_dt = transaction_datetime(transaction)
    if tx_dt:
        score += min(tx_dt.timestamp() / 10_000_000_000, 0.2)
    return score


def minimum_score(case_type: str, complaint: str) -> float:
    if extract_amounts(complaint):
        return 6.0
    if case_type in {"merchant_settlement_delay", "agent_cash_in_issue"}:
        return 5.0
    if case_type == "wrong_transfer":
        return 5.5
    return 5.0


def find_duplicate_transaction(complaint: str, transactions: list[dict[str, Any]]) -> dict[str, Any] | None:
    mentioned_amounts = extract_amounts(complaint)
    payments = [
        tx
        for tx in transactions
        if normalize_text(tx.get("type")) == "payment" and normalize_text(tx.get("status")) == "completed"
    ]
    payments.sort(key=lambda tx: (transaction_datetime(tx).timestamp() if transaction_datetime(tx) else 0.0))

    best_pair: tuple[float, dict[str, Any]] | None = None
    for index, first in enumerate(payments):
        for second in payments[index + 1 :]:
            first_amount = transaction_amount(first)
            second_amount = transaction_amount(second)
            if not amounts_match(first_amount, second_amount):
                continue
            if mentioned_amounts and not any(amounts_match(first_amount, amount) for amount in mentioned_amounts):
                continue
            if normalize_text(first.get("counterparty")) != normalize_text(second.get("counterparty")):
                continue

            first_dt = transaction_datetime(first)
            second_dt = transaction_datetime(second)
            seconds_apart = 999999.0
            if first_dt and second_dt:
                seconds_apart = abs((second_dt - first_dt).total_seconds())
                if seconds_apart > 300:
                    continue

            duplicate = second if (not first_dt or not second_dt or second_dt >= first_dt) else first
            pair_score = seconds_apart
            if best_pair is None or pair_score < best_pair[0]:
                best_pair = (pair_score, duplicate)

    return best_pair[1] if best_pair else None


def has_established_recipient_pattern(chosen_tx: dict[str, Any], transactions: list[dict[str, Any]]) -> bool:
    counterparty = normalize_text(chosen_tx.get("counterparty"))
    if not counterparty:
        return False

    chosen_dt = transaction_datetime(chosen_tx)
    prior_count = 0
    same_counterparty_count = 0
    for tx in transactions:
        if tx is chosen_tx:
            continue
        if normalize_text(tx.get("type")) != "transfer":
            continue
        if normalize_text(tx.get("counterparty")) != counterparty:
            continue
        same_counterparty_count += 1
        tx_dt = transaction_datetime(tx)
        if chosen_dt and tx_dt and tx_dt < chosen_dt:
            prior_count += 1
    return prior_count >= 2 or same_counterparty_count >= 2


def department_for_case(case_type: str, match: MatchDecision, amounts: list[float]) -> str:
    if case_type == "refund_request" and (match.evidence_verdict == "inconsistent" or max_amount(amounts) >= HIGH_VALUE_THRESHOLD):
        return "dispute_resolution"
    return CASE_DEPARTMENTS.get(case_type, "customer_support")


def determine_severity(case_type: str, complaint: str, match: MatchDecision, amounts: list[float]) -> str:
    value = case_amount(match, amounts)
    normalized = normalize_text(complaint)

    if case_type == "phishing_or_social_engineering":
        return "critical"
    if case_type == "duplicate_payment":
        return "high"
    if case_type == "agent_cash_in_issue":
        return "high"
    if case_type == "payment_failed":
        return "high" if value >= HIGH_VALUE_THRESHOLD or contains_any(normalized, DEDUCTION_TERMS) else "medium"
    if case_type == "wrong_transfer":
        return "high" if value >= HIGH_VALUE_THRESHOLD else "medium"
    if case_type == "merchant_settlement_delay":
        return "high" if value >= 50000 else "medium"
    if case_type == "refund_request":
        return "medium" if value >= HIGH_VALUE_THRESHOLD else "low"
    return "low"


def determine_human_review(case_type: str, match: MatchDecision, severity: str, amounts: list[float]) -> bool:
    if case_type in {"phishing_or_social_engineering", "duplicate_payment", "agent_cash_in_issue"}:
        return True
    if match.evidence_verdict == "inconsistent":
        return True
    if case_type == "wrong_transfer":
        return match.transaction is not None
    if case_type == "refund_request":
        return case_amount(match, amounts) >= HIGH_VALUE_THRESHOLD
    if case_type == "merchant_settlement_delay":
        return case_amount(match, amounts) >= 50000
    if case_type == "payment_failed":
        return severity == "critical" or case_amount(match, amounts) >= 10000
    return False


def determine_confidence(case_type: str, match: MatchDecision) -> float:
    if case_type == "other":
        return 0.6
    if match.evidence_verdict == "consistent":
        if case_type in {"duplicate_payment", "merchant_settlement_delay"}:
            return 0.92
        if case_type == "agent_cash_in_issue":
            return 0.88
        return 0.9
    if match.evidence_verdict == "inconsistent":
        return 0.75
    if match.ambiguous:
        return 0.65
    return 0.6


def build_phishing_response(
    ticket_id: str,
    complaint: str,
    language: str,
    base_reason_codes: list[str],
) -> dict[str, Any]:
    if language == "bn":
        reply = (
            "ধন্যবাদ সতর্ক থাকার জন্য। আমরা কখনো আপনার পিন, ওটিপি বা পাসওয়ার্ড চাই না। "
            "এগুলো কারো সাথে শেয়ার করবেন না। আমাদের ফ্রড টিম বিষয়টি অফিসিয়াল চ্যানেলের মাধ্যমে পর্যালোচনা করবে।"
        )
    else:
        reply = (
            "Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, "
            "or password under any circumstances. Please do not share these with anyone. Our fraud team "
            "has been notified of this incident."
        )

    return {
        "ticket_id": ticket_id,
        "relevant_transaction_id": None,
        "evidence_verdict": "insufficient_data",
        "case_type": "phishing_or_social_engineering",
        "severity": "critical",
        "department": "fraud_risk",
        "agent_summary": "Customer reports possible social engineering involving credential or account-threat language.",
        "recommended_next_action": (
            "Escalate to fraud_risk immediately, log reported indicators, and remind the customer that official support never asks for secrets."
        ),
        "customer_reply": reply,
        "human_review_required": True,
        "confidence": 0.95,
        "reason_codes": dedupe(base_reason_codes + ["phishing", "credential_protection", "critical_escalation"]),
    }


def build_agent_summary(
    case_type: str,
    complaint: str,
    match: MatchDecision,
    transactions: list[dict[str, Any]],
    amounts: list[float],
) -> str:
    tx = match.transaction
    amount = format_amount(transaction_amount(tx) if tx else (amounts[0] if amounts else None))
    tx_id = transaction_id(tx)
    counterparty = tx.get("counterparty") if tx else None

    if match.ambiguous:
        return (
            f"Customer complaint appears to involve {amount} BDT, but multiple transactions plausibly match. "
            "A disambiguating customer detail is required before action."
        )
    if case_type == "wrong_transfer":
        if tx:
            return f"Customer reports a possible wrong transfer of {amount} BDT via {tx_id} to {counterparty}."
        return "Customer reports a possible wrong transfer, but no single matching transfer could be identified."
    if case_type == "payment_failed":
        if tx:
            return f"Customer reports a failed payment with possible balance deduction for {amount} BDT via {tx_id}."
        return "Customer reports failed payment or deducted balance, but transaction evidence is missing or unclear."
    if case_type == "refund_request":
        if tx:
            return f"Customer requests refund review for completed merchant payment {tx_id} of {amount} BDT."
        return "Customer requests a refund, but no matching completed merchant payment was identified."
    if case_type == "duplicate_payment":
        if tx:
            return f"Customer reports a duplicate payment; {tx_id} is the suspected duplicate transaction for {amount} BDT."
        return "Customer reports a duplicate payment, but transaction history does not show a confirmed duplicate pair."
    if case_type == "merchant_settlement_delay":
        if tx:
            return f"Merchant reports delayed settlement {tx_id} of {amount} BDT with current status {tx.get('status')}."
        return "Merchant reports delayed settlement, but no matching settlement transaction was identified."
    if case_type == "agent_cash_in_issue":
        if tx:
            return f"Customer reports cash-in via agent not reflected in balance; matched transaction {tx_id} for {amount} BDT."
        return "Customer reports an agent cash-in issue, but no matching cash-in transaction was identified."
    return "Customer reports a vague money-related concern without enough detail to identify a transaction."


def build_next_action(case_type: str, match: MatchDecision, amounts: list[float]) -> str:
    tx_id = transaction_id(match.transaction)

    if match.ambiguous:
        return "Ask the customer for a non-secret disambiguating detail such as counterparty number, transaction ID, amount, or approximate time."
    if case_type == "wrong_transfer":
        if tx_id:
            return f"Verify {tx_id} details with the customer and initiate the wrong-transfer dispute workflow per policy."
        return "Ask for transaction ID, amount, recipient number, and approximate time before initiating a dispute."
    if case_type == "payment_failed":
        if tx_id:
            return f"Investigate {tx_id} ledger status. If balance was deducted on a failed payment, start the eligible reversal flow within SLA."
        return "Ask for transaction ID, amount, and time, then check payment ledger status."
    if case_type == "refund_request":
        return "Explain that refund eligibility depends on merchant or policy confirmation; escalate only if the case is contested or high value."
    if case_type == "duplicate_payment":
        if tx_id:
            return f"Verify suspected duplicate {tx_id} with payments_ops and the biller, then initiate reversal only if confirmed eligible."
        return "Review payment history for duplicate evidence before starting any reversal workflow."
    if case_type == "merchant_settlement_delay":
        return "Route to merchant_operations to verify settlement batch status and provide an official ETA if delayed."
    if case_type == "agent_cash_in_issue":
        if tx_id:
            return f"Investigate {tx_id} with agent operations and confirm the cash-in settlement state."
        return "Ask for agent number, amount, and approximate time, then route to agent_operations."
    return "Reply asking for specific non-secret details: transaction ID, amount, approximate time, and what went wrong."


def build_customer_reply(
    case_type: str,
    match: MatchDecision,
    language: str,
    transactions: list[dict[str, Any]],
) -> str:
    tx_id = transaction_id(match.transaction)
    bn = language == "bn"

    if match.ambiguous:
        if bn:
            return "একই রকম একাধিক লেনদেন দেখা যাচ্ছে। সঠিক লেনদেন শনাক্ত করতে প্রাপকের নম্বর বা ট্রানজ্যাকশন আইডি জানান।"
        return "We see multiple similar transactions. Please share the recipient or merchant number, or the transaction ID, so we can identify the right transaction."

    if case_type == "wrong_transfer":
        if bn:
            if tx_id:
                return f"আপনার লেনদেন {tx_id} সম্পর্কে আমরা অবগত হয়েছি। আমাদের dispute দল অফিসিয়াল চ্যানেলের মাধ্যমে বিষয়টি পর্যালোচনা করবে।"
            return "আপনার ভুল ট্রান্সফারের বিষয়টি বুঝেছি। সহায়তার জন্য ট্রানজ্যাকশন আইডি, টাকার পরিমাণ এবং প্রাপকের নম্বর জানান।"
        if tx_id:
            return f"We have noted your concern about transaction {tx_id}. Our dispute team will review the case and contact you through official support channels."
        return "We have noted your wrong-transfer concern. Please share the transaction ID, amount, recipient number, and approximate time so we can review it."

    if case_type == "payment_failed":
        if bn:
            if tx_id:
                return f"লেনদেন {tx_id} এ অপ্রত্যাশিত ব্যালেন্স কাটা হয়েছে কি না আমাদের পেমেন্টস দল যাচাই করবে। যোগ্য কোনো টাকা থাকলে অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে।"
            return "আপনার ব্যর্থ পেমেন্টের বিষয়টি আমরা পেয়েছি। যোগ্য কোনো টাকা থাকলে অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে।"
        if tx_id:
            return f"We have noted that transaction {tx_id} may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels."
        return "We have noted the failed payment concern. Our payments team will review the case and any eligible amount will be returned through official channels."

    if case_type == "refund_request":
        if bn:
            return "সম্পন্ন merchant payment-এর refund merchant বা policy confirmation-এর উপর নির্ভর করে। আমরা বিষয়টি যাচাই করতে সহায়তা করব।"
        return "Refunds for completed merchant payments depend on merchant or policy confirmation. We can help review the transaction, but refund eligibility must be verified first."

    if case_type == "duplicate_payment":
        if bn:
            if tx_id:
                return f"সম্ভাব্য duplicate payment {tx_id} সম্পর্কে আমরা অবগত হয়েছি। আমাদের payments দল যাচাই করবে এবং যোগ্য কোনো টাকা থাকলে অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে।"
            return "সম্ভাব্য duplicate payment সম্পর্কে আমরা অবগত হয়েছি। যাচাইয়ের পর যোগ্য কোনো টাকা থাকলে অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে।"
        if tx_id:
            return f"We have noted the possible duplicate payment for transaction {tx_id}. Our payments team will verify it and any eligible amount will be returned through official channels."
        return "We have noted the possible duplicate payment. Our payments team will verify it and any eligible amount will be returned through official channels."

    if case_type == "merchant_settlement_delay":
        if bn:
            if tx_id:
                return f"আপনার settlement {tx_id} সম্পর্কে আমরা অবগত হয়েছি। merchant operations দল batch status যাচাই করে অফিসিয়াল চ্যানেলে আপডেট দেবে।"
            return "আপনার settlement delay বিষয়টি merchant operations দল যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপডেট দেবে।"
        if tx_id:
            return f"We have noted your concern about settlement {tx_id}. Our merchant operations team will check the batch status and update you through official channels."
        return "We have noted your settlement concern. Our merchant operations team will check the batch status and update you through official channels."

    if case_type == "agent_cash_in_issue":
        if bn:
            if tx_id:
                return f"আপনার লেনদেন {tx_id} এর বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে।"
            return "আপনার এজেন্ট cash-in বিষয়টি আমরা পেয়েছি। যাচাইয়ের জন্য agent number, amount এবং approximate time জানান।"
        if tx_id:
            return f"We have noted your cash-in concern for transaction {tx_id}. Our agent operations team will verify it and update you through official channels."
        return "We have noted your agent cash-in concern. Please share the agent number, amount, and approximate time so we can verify it."

    if bn:
        return "সহায়তা করতে অনুগ্রহ করে ট্রানজ্যাকশন আইডি, টাকার পরিমাণ, আনুমানিক সময় এবং কী সমস্যা হয়েছে তা জানান।"
    return "Thank you for reaching out. To help you faster, please share the transaction ID, the amount involved, approximate time, and a short description of what went wrong."


def case_amount(match: MatchDecision, amounts: list[float]) -> float:
    tx_amount = transaction_amount(match.transaction) if match.transaction else None
    if tx_amount is not None:
        return tx_amount
    return max_amount(amounts)


def max_amount(amounts: list[float]) -> float:
    return max(amounts) if amounts else 0.0


def transaction_id(transaction: dict[str, Any] | None) -> str | None:
    if not transaction:
        return None
    value = transaction.get("transaction_id")
    return str(value) if value else None


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
