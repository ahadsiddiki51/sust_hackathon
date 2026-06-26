# QueueStorm Investigator

QueueStorm Investigator is a lightweight FastAPI service for the SUST CSE Carnival 2026 Codex Community Hackathon preliminary problem. It analyzes synthetic digital finance support tickets, investigates the complaint against transaction history, and returns a safe structured support-ops response.

The default implementation is deterministic and rule-based. It does not require paid AI APIs, GPU access, large model downloads, or real payment integrations.

## Tech Stack

- Python 3.12+
- FastAPI
- Pydantic
- Uvicorn
- Pure-Python deterministic reasoning for classification, evidence matching, and safety filtering

## API

### `GET /health`

Returns exactly:

```json
{
  "status": "ok"
}
```

### `POST /analyze-ticket`

Required request fields:

- `ticket_id`: string
- `complaint`: string

Optional request fields:

- `language`: `en`, `bn`, or `mixed`
- `channel`: `in_app_chat`, `call_center`, `email`, `merchant_portal`, `field_agent`
- `user_type`: `customer`, `merchant`, `agent`, `unknown`
- `campaign_context`: string
- `transaction_history`: array of transaction objects
- `metadata`: object

Transaction fields may include:

- `transaction_id`
- `timestamp`
- `type`: `transfer`, `payment`, `cash_in`, `cash_out`, `settlement`, `refund`
- `amount`
- `counterparty`
- `status`: `completed`, `failed`, `pending`, `reversed`

Response fields:

- `ticket_id`
- `relevant_transaction_id`
- `evidence_verdict`: `consistent`, `inconsistent`, `insufficient_data`
- `case_type`: `wrong_transfer`, `payment_failed`, `refund_request`, `duplicate_payment`, `merchant_settlement_delay`, `agent_cash_in_issue`, `phishing_or_social_engineering`, `other`
- `severity`: `low`, `medium`, `high`, `critical`
- `department`: `customer_support`, `dispute_resolution`, `payments_ops`, `merchant_operations`, `agent_operations`, `fraud_risk`
- `agent_summary`
- `recommended_next_action`
- `customer_reply`
- `human_review_required`
- `confidence`
- `reason_codes`

Malformed JSON or missing required fields return `400` with a non-sensitive JSON error. Empty complaints return `422`.

## Local Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
docker build -t queuestorm-investigator .
docker run --rm -p 8000:8000 -e PORT=8000 queuestorm-investigator
```

## Test

The public sample cases can be tested without installing FastAPI:

```bash
python scripts/test_samples.py
```

After the server is running:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"TKT-006","complaint":"Something is wrong with my money. Please check.","transaction_history":[]}'
```

## Environment Variables

- `PORT`: server port, default `8000`
- `ENABLE_LLM`: reserved for future optional LLM support, default `false`
- `LOG_LEVEL`: reserved for deployment logging, default `info`

## Safety Logic

The service treats complaint text as untrusted data. Prompt-injection phrases such as "ignore previous instructions" are ignored and may be added to `reason_codes`.

Customer replies are passed through a final safety filter. Replies must never ask for PIN, OTP, password, passcode, full card number, or other secret credentials. The service also avoids unauthorized promises such as "we will refund you", "your money has been reversed", or "your account has been unblocked".

Safe language uses phrases such as:

- "Please do not share your PIN or OTP with anyone."
- "Any eligible amount will be returned through official channels."
- "Refund eligibility depends on merchant or policy confirmation."
- "We will verify the transaction before taking further action."

Bangla complaints receive Bangla customer replies when `language` is `bn` or the complaint is mostly Bangla.

## Evidence Reasoning

The investigator is more than a classifier. It:

- Detects high-priority phishing/social-engineering cases first.
- Extracts amounts, Bangla digits, phone/counterparty hints, and basic date/time hints.
- Scores transaction matches by type, amount, status, counterparty, recency, and complaint semantics.
- Returns `insufficient_data` when multiple transactions plausibly match.
- Marks wrong-transfer claims as `inconsistent` when prior transfers indicate an established recipient pattern.
- Detects duplicate payments by finding same amount, same merchant/biller, completed payment pairs close in time.

## Known Limitations

- This is a rule-based hackathon solution, not a real financial decision engine.
- Date reasoning is intentionally simple and uses transaction history as the reference window for words like "today" and "yesterday".
- Bangla/Banglish handling covers the expected problem vocabulary but is not a full natural-language parser.
- No real customer data, real payment operations, or production secrets are included.

## Deployment Notes

- Bind to `0.0.0.0`.
- Default port is `8000`.
- Keep `ENABLE_LLM=false` for judging unless a separate optional integration is added.
- Do not commit secrets or real customer data.
- Run `python scripts/test_samples.py` before submitting.
