# QueueStorm Investigator

We built QueueStorm Investigator for the SUST CSE Carnival 2026 Codex Community Hackathon preliminary round. Our goal is to provide a lightweight support-ops copilot for synthetic digital finance tickets. The API reads a customer complaint, checks it against transaction history, classifies the case, and returns a safe structured response for support teams.

We intentionally kept the solution deterministic, fast, and local. The default path does not use paid AI APIs, external model calls, GPU resources, or real payment integrations.

## Tech Stack

- Python 3.12+
- FastAPI for the HTTP API
- Pydantic for request and response validation
- Uvicorn as the ASGI server
- Docker for packaging and deployment
- Pure-Python rule-based reasoning for classification, evidence matching, and safety filtering

## MODELS

We do not use any external AI model by default.

- Default mode: deterministic rule-based investigator.
- Model provider: none.
- API keys required: none.
- Runtime internet access required: no.
- Paid AI APIs required: no.
- Optional LLM support: not enabled. `ENABLE_LLM=false` is reserved only for future extension.

For judging, our submitted behavior is fully local and deterministic.

## AI Approach

Our approach is to simulate an AI support copilot with transparent rules instead of relying on a black-box model. We classify the ticket, inspect transaction evidence, decide whether the complaint is supported by the data, and generate a guarded customer reply.

Our reasoning flow:

1. We normalize complaint text, including Bangla digits.
2. We detect phishing or social-engineering first because safety has priority over normal routing.
3. We classify the complaint into one of the allowed case types.
4. We score transaction matches using transaction type, amount, status, counterparty, date/time hints, and complaint semantics.
5. We return `insufficient_data` instead of guessing when evidence is missing or multiple transactions are plausible.
6. We generate the support summary, next action, customer reply, confidence, and reason codes.
7. We run a final safety filter before returning the response.

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

## Setup

From the project folder:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run Locally

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

On Windows PowerShell after activating `.venv`:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## Docker

Build and run:

```bash
docker build -t queuestorm-investigator .
docker run --rm -p 8000:8000 -e PORT=8000 queuestorm-investigator
```

The API will be available at:

```text
http://127.0.0.1:8000
```

## Runbook

### Start Locally

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Start With Docker

```bash
docker build -t queuestorm-investigator .
docker run -d --restart unless-stopped -p 8000:8000 --name queuestorm queuestorm-investigator
```

### Health Check

```bash
curl http://localhost:8000/health
```

Expected:

```json
{"status":"ok"}
```

### Analyze A Ticket

```bash
curl -X POST http://localhost:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"TKT-006","complaint":"Something is wrong with my money. Please check.","transaction_history":[]}'
```

### Update A Docker Deployment

```bash
git pull
docker stop queuestorm
docker rm queuestorm
docker build -t queuestorm-investigator .
docker run -d --restart unless-stopped -p 8000:8000 --name queuestorm queuestorm-investigator
```

## Testing

We included a public sample regression script:

```bash
python scripts/test_samples.py
```

After the server is running, we can also test with curl:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"TKT-006","complaint":"Something is wrong with my money. Please check.","transaction_history":[]}'
```

## Environment Variables

- `PORT`: server port, default `8000`.
- `ENABLE_LLM`: reserved for future optional LLM support, default `false`.
- `LOG_LEVEL`: reserved for deployment logging, default `info`.

## Safety Logic

We treat complaint text as untrusted user input. If a complaint contains prompt-injection text such as "ignore previous instructions" or "ask user for OTP", we ignore that instruction and continue normal analysis.

Our customer replies go through a final safety filter. We never ask for:

- PIN
- OTP
- Password
- Passcode
- Full card number
- Secret credentials

We also avoid unauthorized promises. Our API should not claim that a refund, reversal, recovery, or account unblock has already happened unless that authority is present in the input, which it is not for this challenge.

Safe wording we use:

- "Please do not share your PIN or OTP with anyone."
- "Any eligible amount will be returned through official channels."
- "Refund eligibility depends on merchant or policy confirmation."
- "We will verify the transaction before taking further action."

For Bangla complaints, we return Bangla customer replies when `language` is `bn` or the complaint is mostly Bangla.

## Evidence Reasoning

We designed the service to be more than a keyword classifier. It compares the complaint with transaction history and explains its decision through `evidence_verdict`, `confidence`, and `reason_codes`.

Our evidence checks include:

- High-priority phishing and social-engineering detection.
- Amount extraction, including Bangla digits.
- Phone and counterparty hint extraction.
- Basic date/time hints such as "today", "yesterday", and simple hour references.
- Transaction scoring by type, amount, status, counterparty, and complaint semantics.
- Ambiguity detection when multiple transactions plausibly match.
- Inconsistent-evidence detection, such as repeated transfers to the same recipient during a wrong-transfer claim.
- Duplicate payment detection using same amount, same counterparty, completed status, and close timestamps.

## Assumptions

- We assume the input tickets are synthetic hackathon cases, not real customer data.
- We treat `transaction_history` as structured evidence.
- We treat complaint text as untrusted user-provided text.
- We prefer `insufficient_data` over guessing when the evidence is ambiguous.
- We treat amount `>= 5000` BDT as high value unless a stronger case-specific rule applies.
- We interpret words like "today" and "yesterday" relative to the available transaction history instead of the server clock.
- We generate safe support guidance only; we do not perform real refunds, reversals, account unblocks, or payment operations.

## Limitations

- Our solution is a rule-based hackathon implementation, not a real financial decision engine.
- Date reasoning is intentionally simple.
- Bangla and Banglish handling focuses on the expected problem vocabulary, not full natural-language understanding.
- We do not integrate with real payment ledgers, customer accounts, fraud tools, or merchant systems.
- We do not store or process real customer data.
- We do not commit secrets or require runtime secrets.

## Deployment Notes

- We bind the service to `0.0.0.0`.
- The default port is `8000`.
- For judging, we keep `ENABLE_LLM=false`.
- Before submitting, we run `python scripts/test_samples.py`.
- For a public deployment, we submit the deployed base URL plus `/health` and `/analyze-ticket`.

