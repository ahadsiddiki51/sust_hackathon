from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .models import AnalysisResponse, TicketRequest, dump_model, validate_model
from .reasoning import analyze_ticket


app = FastAPI(
    title="QueueStorm Investigator",
    version="1.0.0",
    description="Deterministic support-ops copilot for synthetic digital finance tickets.",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze-ticket")
async def analyze_ticket_endpoint(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return error_response(400, "malformed_json", "Malformed JSON body.")
    except Exception:
        return error_response(400, "malformed_json", "Malformed JSON body.")

    if not isinstance(payload, dict):
        return error_response(400, "invalid_request", "Request body must be a JSON object.")

    missing = [field for field in ("ticket_id", "complaint") if field not in payload]
    if missing:
        return error_response(400, "missing_required_field", f"Missing required field: {missing[0]}.")

    if not isinstance(payload.get("ticket_id"), str) or not payload.get("ticket_id").strip():
        return error_response(400, "invalid_ticket_id", "ticket_id must be a non-empty string.")

    if not isinstance(payload.get("complaint"), str):
        return error_response(400, "invalid_complaint", "complaint must be a string.")
    if not payload.get("complaint", "").strip():
        return error_response(422, "empty_complaint", "complaint must not be empty.")

    try:
        ticket = validate_model(TicketRequest, payload)
    except ValidationError:
        return error_response(422, "validation_error", "Request fields failed validation.")

    try:
        result = analyze_ticket(ticket)
        response_model = validate_model(AnalysisResponse, result)
    except ValidationError:
        return error_response(500, "response_validation_error", "Unable to produce a valid analysis response.")
    except Exception:
        return error_response(500, "internal_error", "Unable to analyze ticket safely.")

    return JSONResponse(status_code=200, content=dump_model(response_model))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return error_response(500, "internal_error", "Unable to process the request safely.")


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    content: dict[str, Any] = {"error": {"code": code, "message": message}}
    return JSONResponse(status_code=status_code, content=content)

