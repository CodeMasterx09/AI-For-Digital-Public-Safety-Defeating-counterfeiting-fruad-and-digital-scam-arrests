"""
PRAHARI AI — WhatsApp Webhook (Twilio Sandbox)
===============================================
Gives citizens a REAL phone-based entry point — the most powerful
demo moment in the hackathon. A judge can WhatsApp your number
LIVE ON STAGE and see the fraud detection result on their phone.

SETUP (10 minutes, completely free):
─────────────────────────────────────
1. Sign up at https://www.twilio.com (free trial, no credit card for sandbox)
2. Go to Messaging → Try it out → Send a WhatsApp message
3. You'll get a sandbox number + join code (e.g. "join bright-mountain")
4. In the Twilio Console → Sandbox settings → set webhook URL:
      https://YOUR_NGROK_URL/webhook/whatsapp
5. Run ngrok to expose your local server:
      ngrok http 8000
6. Copy the https URL into Twilio's webhook field
7. Anyone who sends "join bright-mountain" to the sandbox number
   can then WhatsApp scam messages and get instant PRAHARI AI analysis

DEMO SCRIPT FOR JUDGES:
────────────────────────
"WhatsApp +1 415 523 8886, send 'join [your-word]'.
 Then send any suspicious message.
 PRAHARI AI will reply in under 5 seconds."

Watch the fraud ring counter on the dashboard go up in real time.

ADD TO .env:
────────────
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886

ENDPOINTS:
──────────
POST /webhook/whatsapp        Twilio message webhook (incoming citizen message)
GET  /webhook/whatsapp/status Live WhatsApp stats (sessions via WhatsApp)
POST /webhook/whatsapp/test   Test locally without Twilio (direct JSON POST)
"""

import os
import logging
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, Form, HTTPException, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

logger = logging.getLogger("prahari.whatsapp")

router = APIRouter(prefix="/webhook/whatsapp", tags=["WhatsApp"])

# ── In-memory session tracker for WhatsApp conversations ─────────────────────
# Keeps state per sender number so we can have multi-turn conversations
_wa_sessions: dict = {}   # from_number -> {last_result, message_count, first_seen}
_wa_message_count = 0

def _now():
    return datetime.now(timezone.utc).isoformat()


# ── TwiML builder (no twilio SDK needed — plain XML) ─────────────────────────

def _twiml(message: str) -> Response:
    """Return a valid Twilio TwiML XML response."""
    # Escape XML special characters
    msg = (message
           .replace("&", "&amp;")
           .replace("<", "&lt;")
           .replace(">", "&gt;"))
    xml = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{msg}</Message></Response>'
    return Response(content=xml, media_type="application/xml")


# ── Format PRAHARI result for WhatsApp (SMS-friendly, no markdown) ───────────

def _format_whatsapp_reply(result: dict, original_text: str) -> str:
    verdict    = result.get("verdict", "LIKELY_SAFE")
    confidence = result.get("confidence", 0)
    scam_type  = result.get("scam_type", "UNKNOWN").replace("_", " ")
    session_id = result.get("session_id", "N/A")
    layers     = result.get("layers_used", ["rule_engine"])
    reasoning  = result.get("reasoning", "")
    flags      = result.get("flags", [])
    tactics    = result.get("manipulation_tactics", [])
    novel      = result.get("novel_threat_analysis")
    why_missed = result.get("why_rules_missed", "")

    # Header line
    if verdict == "SCAM_LIKELY":
        header = "🚨 *SCAM DETECTED* 🚨"
        color_bar = "━━━━━━━━━━━━━━━━━━━━"
    elif verdict == "SUSPICIOUS":
        header = "⚠️ *SUSPICIOUS MESSAGE* ⚠️"
        color_bar = "━━━━━━━━━━━━━━━━━━━━"
    else:
        header = "✅ *LIKELY SAFE*"
        color_bar = "━━━━━━━━━━━━━━━━━━━━"

    lines = [
        f"*PRAHARI AI — Fraud Shield*",
        color_bar,
        f"{header}",
        f"",
        f"📊 *Risk Score:* {confidence}/100",
        f"🔍 *Threat Type:* {scam_type}",
        f"🤖 *AI Engine:* {' + '.join(l.replace('_',' ').title() for l in layers)}",
    ]

    # Reasoning (most important — shows Gemini is doing real work)
    if reasoning:
        lines += ["", f"💡 *Why flagged:*", reasoning[:300]]

    # Novel threat — this is the showstopper for judges
    if novel and novel.get("is_novel_threat"):
        lines += [
            "",
            "🔬 *NOVEL THREAT DETECTED*",
            f"This message had ZERO scam keywords — yet Gemini's",
            f"behavioral AI flagged covert manipulation:",
        ]
        if tactics:
            lines.append("Tactics: " + ", ".join(tactics[:3]))
        if why_missed:
            lines.append(f"Why rules missed it: {why_missed[:150]}")

    # Flags
    if flags:
        lines += ["", "🚩 *Red Flags:*"]
        for f in flags[:4]:
            lines.append(f"  • {f}")

    # Manipulation tactics
    if tactics and not novel:
        lines += ["", "🧠 *Manipulation tactics used:*"]
        for t in tactics[:3]:
            lines.append(f"  • {t}")

    # Verdict-specific advice
    lines += ["", "📋 *What to do:*"]
    if verdict == "SCAM_LIKELY":
        lines += [
            "1. STOP all communication immediately",
            "2. Do NOT transfer money or share OTP",
            "3. Real police NEVER arrest via WhatsApp/phone",
            "4. Call *1930* (Cyber Crime Helpline) NOW",
            "5. Report at cybercrime.gov.in",
        ]
    elif verdict == "SUSPICIOUS":
        lines += [
            "1. Do NOT share OTP, PIN, or bank details",
            "2. Call the organisation directly (official number)",
            "3. Consult a trusted family member before acting",
            "4. Report if confirmed: call *1930*",
        ]
    else:
        lines += [
            "Stay vigilant — never share financial details",
            "with unverified contacts.",
            "Save *1930* in your contacts.",
        ]

    lines += [
        "",
        color_bar,
        f"📌 Case ID: {session_id}",
        f"🛡 PRAHARI AI | cybercrime.gov.in | 1930",
    ]

    return "\n".join(lines)


# ── Help message ──────────────────────────────────────────────────────────────

HELP_MESSAGE = """🛡 *PRAHARI AI — Fraud Shield*
━━━━━━━━━━━━━━━━━━━━

India's AI-powered scam detector.

*How to use:*
Simply forward or paste any suspicious message, and I'll analyze it instantly.

*Commands:*
• Send any suspicious text → Instant fraud analysis
• Send *HELP* → This message
• Send *STATUS* → Your session stats
• Send *ABOUT* → How PRAHARI AI works

*Supported languages:*
English, हिन्दी, मराठी, ગુજરાતી, தமிழ், বাংলা

*Emergency:* Call *1930* (Cyber Crime Helpline)
*Report:* cybercrime.gov.in

━━━━━━━━━━━━━━━━━━━━
Powered by Gemini AI + Graph Intelligence"""

ABOUT_MESSAGE = """🤖 *How PRAHARI AI Works*
━━━━━━━━━━━━━━━━━━━━

PRAHARI uses a *3-layer AI pipeline:*

*Layer 1 — Rule Engine (instant)*
35+ patterns across English + Hindi/Marathi/Gujarati. Catches known scam keywords instantly.

*Layer 2 — Gemini AI (< 3 sec)*
Google's Gemini LLM analyzes context, intent, and tone — not just keywords. Works in all Indian languages natively.

*Layer 3 — Novel Threat Detection*
For messages with ZERO keywords, Gemini detects hidden social engineering — emotional manipulation, isolation tactics, false urgency — the scams that bypass all keyword filters.

*Graph Intelligence:*
Your report links to PRAHARI's fraud network graph. If the sender's number appears in a known fraud ring, we flag it immediately.

━━━━━━━━━━━━━━━━━━━━
Built for Bharat 🇮🇳"""


# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK ENDPOINT — Twilio calls this for every incoming WhatsApp message
# ══════════════════════════════════════════════════════════════════════════════

@router.post("")
async def whatsapp_incoming(
    request: Request,
    Body: str = Form(default=""),
    From: str = Form(default=""),
    To: str = Form(default=""),
    MessageSid: str = Form(default=""),
    ProfileName: str = Form(default=""),
):
    """
    Main WhatsApp webhook — Twilio POSTs here for every incoming message.
    
    Twilio sends form data with fields: Body, From, To, MessageSid, ProfileName, etc.
    We return TwiML XML with the reply message.
    """
    global _wa_message_count

    from_number = From or "unknown"
    body        = (Body or "").strip()
    name        = ProfileName or "Citizen"

    logger.info(f"WhatsApp from={from_number} name={name} body={body[:80]}")

    if not body:
        return _twiml("Please send a message to analyze. Type HELP for instructions.")

    # ── Command handling ──────────────────────────────────────────────────
    body_upper = body.upper().strip()

    if body_upper in ("HELP", "HI", "HELLO", "START", "NAMASTE", "नमस्ते"):
        return _twiml(HELP_MESSAGE)

    if body_upper == "ABOUT":
        return _twiml(ABOUT_MESSAGE)

    if body_upper == "STATUS":
        session = _wa_sessions.get(from_number, {})
        count   = session.get("message_count", 0)
        since   = session.get("first_seen", _now())[:10]
        scams   = session.get("scams_caught", 0)
        reply   = (
            f"📊 *Your PRAHARI Session*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Messages analyzed: {count}\n"
            f"Scams detected: {scams}\n"
            f"Active since: {since}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Keep forwarding suspicious messages to stay protected! 🛡"
        )
        return _twiml(reply)

    # ── Fraud Analysis ───────────────────────────────────────────────────
    # Import here to avoid circular imports
    from gemini_classifier import classify

    try:
        result = await classify(body, language="auto")
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return _twiml(
            "⚠️ Analysis temporarily unavailable. "
            "For urgent scam help, call 1930 immediately."
        )

    # Update session tracking
    _wa_message_count += 1
    if from_number not in _wa_sessions:
        _wa_sessions[from_number] = {
            "message_count": 0, "scams_caught": 0,
            "first_seen": _now(), "name": name,
        }
    _wa_sessions[from_number]["message_count"] += 1
    _wa_sessions[from_number]["last_seen"] = _now()
    if result.get("verdict") == "SCAM_LIKELY":
        _wa_sessions[from_number]["scams_caught"] = \
            _wa_sessions[from_number].get("scams_caught", 0) + 1

    # Store result for session context
    _wa_sessions[from_number]["last_result"] = result

    # Format and return the WhatsApp reply
    reply = _format_whatsapp_reply(result, body)
    return _twiml(reply)


# ══════════════════════════════════════════════════════════════════════════════
# TEST ENDPOINT — Test without Twilio (POST JSON directly)
# ══════════════════════════════════════════════════════════════════════════════

class WATestRequest(BaseModel):
    message: str
    from_number: str = "+91TEST0000"
    language: str = "auto"

@router.post("/test")
async def whatsapp_test(req: WATestRequest):
    """
    Test the WhatsApp pipeline locally without Twilio.
    POST { "message": "your suspicious text here" }
    Returns the formatted WhatsApp reply as plain text + full analysis JSON.
    """
    from gemini_classifier import classify

    result = await classify(req.message, language=req.language)
    formatted = _format_whatsapp_reply(result, req.message)

    return {
        "whatsapp_reply": formatted,
        "raw_analysis": result,
        "layers_used": result.get("layers_used", []),
        "novel_threat": result.get("novel_threat_analysis") is not None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# STATUS ENDPOINT — Live WhatsApp stats for the dashboard
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/status")
async def whatsapp_status():
    """Returns live WhatsApp channel statistics."""
    total_scams = sum(s.get("scams_caught", 0) for s in _wa_sessions.values())
    return {
        "channel": "whatsapp",
        "total_sessions": len(_wa_sessions),
        "total_messages": _wa_message_count,
        "total_scams_caught": total_scams,
        "active_users": len([s for s in _wa_sessions.values()
                              if s.get("last_seen", "")[:10] == _now()[:10]]),
        "twilio_configured": bool(os.getenv("TWILIO_ACCOUNT_SID")),
        "sandbox_number": os.getenv("TWILIO_WHATSAPP_FROM", "Not configured"),
        "setup_instructions": "See whatsapp_webhook.py docstring for 10-minute setup guide",
    }
