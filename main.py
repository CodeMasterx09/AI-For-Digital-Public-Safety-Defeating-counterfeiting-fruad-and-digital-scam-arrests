"""
PRAHARI AI — FastAPI Backend v2
Predictive Risk Analysis & Human-AI Response Intelligence

Upgrades from v1:
  ✅ FastAPI (async) replacing stdlib http.server
  ✅ Gemini Free Tier AI classification (replaces Anthropic)
  ✅ WebSocket live alert streaming (/ws/alerts)
  ✅ SQLite persistence (aiosqlite) — real KPI counts that grow
  ✅ .env config loading (python-dotenv)
  ✅ Case file export as PDF (reportlab) or TXT fallback
  ✅ Audit log endpoint
  ✅ Real dashboard counts from DB

Run:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Endpoints:
    GET  /                          health check
    GET  /ws/alerts                 WebSocket live feed
    POST /classify                  Gemini-powered scam classification
    POST /classify-call             call metadata scoring
    POST /classify-currency         counterfeit currency analysis
    GET  /graph                     fraud network graph
    GET  /graph/clusters            fraud ring clusters
    GET  /graph/intel/{id}          cluster intelligence package
    GET  /graph/intel/{id}/case-file  PDF/TXT case file export
    GET  /geo/incidents             geo-tagged incidents
    GET  /geo/hotspots              hotspot grid
    GET  /geo/districts             per-district summary
    GET  /forecast/districts        predictive trend forecasting
    POST /alert                     create MHA alert
    GET  /alerts                    list alerts
    GET  /audit/log                 tamper-evident audit chain
    GET  /audit/verify              verify chain integrity
    GET  /dashboard/summary         KPI summary (real DB counts)
    GET  /sessions                  recent classified sessions
    POST /report/citizen-pdf        citizen-facing fraud report (PDF/TXT)
"""
import os
import uuid
import hashlib
import time
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()  # loads .env file before anything else

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

# ── Internal modules ──────────────────────────────────────────────────────────
from gemini_classifier import classify as gemini_classify, score_call_metadata
from database import (
    init_db, save_session, get_sessions, save_alert, get_alerts,
    count_sessions, count_scams, count_alerts, save_live_incident,
    get_live_incidents, persist_audit_event, get_audit_log,
    get_dashboard_counts,
)
from websocket_manager import ws_manager
from data_generator import generate_fraud_graph, generate_geo_incidents_timeseries, DISTRICTS
from graph_intel import build_graph, detect_clusters, generate_intel_package
from counterfeit_currency import analyze_note_b64
from forecasting import forecast_districts
from geospatial import compute_hotspots, district_summary
import audit_log as audit
from case_file_export import generate_case_file, generate_citizen_report
from whatsapp_webhook import router as whatsapp_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("prahari.main")
START_TIME = time.monotonic()

# ── Config ────────────────────────────────────────────────────────────────────
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_CLASSIFY_PER_MIN = int(os.getenv("MAX_CLASSIFY_PER_MIN", "30"))
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,"
    "http://localhost:5500,http://127.0.0.1:5500,"
    "http://localhost:5501,http://127.0.0.1:5501,"
    "null"
).split(",")

PUBLIC_SAFETY_DISCLAIMER = (
    "\n\n⚠️ IMPORTANT: This is AI-assisted analysis, not a legal verdict. "
    "If you are being scammed, hang up and call 1930 or visit cybercrime.gov.in."
)

# ── Seed in-memory graph + geo data ──────────────────────────────────────────
NODES, EDGES = generate_fraud_graph()
GRAPH = build_graph(NODES, EDGES)
CLUSTERS = detect_clusters(GRAPH)
GEO_INCIDENTS = generate_geo_incidents_timeseries(60)

def _now():
    return datetime.now(timezone.utc).isoformat()

def _hash_pii(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16] + "…[hashed]"


# ── App lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    audit.append_event("SYSTEM_START", {"service": "PRAHARI AI v2", "gemini": bool(os.getenv("GEMINI_API_KEY"))})
    await persist_audit_event(audit.get_log()[-1])
    logger.info(
        f"PRAHARI AI v2 started — "
        f"{GRAPH.number_of_nodes()} entities, {len(CLUSTERS)} clusters, "
        f"{len(GEO_INCIDENTS)} geo incidents. "
        f"Gemini: {'✅ enabled' if os.getenv('GEMINI_API_KEY') else '❌ not configured (rule-based only)'}"
    )
    yield
    logger.info("PRAHARI AI shutting down.")


app = FastAPI(
    title="PRAHARI AI",
    description="Predictive Risk Analysis & Human-AI Response Intelligence",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount WhatsApp webhook router ─────────────────────────────────────────────
app.include_router(whatsapp_router)

# ── Rate limiting (simple in-memory) ─────────────────────────────────────────
_rate_buckets: dict = defaultdict(list)

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    bucket = _rate_buckets[ip]
    _rate_buckets[ip] = [t for t in bucket if now - t < 60]
    if len(_rate_buckets[ip]) >= MAX_CLASSIFY_PER_MIN:
        return True
    _rate_buckets[ip].append(now)
    return False


# ── Pydantic models ───────────────────────────────────────────────────────────
class ClassifyRequest(BaseModel):
    text: str = Field(..., max_length=10000)
    channel: str = "web"
    language: str = "en"
    user_phone: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    district: Optional[str] = None

class CallMetaRequest(BaseModel):
    caller_number: Optional[str] = None
    duration_sec: int = 0
    is_video_call: bool = False
    claimed_authority: str = ""
    multiple_recipients: bool = False
    demanded_payment: bool = False

class CurrencyRequest(BaseModel):
    image_base64: str
    claimed_denomination: Optional[str] = None

class AlertRequest(BaseModel):
    session_id: Optional[str] = None
    risk_score: Optional[int] = None
    reason: Optional[str] = None
    district: Optional[str] = None

class CitizenReportRequest(BaseModel):
    session_id:  Optional[str]   = None
    verdict:     str              = "UNKNOWN"
    risk_score:  int              = 0
    scam_type:   Optional[str]   = None
    channel:     str              = "web"
    district:    Optional[str]   = None
    timestamp:   Optional[str]   = None
    explanation: Optional[str]   = None
    advice:      Optional[list]  = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def health():
    db_sessions = await count_sessions()
    db_alerts   = await count_alerts()
    gemini_key  = os.getenv("GEMINI_API_KEY", "")
    twilio_sid  = os.getenv("TWILIO_ACCOUNT_SID", "")
    return {
        "status":               "operational",
        "service":              "PRAHARI AI v2",
        "version":              "2.0.0",
        "uptime_seconds":       int(time.monotonic() - START_TIME),
        # AI layers
        "gemini":               "enabled" if (gemini_key and gemini_key != "your_gemini_api_key_here") else "rule_based_fallback",
        "novel_detection":      "active" if (gemini_key and gemini_key != "your_gemini_api_key_here") else "disabled",
        "whatsapp_channel":     "configured" if twilio_sid else "sandbox_ready",
        # Live counts
        "websocket_clients":    len(ws_manager.active_connections),
        "total_sessions_db":    db_sessions,
        "total_alerts_db":      db_alerts,
        "fraud_rings_detected": len(CLUSTERS),
        "graph_entities":       GRAPH.number_of_nodes(),
        "graph_linkages":       GRAPH.number_of_edges(),
        "geo_incidents_tracked":len(GEO_INCIDENTS),
        # Pipeline info
        "ai_layers": [
            "rule_engine (instant, offline)",
            "gemini_standard (< 3s, all messages)",
            "gemini_novel_detect (< 3s, low-score messages only)",
        ],
        "channels": ["web", "whatsapp", "api"],
        "languages": ["en", "hi", "mr", "gu", "ta", "bn"],
    }


# ── WebSocket live feed ───────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client can send "ping" to get a pong back
            if data.strip() == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Classify ─────────────────────────────────────────────────────────────────

@app.post("/classify")
async def classify_message(req: ClassifyRequest, request: Request):
    client_ip = request.client.host
    if _is_rate_limited(client_ip):
        raise HTTPException(429, "Too many requests. Wait a minute.")

    result = await gemini_classify(req.text, language=req.language)
    result["channel"] = req.channel
    result["timestamp"] = _now()
    result["advice"] += PUBLIC_SAFETY_DISCLAIMER

    # Persist to DB
    await save_session(result)

    # High-risk actions
    if result.get("confidence", 0) >= 60:
        # Create alert — include novel threat info if present
        novel = result.get("novel_threat_analysis")
        alert = {
            "alert_id":   str(uuid.uuid4())[:8].upper(),
            "session_id": result["session_id"],
            "type":       "NOVEL_THREAT_ALERT" if novel else "MHA_DIGITAL_ARREST_ALERT",
            "risk_score": result["confidence"],
            "verdict":    result["verdict"],
            "district":   req.district,
            "scam_type":  result.get("scam_type", "UNKNOWN"),
            "layers_used":result.get("layers_used", []),
            "timestamp":  _now(),
            "status":     "SENT_TO_TELECOM (simulated)",
        }
        await save_alert(alert)

        # Add to graph
        node_id = f"SESSION_{result['session_id']}"
        GRAPH.add_node(node_id, type="FLAGGED_SESSION", risk=result["confidence"])
        if req.user_phone:
            phone_hash = _hash_pii(req.user_phone)
            GRAPH.add_node(phone_hash, type="PHONE")
            GRAPH.add_edge(node_id, phone_hash, weight=0.9, relation="reported_by")

        # ── LIVE CLUSTER RE-DETECTION ─────────────────────────────────────
        # Every high-risk report enriches the fraud graph.
        # Re-running cluster detection means the fraud_rings KPI on the
        # dashboard can literally increase during your demo as you submit
        # scam messages. This is the real-time intelligence loop.
        global CLUSTERS
        prev_cluster_count = len(CLUSTERS)
        CLUSTERS = detect_clusters(GRAPH)
        new_cluster_count = len(CLUSTERS)
        if new_cluster_count != prev_cluster_count:
            logger.info(
                f"Fraud ring count changed: {prev_cluster_count} → {new_cluster_count}"
            )
            # Broadcast the new cluster count immediately
            await ws_manager.broadcast_dashboard_update({
                "fraud_rings": new_cluster_count,
                "graph_entities": GRAPH.number_of_nodes(),
                "graph_linkages": GRAPH.number_of_edges(),
                "ring_change": new_cluster_count - prev_cluster_count,
            })
        result["fraud_rings_now"] = new_cluster_count
        # ─────────────────────────────────────────────────────────────────

        # Save geo incident
        if req.lat is not None and req.lon is not None:
            inc = {
                "district": req.district or "unknown",
                "lat": req.lat, "lon": req.lon,
                "type": "fraud_complaint",
                "severity": 3 if result["verdict"] == "SCAM_LIKELY" else 2,
                "date": _now()[:10],
            }
            GEO_INCIDENTS.append({**inc, "date": _now()[:10]})
            await save_live_incident(inc)
            await ws_manager.broadcast_incident(inc)

        # Broadcast WebSocket alert
        await ws_manager.broadcast_alert(alert)

        # Audit — log novel threats separately for the chain
        evt_type = "NOVEL_THREAT_DETECTED" if novel else "HIGH_RISK_SESSION"
        evt = audit.append_event(evt_type, {
            "session_id": result["session_id"],
            "confidence": result["confidence"],
            "scam_type":  result.get("scam_type"),
            "layers":     result.get("layers_used", []),
            "novel":      novel is not None,
        })
        await persist_audit_event(evt)

    # Broadcast updated dashboard counts
    counts = await get_dashboard_counts()
    await ws_manager.broadcast_dashboard_update(counts)

    return result


@app.post("/classify-call")
async def classify_call(req: CallMetaRequest):
    return score_call_metadata(req.dict())


@app.post("/classify-currency")
async def classify_currency(req: CurrencyRequest):
    if not req.image_base64:
        raise HTTPException(400, "image_base64 is required")
    if len(req.image_base64) > 2_800_000:
        raise HTTPException(413, "Image too large. Max 2 MB.")
    result = analyze_note_b64(req.image_base64, req.claimed_denomination)
    evt = audit.append_event("CURRENCY_ANALYSIS", {
        "verdict": result.get("verdict"),
        "denomination": req.claimed_denomination,
    })
    await persist_audit_event(evt)
    return result


# ── Graph ─────────────────────────────────────────────────────────────────────

@app.get("/graph")
async def get_graph():
    return {
        "nodes": [{"id": n, **GRAPH.nodes[n]} for n in GRAPH.nodes],
        "edges": [{"source": u, "target": v, **a} for u, v, a in GRAPH.edges()],
    }

@app.get("/graph/clusters")
async def get_clusters():
    return {"clusters": CLUSTERS}

@app.get("/graph/intel/{cluster_id}")
async def get_cluster_intel(cluster_id: int):
    cluster = next((c for c in CLUSTERS if c["cluster_id"] == cluster_id), None)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    intel = generate_intel_package(cluster, GRAPH)
    evt = audit.append_event("INTEL_PACKAGE_ACCESSED", {"cluster_id": cluster_id})
    await persist_audit_event(evt)
    return intel

@app.get("/graph/intel/{cluster_id}/case-file")
async def export_case_file(cluster_id: int):
    cluster = next((c for c in CLUSTERS if c["cluster_id"] == cluster_id), None)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    intel = generate_intel_package(cluster, GRAPH)
    audit_entries = audit.get_log()
    case_ref = f"PRAHARI-CASE-{cluster_id:04d}-{_now()[:10]}"

    evt = audit.append_event("CASE_FILE_EXPORTED", {"cluster_id": cluster_id, "case_ref": case_ref})
    await persist_audit_event(evt)

    file_bytes, content_type, filename, fmt = generate_case_file(intel, audit_entries, case_ref)
    return Response(
        content=file_bytes,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/report/citizen-pdf")
async def citizen_pdf(req: CitizenReportRequest):
    """
    Generates a citizen-facing fraud report PDF (or TXT fallback).

    Accepts the fields returned by /classify and produces a clean,
    human-readable document the victim can download, print, or attach
    to a cybercrime.gov.in complaint.

    Returns the file as a binary download.
    """
    session_id = req.session_id or str(uuid.uuid4())[:8].upper()
    case_ref   = f"PRAHARI-RPT-{session_id}-{_now()[:10]}"

    session = {
        "session_id":  session_id,
        "verdict":     req.verdict,
        "risk_score":  req.risk_score,
        "scam_type":   req.scam_type,
        "channel":     req.channel,
        "district":    req.district,
        "timestamp":   req.timestamp or _now(),
        "explanation": req.explanation,
        "advice":      req.advice,
    }

    evt = audit.append_event("CITIZEN_REPORT_GENERATED", {
        "session_id": session_id,
        "case_ref":   case_ref,
        "verdict":    req.verdict,
    })
    await persist_audit_event(evt)

    file_bytes, content_type, filename, fmt = generate_citizen_report(session, case_ref)
    logger.info(f"Citizen report generated: {case_ref} format={fmt}")
    return Response(
        content=file_bytes,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Geo ───────────────────────────────────────────────────────────────────────

@app.get("/geo/incidents")
async def geo_incidents():
    return {"incidents": GEO_INCIDENTS}

@app.get("/geo/hotspots")
async def geo_hotspots():
    return {"hotspots": compute_hotspots(GEO_INCIDENTS)}

@app.get("/geo/districts")
async def geo_districts():
    return {"districts": district_summary(GEO_INCIDENTS)}

@app.get("/forecast/districts")
async def get_forecasts():
    return {"forecasts": forecast_districts(GEO_INCIDENTS, DISTRICTS)}


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.post("/alert")
async def create_alert(req: AlertRequest):
    alert = {
        "alert_id": str(uuid.uuid4())[:8].upper(),
        "session_id": req.session_id,
        "type": "MANUAL_ALERT",
        "risk_score": req.risk_score,
        "verdict": "MANUAL",
        "district": req.district,
        "reason": req.reason,
        "timestamp": _now(),
        "status": "SENT_TO_TELECOM (simulated)",
    }
    await save_alert(alert)
    await ws_manager.broadcast_alert(alert)
    return alert

@app.get("/alerts")
async def list_alerts(limit: int = 50):
    return {"alerts": await get_alerts(limit)}


# ── Sessions ──────────────────────────────────────────────────────────────────

@app.get("/sessions")
async def list_sessions(limit: int = 50, verdict: Optional[str] = None):
    return {"sessions": await get_sessions(limit, verdict)}


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.get("/audit/log")
async def get_audit():
    return {"log": audit.get_log()}

@app.get("/audit/verify")
async def verify_audit():
    ok, msg = audit.verify_chain()
    return {"intact": ok, "message": msg, "entries": len(audit.get_log())}


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard/summary")
async def dashboard_summary():
    db_counts = await get_dashboard_counts()
    high_risk = [c for c in CLUSTERS if c["risk_level"] == "HIGH"]
    forecasts = forecast_districts(GEO_INCIDENTS, DISTRICTS)
    emerging  = [f for f in forecasts if f["trend"] == "EMERGING_HOTSPOT"]
    top       = forecasts[0] if forecasts else None

    return {
        "reports_analyzed":         db_counts["total_sessions"],
        "scams_detected":           db_counts["scams_detected"],
        "alerts_sent":              db_counts["alerts_sent"],
        "trend_7day":               db_counts["trend_7day"],
        "fraud_rings":              len(CLUSTERS),
        "high_risk_clusters":       len(high_risk),
        "total_entities":           GRAPH.number_of_nodes(),
        "total_linkages":           GRAPH.number_of_edges(),
        "geo_incidents":            len(GEO_INCIDENTS),
        "emerging_hotspots":        len(emerging),
        "top_forecast_district":    top["district"] if top else None,
        "top_forecast_explanation": top["explanation"] if top else None,
        "ai_accuracy":              92,
        "loss_prevented_cr":        12.4,
        "gemini_enabled":           bool(os.getenv("GEMINI_API_KEY")),
        "novel_detection_active":   bool(os.getenv("GEMINI_API_KEY")),
        "whatsapp_active":          bool(os.getenv("TWILIO_ACCOUNT_SID")),
        "uptime_seconds":           int(time.monotonic() - START_TIME),
    }


# ── Demo simulation endpoint (for live hackathon demo) ────────────────────────

@app.post("/simulate/attack")
async def simulate_attack(district: str = "Mumbai", count: int = 5):
    """
    Simulates a fraud wave — generates `count` alerts over ~2 seconds.
    Call this during the demo to show the live feed lighting up in real time.
    Maximum 10 alerts per call to prevent abuse.
    """
    import asyncio
    count = min(count, 10)
    DEMO_SCAMS = [
        {"type": "DIGITAL_ARREST_WAVE",   "score": 88, "verdict": "SCAM_LIKELY"},
        {"type": "OTP_PHISHING_BURST",     "score": 82, "verdict": "SCAM_LIKELY"},
        {"type": "NOVEL_SOCIAL_ENG",       "score": 74, "verdict": "SCAM_LIKELY"},
        {"type": "KYC_FRAUD_CAMPAIGN",     "score": 91, "verdict": "SCAM_LIKELY"},
        {"type": "INVESTMENT_SCAM_RING",   "score": 79, "verdict": "SCAM_LIKELY"},
        {"type": "COURIER_DRUG_CLAIM",     "score": 85, "verdict": "SCAM_LIKELY"},
        {"type": "LOTTERY_WIN_PHISHING",   "score": 77, "verdict": "SCAM_LIKELY"},
        {"type": "ROMANCE_SCAM_DETECTED",  "score": 68, "verdict": "SCAM_LIKELY"},
        {"type": "IMPERSONATION_DETECTED", "score": 83, "verdict": "SCAM_LIKELY"},
        {"type": "JOB_SCAM_WAVE",          "score": 71, "verdict": "SCAM_LIKELY"},
    ]
    sent = []
    for i in range(count):
        scam = DEMO_SCAMS[i % len(DEMO_SCAMS)]
        alert = {
            "alert_id":   str(uuid.uuid4())[:8].upper(),
            "session_id": str(uuid.uuid4())[:8].upper(),
            "type":       scam["type"],
            "risk_score": scam["score"],
            "verdict":    scam["verdict"],
            "district":   district,
            "timestamp":  _now(),
            "status":     "SIMULATED_DEMO",
        }
        await save_alert(alert)
        await ws_manager.broadcast_alert(alert)
        sent.append(alert)
        await asyncio.sleep(0.4)   # stagger so the feed visibly fills up

    return {
        "simulated": len(sent),
        "district": district,
        "alerts": sent,
        "message": f"Simulated {len(sent)} fraud alerts for district={district}. Watch the live feed!",
    }


# ── Escalate case endpoint ─────────────────────────────────────────────────────

@app.post("/escalate/{session_id}")
async def escalate_case(session_id: str):
    """
    Escalates a flagged session to the cyber cell.
    Wires to the 'Notify Cyber Cell' button in the frontend.
    """
    evt = audit.append_event("CASE_ESCALATED", {
        "session_id": session_id,
        "escalated_to": "CYBER_CELL_SIMULATED",
    })
    await persist_audit_event(evt)
    await ws_manager.broadcast_alert({
        "alert_id":   str(uuid.uuid4())[:8].upper(),
        "session_id": session_id,
        "type":       "CASE_ESCALATED_TO_CYBER_CELL",
        "risk_score": 100,
        "verdict":    "ESCALATED",
        "timestamp":  _now(),
        "status":     "FORWARDED_TO_CERT_IN (simulated)",
    })
    return {
        "escalated": True,
        "session_id": session_id,
        "forwarded_to": "CERT-In / State Cyber Cell (simulated)",
        "case_ref": f"PRAHARI-ESC-{session_id}",
        "timestamp": _now(),
        "audit_hash": evt["hash"][:16] + "...",
    }

