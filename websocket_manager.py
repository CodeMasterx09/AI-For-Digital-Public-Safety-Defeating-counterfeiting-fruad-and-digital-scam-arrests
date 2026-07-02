"""
PRAHARI AI — WebSocket Live Alert Manager

Manages all active WebSocket connections and broadcasts real-time alerts
to every connected dashboard client.

Features:
  - Multiple simultaneous clients (broadcast to all)
  - Heartbeat ping every 25s to keep connections alive
  - Auto-cleanup of dead connections
  - Typed message protocol (alert, heartbeat, stats_update, incident)
  - Alert queue so late-connecting clients get the last N alerts

Usage in main.py:
    ws_manager = ConnectionManager()

    @app.websocket("/ws/alerts")
    async def alerts_ws(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()   # keep alive / handle pings
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from collections import deque
from typing import List

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("prahari.ws")

# Last N alerts buffered for late-joining clients
ALERT_BUFFER_SIZE = 50


def _now():
    return datetime.now(timezone.utc).isoformat()


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._alert_buffer: deque = deque(maxlen=ALERT_BUFFER_SIZE)
        self._heartbeat_task = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WS client connected — total: {len(self.active_connections)}")

        # Send buffered recent alerts to newly connected client
        if self._alert_buffer:
            await self._send_one(websocket, {
                "type": "history",
                "alerts": list(self._alert_buffer),
                "count": len(self._alert_buffer),
            })

        # Send current connection count to everyone
        await self.broadcast_stats()

        # Start heartbeat loop if not already running
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WS client disconnected — remaining: {len(self.active_connections)}")

    async def broadcast_alert(self, alert: dict):
        """Broadcast a new alert to all connected clients."""
        message = {
            "type": "alert",
            "timestamp": _now(),
            "data": alert,
        }
        self._alert_buffer.append(alert)
        await self._broadcast(message)

    async def broadcast_incident(self, incident: dict):
        """Broadcast a new geo incident (from a live classify call)."""
        message = {
            "type": "incident",
            "timestamp": _now(),
            "data": incident,
        }
        await self._broadcast(message)

    async def broadcast_stats(self):
        """Broadcast updated stats (KPI delta) to all clients."""
        message = {
            "type": "stats_update",
            "timestamp": _now(),
            "connected_clients": len(self.active_connections),
        }
        await self._broadcast(message)

    async def broadcast_dashboard_update(self, counts: dict):
        """Broadcast full dashboard KPI counts."""
        message = {
            "type": "dashboard_update",
            "timestamp": _now(),
            "data": counts,
        }
        await self._broadcast(message)

    async def _broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def _send_one(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_text(json.dumps(message))
        except Exception:
            self.disconnect(websocket)

    async def _heartbeat_loop(self):
        """Send a ping every 25 seconds to keep connections alive."""
        while self.active_connections:
            await asyncio.sleep(25)
            await self._broadcast({
                "type": "heartbeat",
                "timestamp": _now(),
                "connected": len(self.active_connections),
            })
        logger.info("Heartbeat loop exited (no active connections)")


# ── Singleton instance used across the app ───────────────────────────────────
ws_manager = ConnectionManager()
