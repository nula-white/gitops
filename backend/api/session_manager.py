"""
WebSocket session manager.
Maintains a registry of active sessions and their connected clients.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional
from fastapi import WebSocket

log = logging.getLogger(__name__)


class SessionManager:
    def __init__(self) -> None:
        # session_id → list of websockets
        self._connections: Dict[str, List[WebSocket]] = {}
        # session_id → phase label
        self._phases: Dict[str, str] = {}

    # Connection lifecycle

    async def connect(self, session_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(session_id, []).append(ws)
        log.info("WS connected  session=%s  total=%d", session_id, len(self._connections[session_id]))

    def disconnect(self, session_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(session_id, [])
        if ws in conns:
            conns.remove(ws)
        log.info("WS disconnected session=%s  remaining=%d", session_id, len(conns))

    def has_clients(self, session_id: str) -> bool:
        return bool(self._connections.get(session_id))

    # Broadcast

    async def broadcast(self, session_id: str, data: dict) -> None:
        dead: List[WebSocket] = []
        for ws in list(self._connections.get(session_id, [])):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)

    async def broadcast_all(self, data: dict) -> None:
        for sid in list(self._connections.keys()):
            await self.broadcast(sid, data)

    # Heartbeat

    async def heartbeat_loop(self, interval: int = 15) -> None:
        while True:
            await asyncio.sleep(interval)
            await self.broadcast_all({"type": "heartbeat"})


# Singleton
manager = SessionManager()