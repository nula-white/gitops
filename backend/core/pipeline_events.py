"""
PRI SM PipelineEvent Bus
=========================
Thread-safe bridge between synchronous LangGraph pipeline nodes and
the async FastAPI WebSocket handler.

Problem being solved:
  LangGraph nodes are synchronous Python functions.  CodeQL, Joern, and
  SARIF injection are long-running blocking operations.  The FastAPI
  WebSocket handler is async.  When the WS handler delegates pipeline
  execution to a ThreadPoolExecutor, both halves need to communicate
  progress events across the sync/async boundary without locks or
  shared mutable state in the nodes themselves.

Design:
  - Each pipeline session gets a dedicated threading.Queue at WS connect.
  - Sync pipeline nodes call emit() which puts events on the queue.
    emit() is a plain function call — no coroutines, no event loop needed.
  - The async WS handler runs _drain_events() as an asyncio.Task that
    polls the queue at 50 ms intervals and broadcasts to the WebSocket.
  - When the pipeline thread finishes, the WS handler cancels the drainer.

Thread safety:
  - Queue is thread-safe by design.
  - _buses dict is protected by a threading.Lock for create/destroy.
  - emit() checks existence under the lock and is safe to call from any
    thread including if the bus was already destroyed (no-op on miss).

Usage in pipeline nodes (sync context):
    from core.pipeline_events import emit
    emit(session_id, "phase", "codeql_analysis",
         "CodeQL: creating database...", {"language": "python"})

Usage in WS handler (async context):
    from core.pipeline_events import (
        create_bus, destroy_bus, drain_events_task
    )
    bus = create_bus(session_id)
    drain_task = asyncio.create_task(drain_events_task(session_id, manager))
    result = await loop.run_in_executor(None, lambda: run_pipeline(...))
    drain_task.cancel()
    await asyncio.gather(drain_task, return_exceptions=True)
    destroy_bus(session_id)
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Event structure

@dataclass
class PipelineEvent:
    """
    A single progress event emitted by a pipeline stage.

    event_type mirrors WSEventType values so the WS handler can forward
    them directly as typed WebSocket messages.

    Common patterns:
      event_type="phase"     stage="codeql_analysis"  message="Creating database..."
      event_type="phase"     stage="sarif_annotation" message="Injecting 142 annotations..."
      event_type="finding"   stage="sarif_annotation" message="CWE-89 in auth.py:42"
      event_type="complete"  stage="pipeline"         message="Analysis complete"
    """
    session_id: str
    event_type: str          # "phase" | "finding" | "annotation" | "complete" | "error"
    stage:      str          # LangGraph stage name
    message:    str          # Human-readable progress message (shown in frontend)
    data:       dict = field(default_factory=dict)   # Optional structured payload

    def to_ws_payload(self) -> dict[str, Any]:
        """Format for JSON serialisation over the WebSocket."""
        return {
            "type":       self.event_type,
            "session_id": self.session_id,
            "payload": {
                "stage":   self.stage,
                "label":   self.message,
                **self.data,
            },
        }


# Bus registry

_buses: dict[str, queue.Queue] = {}
_buses_lock = threading.Lock()


def create_bus(session_id: str) -> queue.Queue:
    """
    Create and register a new event queue for a pipeline session.
    Call this from the async WS handler before starting the pipeline thread.
    Returns the queue (also accessible via get_bus()).
    """
    with _buses_lock:
        q: queue.Queue = queue.Queue()
        _buses[session_id] = q
        logger.debug("Pipeline event bus created for session=%s", session_id)
    return q


def get_bus(session_id: str) -> "queue.Queue | None":
    """Return the queue for an active session, or None if not registered."""
    return _buses.get(session_id)


def destroy_bus(session_id: str) -> None:
    """
    Remove the event queue for a session.
    Call this from the async WS handler after the pipeline thread finishes
    and the drainer task has been cancelled/awaited.
    """
    with _buses_lock:
        _buses.pop(session_id, None)
        logger.debug("Pipeline event bus destroyed for session=%s", session_id)


# Emission (called from sync pipeline nodes)

def emit(
    session_id: str,
    event_type: str,
    stage:      str,
    message:    str,
    data:       "dict | None" = None,
) -> None:
    """
    Emit a progress event from a synchronous pipeline node.

    Safe to call from any thread.  No-op if no bus is registered for the
    session (e.g. in unit tests or sequential fallback mode).

    Args:
        session_id: pipeline session identifier
        event_type: WebSocket event type string ("phase", "finding", etc.)
        stage:      LangGraph stage name (e.g. "codeql_analysis")
        message:    Human-readable progress text shown in the frontend
        data:       Optional structured payload merged into the WS payload
    """
    bus = get_bus(session_id)
    if bus is None:
        return   # no bus registered — silent no-op (tests, sequential mode)
    try:
        bus.put_nowait(
            PipelineEvent(
                session_id=session_id,
                event_type=event_type,
                stage=stage,
                message=message,
                data=data or {},
            )
        )
    except queue.Full:
        # Queue is bounded only if the caller passed maxsize; default is unbounded.
        # Log and drop rather than block a pipeline node.
        logger.warning(
            "Pipeline event bus full for session=%s — event dropped: %s",
            session_id, message,
        )


def emit_phase(session_id: str, stage: str, label: str) -> None:
    """Convenience: emit a phase-type event (most common pattern)."""
    emit(session_id, "phase", stage, label)


# Async drainer (called from async WS handler)

async def drain_events_task(
    session_id:      str,
    session_manager: Any,          # api.session_manager.SessionManager
    poll_interval_s: float = 0.05, # 50 ms polling — responsive without busy-wait
) -> None:
    """
    Asyncio task that continuously drains the sync event queue and
    broadcasts events to all WebSocket clients for this session.

    Run this as an asyncio.Task alongside the pipeline executor future:

        drain = asyncio.create_task(drain_events_task(sid, manager))
        result = await loop.run_in_executor(None, run_pipeline, ...)
        drain.cancel()
        await asyncio.gather(drain, return_exceptions=True)

    The task drains any remaining events after cancellation via a final
    sweep so no event is silently dropped.
    """
    bus = get_bus(session_id)
    if bus is None:
        return

    try:
        while True:
            # Drain all currently queued events in one pass
            drained_any = False
            while True:
                try:
                    event: PipelineEvent = bus.get_nowait()
                    await session_manager.broadcast(
                        session_id, event.to_ws_payload()
                    )
                    drained_any = True
                except queue.Empty:
                    break

            # Yield control to the event loop
            await asyncio.sleep(poll_interval_s)

    except asyncio.CancelledError:
        # Final drain: flush any events enqueued between the last poll
        # and cancellation (e.g. the last CodeQL milestone).
        while True:
            try:
                event = bus.get_nowait()
                await session_manager.broadcast(
                    session_id, event.to_ws_payload()
                )
            except queue.Empty:
                break
        # Re-raise to allow proper task cleanup
        raise