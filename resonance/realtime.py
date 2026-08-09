from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

ConnectionTarget = tuple[str, WebSocket]


class ConnectionManager:
    """Own active receiver sockets and isolate slow or failed peers during fanout."""

    def __init__(self, *, send_timeout_seconds: float = 2.0) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()
        self._send_timeout_seconds = send_timeout_seconds

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            previous = self._connections.get(device_id)
            self._connections[device_id] = websocket
        if previous and previous is not websocket:
            await self._close(
                previous, code=4001, reason="A newer connection replaced this session"
            )

    async def disconnect(self, device_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            if self._connections.get(device_id) is websocket:
                self._connections.pop(device_id, None)

    async def disconnect_device(self, device_id: str) -> None:
        async with self._lock:
            websocket = self._connections.pop(device_id, None)
        if websocket:
            await self._close(websocket, code=4003, reason="Device access revoked")

    async def snapshot(self) -> list[ConnectionTarget]:
        async with self._lock:
            return list(self._connections.items())

    async def broadcast(
        self,
        payload: dict[str, Any],
        *,
        targets: list[ConnectionTarget] | None = None,
    ) -> list[str]:
        recipients = targets if targets is not None else await self.snapshot()
        results = await asyncio.gather(
            *(self._send(device_id, websocket, payload) for device_id, websocket in recipients)
        )
        delivered = [device_id for device_id, succeeded, _ in results if succeeded]
        stale = [
            (device_id, websocket) for device_id, succeeded, websocket in results if not succeeded
        ]
        await asyncio.gather(
            *(self._discard(device_id, websocket) for device_id, websocket in stale)
        )
        return delivered

    async def send(self, device_id: str, websocket: WebSocket, payload: dict[str, Any]) -> bool:
        _, succeeded, _ = await self._send(device_id, websocket, payload)
        if not succeeded:
            await self._discard(device_id, websocket)
        return succeeded

    async def _discard(self, device_id: str, websocket: WebSocket) -> None:
        await self.disconnect(device_id, websocket)
        await self._close(websocket, code=1011, reason="Receiver send timed out")

    async def _send(
        self, device_id: str, websocket: WebSocket, payload: dict[str, Any]
    ) -> tuple[str, bool, WebSocket]:
        try:
            await asyncio.wait_for(websocket.send_json(payload), timeout=self._send_timeout_seconds)
        except (TimeoutError, asyncio.TimeoutError, RuntimeError, OSError, WebSocketDisconnect):
            return device_id, False, websocket
        return device_id, True, websocket

    async def _close(self, websocket: WebSocket, *, code: int, reason: str) -> None:
        try:
            await asyncio.wait_for(
                websocket.close(code=code, reason=reason), timeout=self._send_timeout_seconds
            )
        except (TimeoutError, asyncio.TimeoutError, RuntimeError, OSError, WebSocketDisconnect):
            pass

    @property
    def count(self) -> int:
        return len(self._connections)

    @property
    def connected_ids(self) -> frozenset[str]:
        return frozenset(self._connections)
