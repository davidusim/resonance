import asyncio

from resonance.realtime import ConnectionManager


class CoordinatedSocket:
    def __init__(self, state: dict[str, object]) -> None:
        self.state = state

    async def send_json(self, payload: dict[str, object]) -> None:
        self.state["started"] = int(self.state["started"]) + 1
        if self.state["started"] == 2:
            self.state["event"].set()
        await self.state["event"].wait()
        self.state.setdefault("payloads", []).append(payload)

    async def close(self, *, code: int, reason: str) -> None:
        self.state.setdefault("closes", []).append((code, reason))


class HangingSocket:
    def __init__(self) -> None:
        self.never = asyncio.Event()
        self.closed = False

    async def send_json(self, payload: dict[str, object]) -> None:
        await self.never.wait()

    async def close(self, *, code: int, reason: str) -> None:
        self.closed = True


class FastSocket:
    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        self.payloads.append(payload)

    async def close(self, *, code: int, reason: str) -> None:
        return None


def test_broadcast_starts_receivers_concurrently() -> None:
    async def scenario() -> None:
        manager = ConnectionManager(send_timeout_seconds=0.2)
        state: dict[str, object] = {"started": 0, "event": asyncio.Event()}
        await manager.connect("one", CoordinatedSocket(state))  # type: ignore[arg-type]
        await manager.connect("two", CoordinatedSocket(state))  # type: ignore[arg-type]

        delivered = await manager.broadcast({"type": "test"})

        assert set(delivered) == {"one", "two"}
        assert len(state["payloads"]) == 2

    asyncio.run(scenario())


def test_slow_receiver_times_out_without_blocking_fast_receiver() -> None:
    async def scenario() -> None:
        manager = ConnectionManager(send_timeout_seconds=0.02)
        fast = FastSocket()
        slow = HangingSocket()
        await manager.connect("slow", slow)  # type: ignore[arg-type]
        await manager.connect("fast", fast)  # type: ignore[arg-type]

        delivered = await manager.broadcast({"type": "test"})

        assert delivered == ["fast"]
        assert fast.payloads == [{"type": "test"}]
        assert manager.connected_ids == {"fast"}
        assert slow.closed

    asyncio.run(scenario())
