from typing import Dict, Set
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.user_sockets: Dict[int, Set[WebSocket]] = {}
        self.lot_sockets: Dict[int, Set[WebSocket]] = {}

    async def connect(self, ws: WebSocket, user_id: int):
        s = self.user_sockets.get(user_id)
        if not s:
            s = set()
            self.user_sockets[user_id] = s
        s.add(ws)

    async def disconnect(self, ws: WebSocket):
        for s in self.user_sockets.values():
            if ws in s:
                s.remove(ws)
        for s in self.lot_sockets.values():
            if ws in s:
                s.remove(ws)

    async def subscribe_lot(self, ws: WebSocket, lot_id: int | None):
        if lot_id is None:
            return
        s = self.lot_sockets.get(lot_id)
        if not s:
            s = set()
            self.lot_sockets[lot_id] = s
        s.add(ws)

    async def unsubscribe_lot(self, ws: WebSocket, lot_id: int | None):
        if lot_id is None:
            return
        s = self.lot_sockets.get(lot_id)
        if s and ws in s:
            s.remove(ws)

    async def send_to_user(self, user_id: int, message: dict):
        s = self.user_sockets.get(user_id)
        if not s:
            return
        for ws in list(s):
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(ws)

    async def broadcast_to_lot(self, lot_id: int, message: dict):
        s = self.lot_sockets.get(lot_id)
        if not s:
            return
        for ws in list(s):
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(ws)

    async def broadcast_all(self, message: dict):
        seen = set()
        for s in self.user_sockets.values():
            for ws in s:
                if ws in seen:
                    continue
                seen.add(ws)
                try:
                    await ws.send_json(message)
                except Exception:
                    await self.disconnect(ws)

manager = ConnectionManager()