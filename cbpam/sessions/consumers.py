from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.core.exceptions import PermissionDenied

from .services import close_session, consume_session_ticket


class TerminalConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]
        if not user.is_authenticated:
            await self.close(code=4401)
            return
        self.authorized_session = None
        await self.accept()
        await self.send_json({"type": "status", "state": "authorization_required"})

    async def receive_json(self, content, **kwargs):
        if self.authorized_session is not None:
            await self.send_json(
                {"type": "error", "message": "La passerelle de session n’est pas configurée."}
            )
            return
        if content.get("type") != "authorize" or not content.get("ticket"):
            await self.send_json({"type": "error", "message": "Ticket de session requis."})
            await self.close(code=4403)
            return

        client = self.scope.get("client")
        source_ip = client[0] if client else None
        try:
            session = await database_sync_to_async(consume_session_ticket)(
                session_id=self.scope["url_route"]["kwargs"]["session_id"],
                token=content["ticket"],
                user=self.scope["user"],
                source_ip=source_ip,
            )
        except PermissionDenied:
            await self.send_json({"type": "error", "message": "Autorisation de session refusée."})
            await self.close(code=4403)
            return

        self.authorized_session = session
        await self.send_json(
            {
                "type": "status",
                "state": "gateway_not_configured",
                "session_id": str(session.pk),
            }
        )
        await database_sync_to_async(close_session)(
            session,
            actor=self.scope["user"],
            reason="gateway_not_configured",
            failed=True,
        )
        await self.close(code=1013)
