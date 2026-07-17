from django.urls import path

from .consumers import TerminalConsumer

websocket_urlpatterns = [
    path("ws/sessions/<uuid:session_id>/terminal/", TerminalConsumer.as_asgi())
]
