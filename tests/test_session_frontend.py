from pathlib import Path

from django.conf import settings


def test_ssh_terminal_supports_copy_and_normal_close():
    terminal = (Path(settings.BASE_DIR) / "static/js/terminal.js").read_text()

    assert "copySelection" in terminal
    assert "terminalBufferText" in terminal
    assert "emulator.hasSelection()" in terminal
    assert "event.code === 1000" in terminal
    assert "window.close()" in terminal


def test_rdp_logout_extension_attempts_to_close_the_session_tab():
    extension = (
        Path(settings.BASE_DIR)
        / "deploy/guacamole-extension/session-lifecycle.js"
    ).read_text()
    dockerfile = (Path(settings.BASE_DIR) / "Dockerfile.guacamole").read_text()

    assert 'tokenKey = "GUAC_AUTH_TOKEN"' in extension
    assert "window.close()" in extension
    assert "pamolive-session-lifecycle.jar" in dockerfile
