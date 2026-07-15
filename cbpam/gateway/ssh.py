import asyncio
import base64
import json

import asyncssh

from .crypto import GatewayProtocolError


async def _send_json(send, payload):
    await send({"type": "websocket.send", "text": json.dumps(payload)})


async def _forward_output(reader, direction, send, recorder):
    while True:
        data = await reader.read(32768)
        if not data:
            return
        recorder.write(direction, data)
        await _send_json(
            send,
            {
                "type": "terminal.output",
                "stream": direction,
                "data": base64.b64encode(data).decode(),
            },
        )


async def _forward_input(receive, process, recorder):
    while True:
        message = await receive()
        if message["type"] == "websocket.disconnect":
            return "client_disconnect"
        if message["type"] != "websocket.receive" or not message.get("text"):
            continue
        try:
            payload = json.loads(message["text"])
        except json.JSONDecodeError:
            continue
        if payload.get("type") == "terminal.input":
            data = str(payload.get("data", "")).encode()[:65536]
            recorder.write("input", data)
            process.stdin.write(data)
        elif payload.get("type") == "terminal.resize":
            cols = min(max(int(payload.get("cols", 80)), 20), 400)
            rows = min(max(int(payload.get("rows", 24)), 5), 200)
            process.change_terminal_size(cols, rows)


async def bridge_ssh(
    envelope,
    receive,
    send,
    recorder,
    *,
    connect_timeout=10,
    cancellation=None,
):
    if envelope.get("protocol") != "ssh":
        raise GatewayProtocolError("Le broker SSH refuse ce protocole.")
    connect_options = {
        "host": envelope["host"],
        "port": int(envelope["port"]),
        "username": envelope["username"],
        "known_hosts": envelope["known_hosts"].encode(),
        "connect_timeout": connect_timeout,
        "login_timeout": connect_timeout,
        "keepalive_interval": 30,
        "keepalive_count_max": 3,
        "encoding": None,
        "client_keys": [],
    }
    if envelope.get("credential_kind") == "ssh_key":
        connect_options["client_keys"] = [asyncssh.import_private_key(envelope["secret"])]
    else:
        connect_options["password"] = envelope["secret"]

    async with asyncssh.connect(**connect_options) as connection:
        process = await connection.create_process(
            term_type="xterm-256color",
            term_size=(80, 24),
            encoding=None,
        )
        await _send_json(send, {"type": "status", "state": "connected"})
        input_task = asyncio.create_task(_forward_input(receive, process, recorder))
        stdout_task = asyncio.create_task(
            _forward_output(process.stdout, "stdout", send, recorder)
        )
        stderr_task = asyncio.create_task(
            _forward_output(process.stderr, "stderr", send, recorder)
        )
        wait_task = asyncio.create_task(process.wait())
        cancellation_task = asyncio.ensure_future(
            cancellation.wait() if cancellation else asyncio.Future()
        )
        done, _pending = await asyncio.wait(
            {input_task, wait_task, cancellation_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancellation_task in done:
            reason = "admin_terminated"
        elif wait_task in done:
            reason = "remote_exit"
        else:
            reason = input_task.result()
        if not wait_task.done():
            process.terminate()
            try:
                await asyncio.wait_for(wait_task, timeout=3)
            except TimeoutError:
                process.kill()
        input_task.cancel()
        cancellation_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        return reason
