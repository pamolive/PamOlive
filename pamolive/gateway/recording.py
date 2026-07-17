import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .crypto import fernet_from_key


class EncryptedSessionRecorder:
    def __init__(self, *, directory, session_id, encryption_key):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.reference = f"{session_id}.pamrec"
        self.path = self.directory / self.reference
        self._file = self.path.open("xb")
        os.chmod(self.path, 0o600)
        self._cipher = fernet_from_key(encryption_key)
        self._digest = hashlib.sha256()
        self.bytes_in = 0
        self.bytes_out = 0

    def write(self, direction, data):
        if not data:
            return
        if direction == "input":
            self.bytes_in += len(data)
        else:
            self.bytes_out += len(data)
        payload = json.dumps(
            {
                "at": datetime.now(UTC).isoformat(),
                "direction": direction,
                "data": base64.b64encode(data).decode(),
            },
            separators=(",", ":"),
        ).encode()
        encrypted = self._cipher.encrypt(payload) + b"\n"
        self._file.write(encrypted)
        self._file.flush()
        self._digest.update(encrypted)

    def close(self):
        if not self._file.closed:
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
        return {
            "recording_reference": self.reference,
            "recording_sha256": self._digest.hexdigest(),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }
