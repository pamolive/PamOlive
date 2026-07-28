import argparse
import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def parse_limit(value):
    if value in ("", "none", "null", "unlimited"):
        return None
    return int(value)


def main():
    parser = argparse.ArgumentParser(description="Generate a signed PAM-olive license.")
    parser.add_argument(
        "--private-key",
        required=True,
        help="Path to the Mopacy Ed25519 private key.",
    )
    parser.add_argument("--customer", required=True)
    parser.add_argument("--edition", choices=("business", "enterprise"), required=True)
    parser.add_argument("--feature", action="append", default=[])
    parser.add_argument("--max-users", default="unlimited")
    parser.add_argument("--max-targets", default="unlimited")
    parser.add_argument("--max-nodes", default="1")
    parser.add_argument("--domain", default="")
    parser.add_argument("--installation-id", default="")
    parser.add_argument(
        "--expires-at",
        default="",
        help="ISO date/time, for example 2027-07-28T00:00:00Z.",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    payload = {
        "customer": args.customer,
        "edition": args.edition,
        "features": sorted(set(args.feature)),
        "max_users": parse_limit(args.max_users),
        "max_targets": parse_limit(args.max_targets),
        "max_nodes": parse_limit(args.max_nodes),
        "domain": args.domain,
        "installation_id": args.installation_id,
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": args.expires_at,
    }

    private_key = serialization.load_pem_private_key(
        Path(args.private_key).read_bytes(),
        password=None,
    )
    signature = (
        base64.urlsafe_b64encode(private_key.sign(canonical_payload(payload)))
        .decode()
        .rstrip("=")
    )
    document = {"payload": payload, "signature": signature}
    Path(args.output).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
