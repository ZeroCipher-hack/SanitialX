"""Vendor-side license tool. Run on the vendor's machine only.

  python scripts/license_tool.py keygen --out keys/
  python scripts/license_tool.py sign --private-key keys/license_private.key \
      --customer "Example Bank" --plan pro --max-agents 200 --days 365 --out license.json

keygen writes license_private.key (keep secret, never ship) and license_public.key
(base64; set it as SENTINELX_LICENSE_PUBLIC_KEY on customer installations).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.license import canonical_bytes  # noqa: E402

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def keygen(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    priv_path = out / "license_private.key"
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(private).decode())
    (out / "license_public.key").write_text(base64.b64encode(key.public_key().public_bytes(**RAW)).decode())
    print(f"Wrote {priv_path} (SECRET) and {out / 'license_public.key'}")


def sign(args: argparse.Namespace) -> None:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(args.private_key).read_text().strip()))
    now = datetime.now(timezone.utc)
    payload = {
        "customer": args.customer,
        "plan": args.plan,
        "max_agents": args.max_agents,
        "features": args.feature,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=args.days)).isoformat(),
    }
    document = {"payload": payload, "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode()}
    Path(args.out).write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"Wrote {args.out} (expires {payload['expires_at']})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("--out", type=Path, required=True)
    sg = sub.add_parser("sign")
    sg.add_argument("--private-key", required=True)
    sg.add_argument("--customer", required=True)
    sg.add_argument("--plan", default="pro")
    sg.add_argument("--max-agents", type=int, required=True)
    sg.add_argument("--days", type=int, default=365)
    sg.add_argument("--feature", action="append", default=[])
    sg.add_argument("--out", required=True)
    args = parser.parse_args()
    keygen(args.out) if args.cmd == "keygen" else sign(args)


if __name__ == "__main__":
    main()
