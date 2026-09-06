#!/usr/bin/env python3
"""SanitialX Linux endpoint agent.

Stdlib-only client supporting:
- enrollment and secure local token persistence
- periodic heartbeat
- Debian-family software inventory
- durable JSONL event spool with batched forwarding
- SSH/auth log collection
- warning/error systemd journal collection
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VERSION = "0.2.0"
DEFAULT_STATE_DIR = Path(os.getenv("SANITIALX_AGENT_STATE_DIR", "/var/lib/sanitialx-agent"))
DEFAULT_SERVER = os.getenv("SANITIALX_SERVER_URL", "http://127.0.0.1:8000/api/v1").rstrip("/")
AUTH_LOG_CANDIDATES = (Path("/var/log/auth.log"), Path("/var/log/secure"))

SSH_FAILED_RE = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_DISCONNECT_RE = re.compile(r"Disconnected from (?:invalid user )?(?P<user>\S+ )?(?P<ip>[0-9a-fA-F:.]+)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def primary_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def stable_agent_id(state_dir: Path) -> str:
    path = state_dir / "agent-id"
    if path.exists():
        return path.read_text().strip()
    machine_id = Path("/etc/machine-id")
    seed = machine_id.read_text().strip() if machine_id.exists() else f"{socket.gethostname()}-{uuid.uuid4()}"
    agent_id = f"linux-{uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:24]}"
    secure_write(path, agent_id + "\n")
    return agent_id


def request_json(method: str, url: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: int = 15) -> dict[str, Any]:
    body = json.dumps(payload).encode() if payload is not None else None
    req_headers = {"Accept": "application/json"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    req_headers.update(headers or {})
    req = Request(url, data=body, headers=req_headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"connection failed: {exc.reason}") from exc


def cpu_percent(sample_seconds: float = 0.15) -> float:
    def read() -> tuple[int, int]:
        fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        values = [int(x) for x in fields]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle
    try:
        total1, idle1 = read()
        time.sleep(sample_seconds)
        total2, idle2 = read()
        delta = total2 - total1
        return round(100.0 * (1.0 - (idle2 - idle1) / delta), 2) if delta > 0 else 0.0
    except Exception:
        return 0.0


def memory_percent() -> float:
    try:
        data: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            data[key] = int(value.strip().split()[0])
        total = data.get("MemTotal", 0)
        available = data.get("MemAvailable", 0)
        return round(100.0 * (total - available) / total, 2) if total else 0.0
    except Exception:
        return 0.0


def collect_software(limit: int = 5000) -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    items = []
    for line in proc.stdout.splitlines()[:limit]:
        if "\t" not in line:
            continue
        package, version = line.split("\t", 1)
        items.append({
            "vendor": "debian",
            "product": package,
            "package_name": package,
            "version": version,
            "ecosystem": "deb",
            "source": "sanitialx-linux-agent",
        })
    return items


def _find_auth_log() -> Path | None:
    for path in AUTH_LOG_CANDIDATES:
        if path.exists() and path.is_file():
            return path
    return None


class Agent:
    def __init__(self, server: str, state_dir: Path) -> None:
        self.server = server.rstrip("/")
        self.state_dir = state_dir
        self.agent_id = stable_agent_id(state_dir)
        self.token_path = state_dir / "agent-token"
        self.spool_path = state_dir / "events.jsonl"
        self.auth_cursor_path = state_dir / "auth-log-cursor.json"
        self.journal_cursor_path = state_dir / "journal-since"

    def token(self) -> str:
        if not self.token_path.exists():
            raise RuntimeError("Agent is not enrolled. Run `enroll` first.")
        return self.token_path.read_text().strip()

    def agent_headers(self) -> dict[str, str]:
        return {"X-Agent-Token": self.token()}

    def enroll(self, enrollment_key: str) -> dict[str, Any]:
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "ip_address": primary_ip(),
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "agent_version": VERSION,
        }
        result = request_json("POST", f"{self.server}/agents/enroll", payload, {"X-Enrollment-Key": enrollment_key})
        secure_write(self.token_path, str(result["agent_token"]) + "\n")
        return result

    def heartbeat(self) -> dict[str, Any]:
        return request_json(
            "POST",
            f"{self.server}/agents/{self.agent_id}/heartbeat",
            {"cpu_usage": cpu_percent(), "memory_usage": memory_percent(), "agent_version": VERSION, "ip_address": primary_ip()},
            self.agent_headers(),
        )

    def inventory(self) -> dict[str, Any]:
        return request_json(
            "PUT",
            f"{self.server}/agents/{self.agent_id}/inventory/software",
            {"software": collect_software()},
            self.agent_headers(),
            timeout=60,
        )

    def queue_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        *,
        source_ip: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "timestamp": utc_now(),
            "severity": severity.upper(),
            "source_ip": source_ip,
            "destination_ip": primary_ip(),
            "message": message[:4000],
            "metadata": {"collector": "sanitialx-linux-agent", **(metadata or {})},
        }
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.spool_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    def _classify_auth_line(self, line: str) -> tuple[str, str, str | None, dict[str, Any]] | None:
        if "sshd[" not in line:
            return None
        match = SSH_FAILED_RE.search(line)
        if match:
            return "SSH_AUTH_FAILURE", "MEDIUM", match.group("ip"), {"user": match.group("user"), "auth_result": "failed"}
        match = SSH_ACCEPTED_RE.search(line)
        if match:
            return "SSH_AUTH_SUCCESS", "INFO", match.group("ip"), {"user": match.group("user"), "auth_method": match.group("method"), "auth_result": "accepted"}
        match = SSH_INVALID_RE.search(line)
        if match:
            return "SSH_INVALID_USER", "LOW", match.group("ip"), {"user": match.group("user"), "auth_result": "invalid_user"}
        match = SSH_DISCONNECT_RE.search(line)
        if match:
            return "SSH_DISCONNECT", "INFO", match.group("ip"), {"auth_result": "disconnect"}
        return None

    def collect_auth_events(self, max_lines: int = 2000) -> int:
        """Read only newly appended SSH auth lines, surviving normal log rotation."""
        path = _find_auth_log()
        if path is None:
            return 0
        stat = path.stat()
        cursor = {"inode": stat.st_ino, "offset": stat.st_size}
        if self.auth_cursor_path.exists():
            try:
                cursor = json.loads(self.auth_cursor_path.read_text())
            except (OSError, ValueError, TypeError):
                cursor = {"inode": stat.st_ino, "offset": stat.st_size}

        offset = int(cursor.get("offset", 0)) if int(cursor.get("inode", 0)) == stat.st_ino else 0
        if offset > stat.st_size:
            offset = 0

        queued = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for index, line in enumerate(handle):
                if index >= max_lines:
                    break
                classified = self._classify_auth_line(line)
                if classified is None:
                    continue
                event_type, severity, source_ip, metadata = classified
                self.queue_event(event_type, severity, line.strip(), source_ip=source_ip, metadata={"log_source": str(path), **metadata})
                queued += 1
            new_offset = handle.tell()
        secure_write(self.auth_cursor_path, json.dumps({"inode": stat.st_ino, "offset": new_offset}) + "\n")
        return queued

    def collect_system_events(self, max_lines: int = 200) -> int:
        """Collect new warning-or-higher journal messages without shell execution."""
        if not Path("/run/systemd/system").exists():
            return 0
        since = self.journal_cursor_path.read_text().strip() if self.journal_cursor_path.exists() else "now"
        now_epoch = str(int(time.time()))
        try:
            proc = subprocess.run(
                ["journalctl", "--no-pager", "--output=json", "--priority=0..4", f"--since=@{since}"],
                text=True,
                capture_output=True,
                check=True,
                timeout=15,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return 0

        queued = 0
        for line in proc.stdout.splitlines()[-max_lines:]:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            message = str(record.get("MESSAGE") or "").strip()
            if not message:
                continue
            priority = int(record.get("PRIORITY", 4))
            severity = "CRITICAL" if priority <= 2 else "HIGH" if priority == 3 else "MEDIUM"
            unit = record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER")
            self.queue_event(
                "LINUX_SYSTEM_ALERT",
                severity,
                message,
                metadata={"journal_priority": priority, "unit": unit, "log_source": "journald"},
            )
            queued += 1
        secure_write(self.journal_cursor_path, now_epoch + "\n")
        return queued

    def collect_events(self) -> int:
        return self.collect_auth_events() + self.collect_system_events()

    def flush_events(self, batch_size: int = 200) -> int:
        if not self.spool_path.exists():
            return 0
        lines = [line for line in self.spool_path.read_text().splitlines() if line.strip()]
        if not lines:
            return 0
        batch_lines = lines[: min(max(1, batch_size), 500)]
        events = [json.loads(line) for line in batch_lines]
        request_json("POST", f"{self.server}/agents/{self.agent_id}/events", {"events": events}, self.agent_headers(), timeout=30)
        remaining = lines[len(batch_lines):]
        secure_write(self.spool_path, ("\n".join(remaining) + "\n") if remaining else "")
        return len(events)

    def run(self, heartbeat_interval: int = 30, inventory_interval: int = 21600, collector_interval: int = 10) -> None:
        next_inventory = 0.0
        next_collect = 0.0
        retry_delay = 5
        while True:
            started = time.monotonic()
            try:
                if time.monotonic() >= next_collect:
                    self.collect_events()
                    next_collect = time.monotonic() + collector_interval
                self.flush_events()
                self.heartbeat()
                if time.monotonic() >= next_inventory:
                    self.inventory()
                    next_inventory = time.monotonic() + inventory_interval
                retry_delay = 5
            except Exception as exc:
                print(f"[{utc_now()}] agent cycle failed: {exc}", file=sys.stderr, flush=True)
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 300)
                continue
            elapsed = time.monotonic() - started
            time.sleep(max(1.0, heartbeat_interval - elapsed))


def main() -> int:
    parser = argparse.ArgumentParser(description="SanitialX Linux endpoint agent")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll")
    enroll.add_argument("--key", default=os.getenv("SANITIALX_ENROLLMENT_KEY"))
    sub.add_parser("heartbeat")
    sub.add_parser("inventory")
    sub.add_parser("collect")
    sub.add_parser("flush")
    sub.add_parser("run")
    event = sub.add_parser("event")
    event.add_argument("event_type")
    event.add_argument("message")
    event.add_argument("--severity", default="INFO", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    args = parser.parse_args()
    agent = Agent(args.server, Path(args.state_dir))
    try:
        if args.command == "enroll":
            if not args.key:
                raise RuntimeError("Enrollment key required via --key or SANITIALX_ENROLLMENT_KEY")
            print(json.dumps(agent.enroll(args.key), indent=2))
        elif args.command == "heartbeat":
            print(json.dumps(agent.heartbeat(), indent=2))
        elif args.command == "inventory":
            print(json.dumps(agent.inventory(), indent=2))
        elif args.command == "collect":
            print(json.dumps({"queued": agent.collect_events()}))
        elif args.command == "flush":
            print(json.dumps({"forwarded": agent.flush_events()}))
        elif args.command == "event":
            agent.queue_event(args.event_type, args.severity, args.message)
            print("queued")
        elif args.command == "run":
            agent.run()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"sanitialx-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
