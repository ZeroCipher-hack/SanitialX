from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sanitialx_agent
from sanitialx_agent import Agent


class LinuxAgentCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.agent = Agent("http://127.0.0.1:8000/api/v1", Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_failed_password_is_medium_auth_failure(self) -> None:
        result = self.agent._classify_auth_line(
            "Sep  6 11:00:01 host sshd[123]: Failed password for root from 203.0.113.10 port 55221 ssh2"
        )
        self.assertIsNotNone(result)
        event_type, severity, source_ip, metadata = result  # type: ignore[misc]
        self.assertEqual(event_type, "SSH_AUTH_FAILURE")
        self.assertEqual(severity, "MEDIUM")
        self.assertEqual(source_ip, "203.0.113.10")
        self.assertEqual(metadata["user"], "root")

    def test_bare_journald_failed_password_is_classified(self) -> None:
        result = self.agent._classify_auth_line(
            "Failed password for invalid user fakeuser from 127.0.0.1 port 44464 ssh2"
        )
        self.assertIsNotNone(result)
        event_type, severity, source_ip, metadata = result  # type: ignore[misc]
        self.assertEqual(event_type, "SSH_AUTH_FAILURE")
        self.assertEqual(severity, "MEDIUM")
        self.assertEqual(source_ip, "127.0.0.1")
        self.assertEqual(metadata["user"], "fakeuser")

    def test_invalid_user_is_low_security_event(self) -> None:
        result = self.agent._classify_auth_line(
            "Sep  6 11:00:02 host sshd[124]: Invalid user admin2 from 198.51.100.5 port 4411"
        )
        self.assertIsNotNone(result)
        event_type, severity, source_ip, metadata = result  # type: ignore[misc]
        self.assertEqual(event_type, "SSH_INVALID_USER")
        self.assertEqual(severity, "LOW")
        self.assertEqual(source_ip, "198.51.100.5")
        self.assertEqual(metadata["user"], "admin2")

    def test_successful_publickey_login_is_info(self) -> None:
        result = self.agent._classify_auth_line(
            "Sep  6 11:00:03 host sshd[125]: Accepted publickey for tolqin from 192.0.2.20 port 2222 ssh2"
        )
        self.assertIsNotNone(result)
        event_type, severity, source_ip, metadata = result  # type: ignore[misc]
        self.assertEqual(event_type, "SSH_AUTH_SUCCESS")
        self.assertEqual(severity, "INFO")
        self.assertEqual(source_ip, "192.0.2.20")
        self.assertEqual(metadata["auth_method"], "publickey")

    def test_non_sshd_line_is_ignored(self) -> None:
        self.assertIsNone(self.agent._classify_auth_line("kernel: ordinary system message"))

    @patch("sanitialx_agent.subprocess.run")
    def test_journald_fallback_initializes_cursor_without_backfill(self, run) -> None:
        run.return_value = SimpleNamespace(stdout="-- No entries --\n-- cursor: cursor-initial\n")
        with patch.object(sanitialx_agent, "_find_auth_log", return_value=None), patch.object(
            sanitialx_agent.Path, "exists", autospec=True
        ) as exists:
            def fake_exists(path: Path) -> bool:
                if path == Path("/run/systemd/system"):
                    return True
                return Path.__dict__["exists"](path)  # type: ignore[index]

            exists.side_effect = fake_exists
            queued = self.agent.collect_auth_events()

        self.assertEqual(queued, 0)
        self.assertEqual(self.agent.ssh_journal_cursor_path.read_text().strip(), "cursor-initial")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["journalctl", "-u", "ssh"])
        self.assertIn("-n", command)
        self.assertIn("0", command)

    @patch("sanitialx_agent.subprocess.run")
    def test_journald_fallback_queues_real_kali_ssh_failures(self, run) -> None:
        self.agent.ssh_journal_cursor_path.parent.mkdir(parents=True, exist_ok=True)
        self.agent.ssh_journal_cursor_path.write_text("cursor-old\n")
        records = [
            {"MESSAGE": "Invalid user fakeuser from 127.0.0.1 port 44464"},
            {"MESSAGE": "pam_unix(sshd:auth): authentication failure; rhost=127.0.0.1"},
            {"MESSAGE": "Failed password for invalid user fakeuser from 127.0.0.1 port 44464 ssh2"},
            {"MESSAGE": "Failed password for invalid user fakeuser from 127.0.0.1 port 44464 ssh2"},
            {"MESSAGE": "Failed password for invalid user fakeuser from 127.0.0.1 port 44464 ssh2"},
            {"MESSAGE": "Connection closed by invalid user fakeuser 127.0.0.1 port 44464 [preauth]"},
        ]
        stdout = "\n".join(json.dumps(record) for record in records)
        stdout += "\n-- cursor: cursor-new\n"
        run.return_value = SimpleNamespace(stdout=stdout)

        with patch.object(sanitialx_agent, "_find_auth_log", return_value=None), patch.object(
            sanitialx_agent.Path, "exists", autospec=True
        ) as exists:
            def fake_exists(path: Path) -> bool:
                if path == Path("/run/systemd/system"):
                    return True
                return Path.__dict__["exists"](path)  # type: ignore[index]

            exists.side_effect = fake_exists
            queued = self.agent.collect_auth_events()

        self.assertEqual(queued, 5)
        events = [json.loads(line) for line in self.agent.spool_path.read_text().splitlines() if line.strip()]
        self.assertEqual([event["event_type"] for event in events].count("SSH_AUTH_FAILURE"), 3)
        self.assertEqual([event["event_type"] for event in events].count("SSH_INVALID_USER"), 1)
        self.assertEqual([event["event_type"] for event in events].count("SSH_DISCONNECT"), 1)
        self.assertTrue(all(event["source_ip"] == "127.0.0.1" for event in events))
        self.assertTrue(all(event["metadata"]["log_source"] == "journald:ssh.service" for event in events))
        self.assertEqual(self.agent.ssh_journal_cursor_path.read_text().strip(), "cursor-new")
        command = run.call_args.args[0]
        self.assertIn("--after-cursor=cursor-old", command)
        self.assertIn("--output=json", command)


if __name__ == "__main__":
    unittest.main()
