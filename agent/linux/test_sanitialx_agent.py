from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
