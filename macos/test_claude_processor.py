#!/usr/bin/env python3
"""
Unit and Regression Tests for AirDrop P2P AI Processing Subsystem
"""

import os
import sys
import json
import time
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

# Ensure macos dir is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import claude_processor


class TestClaudeProcessor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sensitive_file_detection(self):
        """Ensure sensitive credentials and private keys are strictly blocked."""
        blocked_names = [
            "id_rsa", "id_rsa.pub", "id_ed25519", "server.key", "cert.pem",
            ".env", ".env.local", ".env.production", "database_secret.json",
            "aws_credentials.txt", "passwords.kdbx", "auth_token.jwt",
            "access_token.json", "private_key.p8", "vpn.ovpn"
        ]
        for name in blocked_names:
            p = self.dir_path / name
            p.write_text("dummy content", encoding="utf-8")
            is_sens, reason = claude_processor.is_sensitive_file(p)
            self.assertTrue(is_sens, f"Expected {name} to be marked sensitive; reason: {reason}")

    def test_sensitive_content_sniffing(self):
        """Files with benign names but containing private key headers must be blocked."""
        p = self.dir_path / "notes.txt"
        p.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...", encoding="utf-8")
        is_sens, reason = claude_processor.is_sensitive_file(p)
        self.assertTrue(is_sens, f"Expected notes.txt with private key header to be blocked: {reason}")

    def test_sensitive_api_token_sniffing(self):
        """Files containing raw API keys and cloud tokens must be blocked."""
        tokens = [
            "sk-ant-api03-abcdefghijklmnop1234567890",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_123456789012345678901234567890123456",
            "xoxb-1234567890-abcdefghij"
        ]
        for tok in tokens:
            p = self.dir_path / "config_sample.txt"
            p.write_text(f"API_SECRET = '{tok}'\n", encoding="utf-8")
            is_sens, reason = claude_processor.is_sensitive_file(p)
            self.assertTrue(is_sens, f"Expected token {tok} to be caught in {p.name}: {reason}")

    def test_benign_file_allowed(self):
        """Benign files must not be falsely flagged as sensitive."""
        allowed_names = [
            "report.pdf", "photo.png", "vacation.jpg", "main.swift",
            "MainActivity.kt", "README.md", "dataset.csv"
        ]
        for name in allowed_names:
            p = self.dir_path / name
            p.write_text("Hello world", encoding="utf-8")
            is_sens, reason = claude_processor.is_sensitive_file(p)
            self.assertFalse(is_sens, f"Expected {name} to be allowed; got {reason}")

    def test_large_text_head_tail_truncation(self):
        """Ensure large text retains both header context and conclusion footer."""
        p = self.dir_path / "huge_doc.txt"
        head_text = "HEAD_MARKER: Document Introduction and Schema\n"
        tail_text = "\nTAIL_MARKER: Final Conclusion and Signature\n"
        middle_text = "middle content " * 15000
        p.write_text(head_text + middle_text + tail_text, encoding="utf-8")

        with patch("claude_processor.call_claude_api") as mock_api:
            mock_api.return_value = "Summary"
            claude_processor.analyze_text_file(p, api_key="test-key")
            call_args = mock_api.call_args[0]
            messages = call_args[0]
            user_content = messages[0]["content"]

            self.assertIn("HEAD_MARKER", user_content)
            self.assertIn("TAIL_MARKER", user_content)
            self.assertIn("Truncated", user_content)

    def test_local_offline_analysis(self):
        """Test local structural analysis fallback when offline."""
        p = self.dir_path / "sample.py"
        p.write_text("class AirDropEngine:\n    def start(self):\n        pass\n", encoding="utf-8")

        summary = claude_processor.run_local_offline_analysis(p)
        self.assertIn("Local Analysis", summary)
        self.assertIn("AirDropEngine", summary)
        self.assertIn("Zero Cloud Exfiltration", summary)

    def test_ollama_local_fallback(self):
        """Test Ollama local LLM query when offline and available."""
        mock_tags = MagicMock()
        mock_tags.read.return_value = json.dumps({"models": [{"name": "llama3.2:latest"}]}).encode("utf-8")
        mock_tags.__enter__.return_value = mock_tags

        mock_gen = MagicMock()
        mock_gen.read.return_value = json.dumps({"response": "This is a local offline summary."}).encode("utf-8")
        mock_gen.__enter__.return_value = mock_gen

        with patch("urllib.request.urlopen", side_effect=[mock_tags, mock_gen]):
            res = claude_processor.query_ollama_local(prompt="Analyze file")
            self.assertIsNotNone(res)
            self.assertIn("Ollama", res)
            self.assertIn("local offline summary", res)

    def test_streaming_sse_parser(self):
        """Test Server-Sent Events (SSE) streaming token extraction."""
        sse_lines = [
            b'event: message_start\n',
            b'data: {"type": "message_start", "message": {}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hello "}}\n',
            b'\n',
            b'event: content_block_delta\n',
            b'data: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "World!"}}\n',
            b'\n',
            b'event: message_stop\n',
            b'data: [DONE]\n'
        ]

        mock_resp = MagicMock()
        mock_resp.__iter__.return_value = iter(sse_lines)
        mock_resp.__enter__.return_value = mock_resp

        received_tokens = []
        def on_token(tok):
            received_tokens.append(tok)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            full_text = claude_processor.call_claude_api(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="test",
                api_key="test-key",
                stream=True,
                on_chunk=on_token
            )
            self.assertEqual(full_text, "Hello World!")
            self.assertEqual(received_tokens, ["Hello ", "World!"])

    def test_process_dropped_file_privacy_notice(self):
        """When a sensitive file is dropped, write privacy notice sidecar without calling API."""
        p = self.dir_path / "id_rsa"
        p.write_text("dummy key", encoding="utf-8")

        with patch("claude_processor.is_claude_enabled", return_value=True), \
             patch("claude_processor.call_claude_api") as mock_api:
            sidecar = claude_processor.process_dropped_file(p, output_dir=self.dir_path)
            self.assertIsNotNone(sidecar)
            self.assertTrue(sidecar.exists())
            content = sidecar.read_text(encoding="utf-8")
            self.assertIn("Privacy Safeguard Notice", content)
            mock_api.assert_not_called()

    @patch("time.sleep", return_value=None)
    def test_api_retry_on_429_rate_limit(self, mock_sleep):
        """Verify exponential backoff on HTTP 429 and eventual success."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"content": [{"type": "text", "text": "Success after 429"}]}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        mock_fp = MagicMock()
        mock_fp.read.return_value = b'{"error": {"message": "rate_limit_exceeded"}}'
        http_429 = urllib.error.HTTPError(
            url="https://api.anthropic.com",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "1"},
            fp=mock_fp
        )

        with patch("urllib.request.urlopen", side_effect=[http_429, mock_resp]):
            res = claude_processor.call_claude_api(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="test",
                api_key="test-key"
            )
            self.assertEqual(res, "Success after 429")
            self.assertTrue(mock_sleep.called)

    @patch("time.sleep", return_value=None)
    def test_api_model_fallback_on_404_or_overloaded(self, mock_sleep):
        """Verify model fallback cascade when a model is not found or retired."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"content": [{"type": "text", "text": "Fallback Success"}]}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        mock_fp = MagicMock()
        mock_fp.read.return_value = b'{"error": {"type": "not_found_error", "message": "Model retired"}}'
        http_404 = urllib.error.HTTPError(
            url="https://api.anthropic.com",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=mock_fp
        )

        with patch("urllib.request.urlopen", side_effect=[http_404, mock_resp]):
            res = claude_processor.call_claude_api(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="test",
                model=claude_processor.FALLBACK_MODELS[0],
                api_key="test-key"
            )
            self.assertEqual(res, "Fallback Success")


if __name__ == "__main__":
    unittest.main()
