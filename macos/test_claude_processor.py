#!/usr/bin/env python3
"""
Unit and Regression Tests for GlideDrop AI Processing Subsystem
"""

import hashlib
import io
import os
import plistlib
import shutil
import socket
import ssl
import subprocess
import sys
import json
import threading
import time
import unittest
import tempfile
from contextlib import redirect_stdout, redirect_stderr
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
        p.write_text("class GlideDropEngine:\n    def start(self):\n        pass\n", encoding="utf-8")

        summary = claude_processor.run_local_offline_analysis(p)
        self.assertIn("Local Analysis", summary)
        self.assertIn("GlideDropEngine", summary)
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

    def test_cli_test_mode_never_logs_api_key_or_prefix(self):
        """CLI --test must not print any portion or prefix of the API key in cleartext."""
        env_val = "sk-ant-api03-EnvMockValue1234567890"
        cfg_val = "sk-ant-cfg01-CfgMockValue0987654321"
        file_val = "sk-ant-file1-FileMockValue1122334455"

        missing_path = MagicMock(spec=Path)
        missing_path.exists.return_value = False

        cfg_mock = MagicMock(spec=Path)
        cfg_mock.exists.return_value = True
        cfg_mock.read_text.return_value = json.dumps({"api_key": cfg_val, "enabled": True})

        key_mock = MagicMock(spec=Path)
        key_mock.exists.return_value = True
        key_mock.read_text.return_value = file_val

        cases = [
            ({"ANTHROPIC_API_KEY": env_val}, missing_path, missing_path, env_val),
            ({"ANTHROPIC_API_KEY": ""}, cfg_mock, missing_path, cfg_val),
            ({"ANTHROPIC_API_KEY": ""}, missing_path, key_mock, file_val),
        ]

        for env_patch, cfg_target, key_target, expected_val in cases:
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.dict(os.environ, env_patch, clear=False), \
                 patch.object(claude_processor, "CONFIG_FILE", cfg_target), \
                 patch.object(claude_processor, "KEY_FILE", key_target), \
                 patch.object(sys, "argv", ["claude_processor.py", "--test"]), \
                 patch("claude_processor.call_claude_api", return_value="Claude API connection successful!"), \
                 redirect_stdout(out_buf), \
                 redirect_stderr(err_buf):
                with self.assertRaises(SystemExit) as cm:
                    claude_processor.main()
                self.assertEqual(cm.exception.code, 0)

            combined_output = out_buf.getvalue() + err_buf.getvalue()
            self.assertIn("Verifying configured Claude API key", combined_output)
            self.assertNotIn(expected_val, combined_output)
            self.assertNotIn(expected_val[:8], combined_output)
            self.assertNotIn("sk-ant-", combined_output)
            self.assertNotIn("prefix:", combined_output.lower())

    def test_cli_test_mode_missing_key_exits_nonzero(self):
        """CLI --test must fail cleanly with exit code 1 when no API key is configured."""
        missing_cfg = self.dir_path / "missing_config.json"
        missing_key = self.dir_path / "missing_key.txt"
        out_buf = io.StringIO()

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False), \
             patch.object(claude_processor, "CONFIG_FILE", missing_cfg), \
             patch.object(claude_processor, "KEY_FILE", missing_key), \
             patch.object(sys, "argv", ["claude_processor.py", "--test"]), \
             redirect_stdout(out_buf):
            with self.assertRaises(SystemExit) as cm:
                claude_processor.main()
            self.assertEqual(cm.exception.code, 1)

        self.assertIn("No Anthropic API key configured", out_buf.getvalue())

    def test_cli_test_mode_api_error_never_logs_api_key_or_prefix(self):
        """CLI --test failure path must exit 1 without leaking the configured key or prefix."""
        env_val = "sk-ant-api03-ErrMockValue9876543210"
        missing_path = MagicMock(spec=Path)
        missing_path.exists.return_value = False
        out_buf = io.StringIO()
        err_buf = io.StringIO()

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": env_val}, clear=False), \
             patch.object(claude_processor, "CONFIG_FILE", missing_path), \
             patch.object(claude_processor, "KEY_FILE", missing_path), \
             patch.object(sys, "argv", ["claude_processor.py", "--test"]), \
             patch("claude_processor.call_claude_api", side_effect=RuntimeError("HTTP 503 upstream failure")), \
             redirect_stdout(out_buf), \
             redirect_stderr(err_buf):
            with self.assertRaises(SystemExit) as cm:
                claude_processor.main()
            self.assertEqual(cm.exception.code, 1)

        combined_output = out_buf.getvalue() + err_buf.getvalue()
        self.assertIn("Verification FAILED", combined_output)
        self.assertNotIn(env_val, combined_output)
        self.assertNotIn(env_val[:8], combined_output)
        self.assertNotIn("sk-ant-", combined_output)
        self.assertNotIn("prefix:", combined_output.lower())

    def test_cli_set_key_saves_without_logging_key(self):
        """CLI --set-key must not echo the provided key or prefix to stdout/stderr."""
        entered_val = "sk-ant-api03-SetMockValue5566778899"
        dir_mock = MagicMock(spec=Path)
        cfg_mock = MagicMock(spec=Path)
        cfg_mock.exists.return_value = False
        out_buf = io.StringIO()
        err_buf = io.StringIO()

        with patch.object(claude_processor, "CONFIG_DIR", dir_mock), \
             patch.object(claude_processor, "CONFIG_FILE", cfg_mock), \
             patch.object(sys, "argv", ["claude_processor.py", "--set-key", entered_val]), \
             redirect_stdout(out_buf), \
             redirect_stderr(err_buf):
            with self.assertRaises(SystemExit) as cm:
                claude_processor.main()
            self.assertEqual(cm.exception.code, 0)

        cfg_mock.write_text.assert_called_once()
        combined_output = out_buf.getvalue() + err_buf.getvalue()
        self.assertIn("Saved API key securely", combined_output)
        self.assertNotIn(entered_val, combined_output)
        self.assertNotIn(entered_val[:8], combined_output)
        self.assertNotIn("sk-ant-", combined_output)

    def test_glidedrop_send_tls_pinning_enforced(self):
        """glidedrop.sh send client must enforce SHA-256 pinning and fail closed when unpinned."""
        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            self.skipTest("openssl binary not available")

        sh_path = Path(__file__).resolve().parent / "glidedrop.sh"
        sh_text = sh_path.read_text(encoding="utf-8")
        marker = 'STATE_DIR="$STATE_DIR" python3 - "$@" << \'PYEOF\' &\n'
        start_idx = sh_text.find(marker)
        self.assertNotEqual(start_idx, -1, "Could not locate send python block in glidedrop.sh")
        body_start = start_idx + len(marker)
        end_idx = sh_text.find("\nPYEOF\n", body_start)
        self.assertNotEqual(end_idx, -1, "Could not locate end of send python block")
        send_script = sh_text[body_start:end_idx]

        cert_path = self.dir_path / "srv_cert.pem"
        key_path = self.dir_path / "srv_key.pem"
        subprocess.run(
            [
                openssl_bin, "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "7", "-nodes", "-subj", "/CN=glidedrop-test"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Compute DER SHA-256 fingerprint of test server certificate
        pem_lines = [
            line.strip() for line in cert_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("-----")
        ]
        import base64
        cert_der = base64.b64decode("".join(pem_lines))
        actual_fp = hashlib.sha256(cert_der).hexdigest().lower()
        colon_fp = ":".join(actual_fp[i:i + 2] for i in range(0, 64, 2)).upper()
        wrong_fp = ("0" if actual_fp[0] != "0" else "1") + actual_fp[1:]

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert_path), str(key_path))

        http_requests = []
        stop_event = threading.Event()
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(8)
        srv_sock.settimeout(0.2)
        port = srv_sock.getsockname()[1]

        def serve_loop():
            while not stop_event.is_set():
                try:
                    raw_conn, _ = srv_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    with raw_conn:
                        raw_conn.settimeout(3.0)
                        with server_ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
                            f = tls_conn.makefile("rb")
                            while True:
                                req_line = f.readline().decode("iso-8859-1").strip()
                                if not req_line:
                                    break
                                http_requests.append(req_line)
                                headers = {}
                                while True:
                                    hl = f.readline().decode("iso-8859-1").strip()
                                    if not hl:
                                        break
                                    if ":" in hl:
                                        k, v = hl.split(":", 1)
                                        headers[k.strip().lower()] = v.strip()
                                clen = int(headers.get("content-length", "0"))
                                if clen > 0:
                                    f.read(clen)
                                if "/Discover" in req_line:
                                    body = plistlib.dumps({"ReceiverComputerName": "LoopbackTestPeer"}, fmt=plistlib.FMT_BINARY)
                                else:
                                    body = b""
                                resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii") + body
                                tls_conn.sendall(resp)
                                if "/Ask" in req_line:
                                    break
                except Exception:
                    pass

        srv_thread = threading.Thread(target=serve_loop, daemon=True)
        srv_thread.start()

        state_dir = self.dir_path / "state"
        state_dir.mkdir(exist_ok=True)
        env = {**os.environ, "GLIDEDROP_STATE_DIR": str(state_dir)}

        try:
            # 1. Valid pinned fingerprint (colon-delimited uppercase) must succeed
            res_ok = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", colon_fp, "https://example.com/ok"],
                input=send_script,
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(res_ok.returncode, 0, f"Expected pinned send to succeed: {res_ok.stderr}")
            self.assertEqual(len(http_requests), 2)

            # 2. Mismatched pin must abort before sending any HTTP request
            http_requests.clear()
            res_bad_pin = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", wrong_fp, "https://example.com/mitm"],
                input=send_script,
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertNotEqual(res_bad_pin.returncode, 0)
            self.assertEqual(http_requests, [], "Mismatched pin must abort before any HTTP request")

            # 3. Malformed pin must fail closed immediately
            res_malformed = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", "not-a-sha256", "https://example.com/bad"],
                input=send_script,
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertNotEqual(res_malformed.returncode, 0)
            self.assertEqual(http_requests, [])

            # 4. Unpinned self-signed cert must fail closed (no CERT_NONE bypass)
            res_unpinned = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "https://example.com/unpinned"],
                input=send_script,
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertNotEqual(res_unpinned.returncode, 0)
            self.assertEqual(http_requests, [], "Unpinned connection to self-signed cert must fail closed")
        finally:
            stop_event.set()
            srv_sock.close()
            srv_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
