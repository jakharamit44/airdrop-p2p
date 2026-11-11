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
        """Verify model fallback cascade uses current Anthropic 4.x IDs when a model returns 404."""
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

        attempted_models = []

        def fake_urlopen(req, timeout=90.0):
            body = json.loads(req.data.decode("utf-8"))
            attempted_models.append(body.get("model"))
            if len(attempted_models) == 1:
                raise http_404
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = claude_processor.call_claude_api(
                messages=[{"role": "user", "content": "hi"}],
                system_prompt="test",
                model=claude_processor.FALLBACK_MODELS[0],
                api_key="test-key"
            )
            self.assertEqual(res, "Fallback Success")
            self.assertEqual(attempted_models, ["claude-sonnet-4-6", "claude-haiku-4-5"])

    def test_default_model_ids_and_clean_imports(self):
        """Verify current Anthropic 4.x model defaults and absence of unused imports."""
        self.assertEqual(claude_processor.DEFAULT_MODEL, "claude-sonnet-4-6")
        self.assertEqual(claude_processor.FAST_MODEL, "claude-haiku-4-5")
        self.assertEqual(claude_processor.OPUS_MODEL, "claude-opus-4-6")
        self.assertEqual(
            claude_processor.FALLBACK_MODELS,
            ["claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6"],
        )
        src = (Path(__file__).resolve().parent / "claude_processor.py").read_text(encoding="utf-8")
        self.assertNotIn("claude-3-5-sonnet-latest", src)
        self.assertNotIn("claude-3-5-haiku-latest", src)
        self.assertNotIn("claude-3-opus-latest", src)
        self.assertNotIn("import mimetypes", src)

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

    def _extract_send_python_script(self) -> str:
        sh_path = Path(__file__).resolve().parent / "glidedrop.sh"
        sh_text = sh_path.read_text(encoding="utf-8")
        marker = 'STATE_DIR="$STATE_DIR" python3 - "$@" << \'PYEOF\' &\n'
        start_idx = sh_text.find(marker)
        self.assertNotEqual(start_idx, -1, "Could not locate send python block in glidedrop.sh")
        body_start = start_idx + len(marker)
        end_idx = sh_text.find("\nPYEOF\n", body_start)
        self.assertNotEqual(end_idx, -1, "Could not locate end of send python block")
        return sh_text[body_start:end_idx]

    def test_glidedrop_send_preserves_progress_on_ble_handoff(self):
        """Without --peer, failing discover_android() must preserve transfer_progress.json for BLE handoff."""
        send_script = self._extract_send_python_script()
        state_dir = self.dir_path / "state_handoff"
        state_dir.mkdir(exist_ok=True)
        prog_file = state_dir / "transfer_progress.json"
        initial_prog = {
            "active": True,
            "direction": "Sending",
            "fileName": "test.bin",
            "phase": "Connecting via Bluetooth LE…",
            "updatedAt": time.time(),
        }
        prog_file.write_text(json.dumps(initial_prog), encoding="utf-8")

        sample = self.dir_path / "sample.bin"
        sample.write_bytes(b"glidedrop-test-payload")

        # Force discover_android() to fail without touching any real 192.168.49.1 device
        harness = (
            "import socket as _orig_sock\n"
            "def _fail_conn(*a, **kw):\n"
            "    raise OSError('P2P unreachable in unit test')\n"
            "_orig_sock.create_connection = _fail_conn\n"
        ) + send_script

        env = {**os.environ, "GLIDEDROP_STATE_DIR": str(state_dir)}
        res = subprocess.run(
            [sys.executable, "-", str(sample)],
            input=harness,
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(
            prog_file.exists(),
            f"transfer_progress.json must NOT be deleted when handing off to BLE send (stderr={res.stderr})",
        )
        saved = json.loads(prog_file.read_text(encoding="utf-8"))
        self.assertTrue(saved.get("active"))

    def test_glidedrop_send_clears_progress_on_peer_fail_decline_cancel_success(self):
        """transfer_progress.json must be cleared when --peer fails, receiver declines (43), cancelled (44), or succeeds."""
        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            self.skipTest("openssl binary not available")

        send_script = self._extract_send_python_script()
        cert_path = self.dir_path / "srv_cert2.pem"
        key_path = self.dir_path / "srv_key2.pem"
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
        import base64
        pem_lines = [
            line.strip() for line in cert_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("-----")
        ]
        actual_fp = hashlib.sha256(base64.b64decode("".join(pem_lines))).hexdigest().lower()

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert_path), str(key_path))

        ask_status_code = {"code": 200}
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
                                headers = {}
                                while True:
                                    hl = f.readline().decode("iso-8859-1").strip()
                                    if not hl:
                                        break
                                    if ":" in hl:
                                        k, v = hl.split(":", 1)
                                        headers[k.strip().lower()] = v.strip()
                                if "chunked" in headers.get("transfer-encoding", "").lower():
                                    while True:
                                        raw_sz = f.readline()
                                        if not raw_sz:
                                            break
                                        sz_line = raw_sz.decode("iso-8859-1").strip()
                                        if not sz_line:
                                            continue
                                        sz = int(sz_line.split(";", 1)[0], 16)
                                        if sz == 0:
                                            f.readline()
                                            break
                                        f.read(sz)
                                        f.read(2)
                                else:
                                    clen = int(headers.get("content-length", "0"))
                                    if clen > 0:
                                        f.read(clen)
                                if "/Discover" in req_line:
                                    body = plistlib.dumps({"ReceiverComputerName": "LoopbackPeer"}, fmt=plistlib.FMT_BINARY)
                                    tls_conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
                                elif "/Ask" in req_line:
                                    code = ask_status_code["code"]
                                    reason = "Forbidden" if code == 403 else "OK"
                                    tls_conn.sendall(f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
                                    if code != 200:
                                        break
                                elif "/Upload" in req_line:
                                    tls_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                    break
                except Exception:
                    pass

        srv_thread = threading.Thread(target=serve_loop, daemon=True)
        srv_thread.start()

        state_dir = self.dir_path / "state_clear"
        state_dir.mkdir(exist_ok=True)
        prog_file = state_dir / "transfer_progress.json"
        env = {**os.environ, "GLIDEDROP_STATE_DIR": str(state_dir)}
        sample = self.dir_path / "upload_test.bin"
        sample.write_bytes(b"hello-glidedrop" * 100)

        def seed_progress():
            prog_file.write_text(json.dumps({"active": True, "updatedAt": time.time()}), encoding="utf-8")

        try:
            # 1. --peer failure (wrong pin) must clear progress
            seed_progress()
            wrong_fp = ("0" if actual_fp[0] != "0" else "1") + actual_fp[1:]
            res_peer_fail = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", wrong_fp, str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_peer_fail.returncode, 46, f"Expected exit 46 on pin mismatch, got {res_peer_fail.returncode}: {res_peer_fail.stderr}")
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on --peer pin failure")

            # 2. Receiver decline (403 -> rc 43) must clear progress
            ask_status_code["code"] = 403
            seed_progress()
            res_decline = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", actual_fp, str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_decline.returncode, 43)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on rc=43 decline")

            # 3. Cancelled transfer (cancel_transfer.flag -> rc 44) must clear progress
            ask_status_code["code"] = 200
            seed_progress()
            (state_dir / "cancel_transfer.flag").write_text(str(time.time()), encoding="utf-8")
            res_cancel = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", actual_fp, str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_cancel.returncode, 44)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on rc=44 cancel")
            (state_dir / "cancel_transfer.flag").unlink(missing_ok=True)

            # 4. Success (rc 0) must clear progress
            seed_progress()
            res_ok = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", actual_fp, str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on success")

            # 5. Leading --pin before --peer failure must clear progress
            seed_progress()
            res_pin_first = subprocess.run(
                [sys.executable, "-", "--pin", wrong_fp, "--peer", f"127.0.0.1:{port}", str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertNotEqual(res_pin_first.returncode, 0)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared when --pin precedes --peer")

            # 6. Invalid --pin syntax or missing file must clear progress and exit 45
            seed_progress()
            res_bad_pin = subprocess.run(
                [sys.executable, "-", "--peer", f"127.0.0.1:{port}", "--pin", "not-a-sha256", str(sample)],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_bad_pin.returncode, 45)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on invalid --pin")

            seed_progress()
            res_missing = subprocess.run(
                [sys.executable, "-", str(self.dir_path / "does_not_exist.bin")],
                input=send_script, text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(res_missing.returncode, 45)
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on missing input file")
        finally:
            stop_event.set()
            srv_sock.close()
            srv_thread.join(timeout=2)

    def test_glidedrop_phase1_daemon_invariants_and_swift_suite(self):
        """Verify Phase 1 & Phase 2 structural invariants and compile+run Swift daemon regression tests."""
        mac_dir = Path(__file__).resolve().parent
        swift_src = (mac_dir / "glidedrop-daemon.swift").read_text(encoding="utf-8")
        self.assertNotIn("retriedJoin", swift_src, "Synchronous retriedJoin must be removed")
        self.assertNotIn('Data("WP2P\\n".utf8)', swift_src, "Sender WP2P must be removed")
        self.assertNotIn('Data("WP2P".utf8)', swift_src, "Unpinned legacy WP2P downgrade must be removed")
        self.assertNotIn("BLE_E2EE_KEY", swift_src, "Hardcoded static BLE_E2EE_KEY must be eliminated")
        self.assertIn("deriveBleFrameKey", swift_src)
        self.assertIn("deriveSessionToken", swift_src)
        self.assertIn("registerP2pSessionToken", swift_src)
        self.assertIn("clearP2pSessionTokens", swift_src)
        self.assertIn("isValidSha256Fingerprint", swift_src)
        self.assertIn("BLEK", swift_src)
        self.assertIn("txProc.terminationStatus == 46", swift_src)
        self.assertIn("currentRawWifiSsid()", swift_src)
        self.assertIn("Date().addingTimeInterval(25.0)", swift_src, "25s DHCP wait must be present")
        self.assertIn("didFailToConnect", swift_src)
        self.assertIn("didDisconnectPeripheral", swift_src)
        self.assertIn("didModifyServices", swift_src)
        self.assertIn("TX_LOCK_TTL_SECONDS: TimeInterval = 180.0", swift_src)
        self.assertIn("MAX_ENCRYPTED_BLE_ARCHIVE_BYTES = 30_000_000", swift_src)
        self.assertIn("Waiting for receiver confirmation…", swift_src)

        swift_test_file = mac_dir / "test_glidedrop_daemon.swift"
        self.assertTrue(swift_test_file.exists(), "Missing macos/test_glidedrop_daemon.swift")
        xcrun_bin = shutil.which("xcrun")
        if not xcrun_bin:
            self.skipTest("xcrun not available")

        test_bin = self.dir_path / "glidedrop-swift-tests"
        compile_res = subprocess.run(
            [
                xcrun_bin, "swiftc", "-D", "GLIDEDROP_TESTING", "-parse-as-library",
                str(mac_dir / "glidedrop-daemon.swift"),
                str(swift_test_file),
                "-o", str(test_bin),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(compile_res.returncode, 0, f"Swift test compilation failed:\n{compile_res.stderr}")
        run_res = subprocess.run([str(test_bin)], capture_output=True, text=True, timeout=30)
        self.assertEqual(run_res.returncode, 0, f"Swift regression tests failed:\n{run_res.stdout}\n{run_res.stderr}")
        self.assertIn("All Swift regression checks PASSED", run_res.stdout)

    def test_glidedrop_sh_bash_send_dispatch(self):
        """Exercise glidedrop.sh bash send dispatch: BLE handoff vs --pin/--peer fail vs missing file."""
        mac_dir = Path(__file__).resolve().parent
        sh_src = (mac_dir / "glidedrop.sh").read_text(encoding="utf-8")

        state_dir = self.dir_path / "sh_state"
        state_dir.mkdir(exist_ok=True)
        ble_calls_log = self.dir_path / "ble_calls.log"
        stub_ble = self.dir_path / "stub_ble"
        stub_ble.write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$*" >> "{ble_calls_log}"\n'
            f'test -f "{state_dir}/transfer_progress.json" && echo "PROGRESS_PRESENT" >> "{ble_calls_log}" || echo "PROGRESS_MISSING" >> "{ble_calls_log}"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        stub_ble.chmod(0o755)

        test_sh = self.dir_path / "glidedrop_test.sh"
        patched_sh = sh_src.replace(
            'if [[ -x "/Applications/GlideDrop.app/Contents/MacOS/GlideDrop" ]]; then\n'
            '  BLE_BIN="/Applications/GlideDrop.app/Contents/MacOS/GlideDrop"\n'
            'elif [[ -x "$SCRIPT_DIR/GlideDrop.app/Contents/MacOS/GlideDrop" ]]; then\n'
            '  BLE_BIN="$SCRIPT_DIR/GlideDrop.app/Contents/MacOS/GlideDrop"\n'
            'else\n'
            '  BLE_BIN="$STATE_DIR/glidedrop-daemon"\n'
            'fi',
            f'BLE_BIN="{stub_ble}"',
        ).replace(
            '        with socket.create_connection(("192.168.49.1", 8771), timeout=0.25):\n'
            '            return "192.168.49.1", 8771',
            '        raise OSError("unit test P2P unreachable")',
        )
        self.assertIn(f'BLE_BIN="{stub_ble}"', patched_sh)
        self.assertIn('unit test P2P unreachable', patched_sh)
        test_sh.write_text(patched_sh, encoding="utf-8")
        test_sh.chmod(0o755)

        sample = self.dir_path / "payload.bin"
        sample.write_bytes(b"hello-bash-send")
        prog_file = state_dir / "transfer_progress.json"
        env = {**os.environ, "GLIDEDROP_STATE_DIR": str(state_dir)}

        # 1. Without --peer: preserves transfer_progress.json across Python exit -> invokes stub_ble send
        prog_file.write_text(json.dumps({"active": True, "updatedAt": time.time()}), encoding="utf-8")
        r1 = subprocess.run(["bash", str(test_sh), "send", str(sample)], capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        calls1 = ble_calls_log.read_text(encoding="utf-8")
        self.assertIn(f"send {sample}", calls1)
        self.assertIn("PROGRESS_PRESENT", calls1, "transfer_progress.json must remain present when BLE handoff starts")

        # 2. Leading --pin before --peer failure: must NOT fall back to BLE and must clear progress
        ble_calls_log.unlink()
        prog_file.write_text(json.dumps({"active": True, "updatedAt": time.time()}), encoding="utf-8")
        r2 = subprocess.run(
            ["bash", str(test_sh), "send", "--pin", "0" * 64, "--peer", "127.0.0.1:1", str(sample)],
            capture_output=True, text=True, env=env, timeout=15,
        )
        self.assertNotEqual(r2.returncode, 0)
        self.assertFalse(ble_calls_log.exists(), "--pin before --peer must not trigger BLE fallback")
        self.assertFalse(prog_file.exists(), f"transfer_progress.json must be cleared on --peer failure (stderr={r2.stderr})")

        # 3. Missing input file: must NOT invoke BLE fallback, must clear progress and exit 1
        prog_file.write_text(json.dumps({"active": True, "updatedAt": time.time()}), encoding="utf-8")
        r3 = subprocess.run(
            ["bash", str(test_sh), "send", str(self.dir_path / "missing_file.bin")],
            capture_output=True, text=True, env=env, timeout=10,
        )
        self.assertEqual(r3.returncode, 1, r3.stderr)
        self.assertFalse(ble_calls_log.exists(), "Missing file must not invoke BLE fallback")
        self.assertFalse(prog_file.exists(), f"transfer_progress.json must be cleared on missing file (stderr={r3.stderr})")

        # 4. TLS fingerprint mismatch (exit 46) even WITHOUT --peer must fail closed and NOT fall back to BLE
        tls_script_dir = self.dir_path / "tls_fail_test"
        tls_script_dir.mkdir(exist_ok=True)
        cert_pem = tls_script_dir / "cert.pem"
        key_pem = tls_script_dir / "key.pem"
        openssl_bin = shutil.which("openssl") or "/usr/bin/openssl"
        subprocess.run(
            [openssl_bin, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-keyout", str(key_pem), "-out", str(cert_pem), "-days", "1", "-nodes", "-subj", "/CN=test"],
            check=True, capture_output=True, text=True,
        )
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(4)
        srv_port = srv_sock.getsockname()[1]
        stop_ev = threading.Event()
        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(str(cert_pem), str(key_pem))

        def _tls_srv():
            srv_sock.settimeout(0.2)
            while not stop_ev.is_set():
                try:
                    c, _ = srv_sock.accept()
                    try:
                        with srv_ctx.wrap_socket(c, server_side=True) as tls:
                            tls.recv(1024)
                    except Exception:
                        pass
                except socket.timeout:
                    continue

        t = threading.Thread(target=_tls_srv, daemon=True)
        t.start()
        try:
            patched_p2p_sh = test_sh.read_text(encoding="utf-8").replace(
                '        raise OSError("unit test P2P unreachable")',
                f'        return "127.0.0.1", {srv_port}',
            )
            test_sh_tls = tls_script_dir / "glidedrop_tls_test.sh"
            test_sh_tls.write_text(patched_p2p_sh, encoding="utf-8")
            test_sh_tls.chmod(0o755)
            prog_file.write_text(json.dumps({"active": True, "updatedAt": time.time()}), encoding="utf-8")
            r4 = subprocess.run(
                ["bash", str(test_sh_tls), "send", "--pin", "f" * 64, str(sample)],
                capture_output=True, text=True, env=env, timeout=15,
            )
            self.assertEqual(r4.returncode, 46, f"Expected exit 46 on TLS mismatch without --peer, got {r4.returncode}: {r4.stderr}")
            self.assertFalse(ble_calls_log.exists(), "TLS pin failure (rc=46) must NOT trigger BLE fallback")
            self.assertFalse(prog_file.exists(), "transfer_progress.json must be cleared on rc=46")
        finally:
            stop_ev.set()
            srv_sock.close()
            t.join(timeout=2)

    def test_glidedrop_receiver_session_token_and_recent_uploads_cap(self):
        """Verify constant-time X-GlideDrop-Token validation on :8772, 127.0.0.1 Finder proxy bypass on :8773, and bounded RECENT_UPLOADS."""
        mac_dir = Path(__file__).resolve().parent
        sh_src = (mac_dir / "glidedrop.sh").read_text(encoding="utf-8")
        start_marker = 'nohup python3 -u - "$STATE_DIR/cert.pem" "$STATE_DIR/key.pem" "$PORT" "$PROXY_PORT" "$SCRIPT_DIR/glidedrop.sh" >"$LOG_FILE" 2>&1 << \'PYEOF\' &\n'
        end_marker = '\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)'
        self.assertIn(start_marker, sh_src)
        self.assertIn(end_marker, sh_src)

        py_part = sh_src.split(start_marker, 1)[1].split(end_marker, 1)[0]
        # Avoid spawning background worker threads during unit test import
        py_part = py_part.replace(
            "for _ in range(2):\n    threading.Thread(target=_claude_processor_worker, daemon=True).start()",
            "pass",
        )

        rx_state = self.dir_path / "rx_state"
        rx_state.mkdir(exist_ok=True)
        ns = {}
        old_argv = sys.argv
        try:
            sys.argv = [
                "glidedrop_rx_test",
                str(rx_state / "cert.pem"),
                str(rx_state / "key.pem"),
                "8772",
                "8773",
                str(mac_dir / "glidedrop.sh"),
            ]
            exec(compile(py_part, "glidedrop_rx_extract.py", "exec"), ns)
        finally:
            sys.argv = old_argv

        handle_client = ns["handle_client"]
        check_recent = ns["check_and_record_recent_upload"]
        recent_map = ns["RECENT_UPLOADS"]

        def run_discover(addr, is_p2p_proxy: bool, extra_headers: str = "") -> bytes:
            s_srv, s_cli = socket.socketpair()
            s_cli.settimeout(3.0)
            th = threading.Thread(target=handle_client, args=(s_srv, addr, is_p2p_proxy), daemon=True)
            th.start()
            try:
                body = plistlib.dumps({"DeviceSupportFlags": 111611}, fmt=plistlib.FMT_BINARY)
                req = (
                    f"POST /Discover HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:8772\r\n"
                    f"{extra_headers}"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii") + body
                s_cli.sendall(req)
                s_cli.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    d = s_cli.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
                return b"".join(chunks)
            finally:
                s_cli.close()
                th.join(timeout=3)

        token_file = rx_state / "p2p_session_token.json"
        valid_tok = "a1b2c3d4" * 8
        wrong_tok = "f" * 64
        now = time.time()

        # 1. Missing token file on :8772 -> 401 Unauthorized, no last_peer_ip / rx lock written
        resp1 = run_discover(("192.168.49.25", 50001), is_p2p_proxy=False)
        self.assertTrue(resp1.startswith(b"HTTP/1.1 401 Unauthorized"), resp1)
        self.assertFalse((rx_state / "last_peer_ip").exists())
        self.assertFalse((rx_state / "rx_in_progress.lock").exists())

        # 2. Expired token -> 401 Unauthorized
        token_file.write_text(json.dumps({
            "tokens": [{"token": valid_tok, "created_at": now - 400, "expires_at": now - 10}]
        }), encoding="utf-8")
        resp2 = run_discover(("192.168.49.25", 50002), is_p2p_proxy=False, extra_headers=f"X-GlideDrop-Token: {valid_tok}\r\n")
        self.assertTrue(resp2.startswith(b"HTTP/1.1 401 Unauthorized"), resp2)

        # 2b. Malformed non-dict p2p_session_token.json (e.g. JSON list) must fail closed with 401
        token_file.write_text("[]", encoding="utf-8")
        resp_malformed = run_discover(("192.168.49.25", 50008), is_p2p_proxy=False, extra_headers=f"X-GlideDrop-Token: {valid_tok}\r\n")
        self.assertTrue(resp_malformed.startswith(b"HTTP/1.1 401 Unauthorized"), resp_malformed)

        # 3. Wrong token when valid token is active -> 401 Unauthorized
        token_file.write_text(json.dumps({
            "tokens": [{"token": valid_tok, "created_at": now, "expires_at": now + 300}]
        }), encoding="utf-8")
        resp3 = run_discover(("192.168.49.25", 50003), is_p2p_proxy=False, extra_headers=f"X-GlideDrop-Token: {wrong_tok}\r\n")
        self.assertTrue(resp3.startswith(b"HTTP/1.1 401 Unauthorized"), resp3)

        # 4. Even loopback hitting :8772 directly without token -> 401 Unauthorized
        resp4 = run_discover(("127.0.0.1", 50004), is_p2p_proxy=False)
        self.assertTrue(resp4.startswith(b"HTTP/1.1 401 Unauthorized"), resp4)

        # 5. Valid X-GlideDrop-Token on :8772 -> 200 OK
        resp5 = run_discover(("192.168.49.25", 50005), is_p2p_proxy=False, extra_headers=f"X-GlideDrop-Token: {valid_tok}\r\n")
        self.assertTrue(resp5.startswith(b"HTTP/1.1 200 OK"), resp5)

        # 6. Finder awdl0 loopback proxy (:8773, is_p2p_proxy=True) works on 127.0.0.1 WITHOUT token
        resp6 = run_discover(("127.0.0.1", 50006), is_p2p_proxy=True)
        self.assertTrue(resp6.startswith(b"HTTP/1.1 200 OK"), resp6)

        # 7. Finder proxy (:8773) rejects non-loopback address with 403 Forbidden
        resp7 = run_discover(("192.168.1.42", 50007), is_p2p_proxy=True)
        self.assertTrue(resp7.startswith(b"HTTP/1.1 403 Forbidden"), resp7)

        # 8. RECENT_UPLOADS TTL pruning and max size cap (256)
        recent_map.clear()
        sig0 = (("a.txt", 10),)
        self.assertFalse(check_recent(sig0, now=1000.0))
        self.assertTrue(check_recent(sig0, now=1010.0), "Duplicate upload within 60s TTL must be detected")
        self.assertFalse(check_recent(sig0, now=1061.0), "Expired entry after 60s TTL must be pruned and accepted again")

        for i in range(300):
            check_recent(((f"f_{i}.bin", i),), now=2000.0 + (i * 0.01))
        self.assertLessEqual(len(recent_map), 256, "RECENT_UPLOADS must be bounded to <= 256 entries")


if __name__ == "__main__":
    unittest.main()
