#!/usr/bin/env python3
"""Standalone transport regressions; never starts the app or changes networking.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s macos -p test_glidedrop_transport.py -v
"""
import ast
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import plistlib
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import zlib
from pathlib import Path
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("glidedrop.sh")


def python_blocks():
    text = SOURCE.read_text()
    return [part.split("\nPYEOF", 1)[0] for part in text.split("<< 'PYEOF' &\n")[1:]]


def namespace(block=0):
    tree = ast.parse(python_blocks()[block])
    # Load real functions/classes/constants, without daemon launch or system calls.
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            nodes.append(node)
        elif isinstance(node, ast.Assign):
            try:
                ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            nodes.append(node)
    if block == 1:
        nodes.extend(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in ("read_http_response", "require_http_success"))
    ns = dict(globals())
    ns.update(in_ask_or_upload=False, peer_name="Test peer", DEFAULT_MAC_NAME="Test Mac", write_progress=lambda *a, **k: None,
              RECENT_UPLOADS={}, RECENT_UPLOADS_LOCK=threading.Lock(), FORWARD_LOCK=threading.Lock(),
              CONSENT_LOCK=threading.Lock(), CLIENT_SLOTS=threading.BoundedSemaphore(8))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), ns)
    return ns


def entry(name, data=b"", mode=0o100644):
    nb = name.encode() + b"\0"
    return (f"070707{0:06o}{2:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}"
            f"{0:011o}{len(nb):06o}{len(data):011o}").encode() + nb + data


def archive(*files):
    return b"".join(entry(name, data) for name, data in files) + entry("TRAILER!!!", mode=0)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gdt-")
        self.root = Path(self.tmp.name)
        self.rx = namespace()
        self.tx = namespace(1)
        for ns in (self.rx, self.tx):
            ns["STATE_DIR"] = self.root

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, **changes):
        obj = dict(ssid="DIRECT-test", interface="en0", cidr="192.168.73.0/24",
                   gatewayIp="192.168.73.1", httpsPort=8771, updatedAt=time.time())
        obj.update(changes)
        (self.root / "active_p2p_session.json").write_text(json.dumps(obj))
        return obj

    def upload(self, data, headers=None, **kwargs):
        return self.rx["stream_upload_to_dir"](io.BytesIO(data), headers or {"content-length": str(len(data))},
                                                self.root / "out", fsync_files=False, **kwargs)

    def test_sender_rejects_non_200_upload(self):
        # Exercise the sender body with fake I/O, including its final success bookkeeping.
        code = python_blocks()[1]
        start = code.index("                st3, _ = read_http_response(f)")
        end = code.index("\n            else:\n", start)
        import textwrap
        segment = textwrap.dedent(code[start:end])
        for status in (400, 401, 403, 413, 500):
            with self.subTest(status=status):
                sent = Mock()
                ns = dict(self.tx, read_http_response=lambda f, s=status: (f"HTTP/1.1 {s} Error", b""),
                          f=None, t0=time.time(), files=[SOURCE], append_history=sent)
                with self.assertRaises((ValueError, RuntimeError, SystemExit)):
                    exec(segment, ns)
                sent.assert_not_called()

    def test_response_parser_bounds_and_complete_body(self):
        bad = [b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
               b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192 + b"\r\n\r\n",
               b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 65 + b"\r\n",
               b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"]
        for response in bad:
            with self.subTest(response=response[:80]), self.assertRaises((ValueError, EOFError)):
                self.tx["read_http_response"](io.BytesIO(response))
        self.assertEqual(self.tx["read_http_response"](io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")),
                         ("HTTP/1.1 200 OK", b"ok"))

    def test_lan_flag_linklocal_and_loopback_do_not_authorize(self):
        (self.root / "lan_fallback_active.flag").write_text(str(time.time()))
        for ip in ("192.168.1.2", "fe80::1234%en0", "127.0.0.1", "::1"):
            with self.subTest(ip=ip):
                self.assertFalse(self.rx["is_authorized_peer_ip"](ip))

    def test_only_confirmed_session_schema_is_accepted(self):
        self.session()
        self.assertIsNotNone(self.rx["load_active_p2p_session"]())
        for changes in (dict(ssid="Home"), dict(interface=""), dict(cidr="0.0.0.0/0"),
                        dict(gatewayIp="10.0.0.1"), dict(updatedAt=time.time() + 60)):
            with self.subTest(changes=changes):
                self.session(**changes)
                self.assertIsNone(self.rx["load_active_p2p_session"]())
                self.assertIsNone(self.tx["load_active_p2p_session"]())

    def test_outgoing_requires_literal_gateway_port_and_os_route(self):
        self.session()
        route = "route to: 192.168.73.1\n interface: en0\n"
        with patch.object(subprocess, "check_output", return_value=route):
            for ns in (self.rx, self.tx):
                validator = ns.get("validate_peer_route")
                self.assertIsNotNone(validator, "explicit peer targets need OS route validation")
                self.assertEqual(validator("192.168.73.1", 8771)["interface"], "en0")
                for host, port in (("192.168.1.2", 8771), ("peer.example", 8771), ("192.168.73.1", 443)):
                    with self.subTest(host=host, port=port), self.assertRaises((ValueError, RuntimeError)):
                        validator(host, port)
        with patch.object(subprocess, "check_output", return_value="interface: en1\n"):
            with self.assertRaises((ValueError, RuntimeError)):
                self.tx["validate_peer_route"]("192.168.73.1", 8771)

    def test_discovery_never_probes_an_unvalidated_route(self):
        self.session()
        with patch.object(subprocess, "check_output", return_value="interface: en1\n"), \
                patch.object(socket, "create_connection") as connect:
            with self.assertRaises((ValueError, RuntimeError)):
                self.tx["discover_android"]("ab" * 32)
            connect.assert_not_called()

    def test_archive_requires_trailer(self):
        for data in (b"", entry("one.txt", b"one")):
            with self.subTest(data=data[:10]), self.assertRaises((ValueError, EOFError)):
                self.upload(data)

    def test_archive_requires_complete_http_and_gzip_framing(self):
        data = archive(("one.txt", b"one"))
        variants = [(data, {"content-length": str(len(data) + 10)}),
                    (f"{len(data):x}\r\n".encode() + data + b"\r\n", {"transfer-encoding": "chunked"}),
                    (gzip.compress(data)[:-8], None)]
        for body, headers in variants:
            with self.subTest(headers=headers), self.assertRaises((ValueError, EOFError)):
                self.upload(body, headers)
        self.assertFalse(list((self.root / "out").glob("*.txt")), "invalid uploads must not publish files")

    def test_valid_raw_gzip_and_dvzip(self):
        for data in (archive(("raw.txt", b"a")), gzip.compress(archive(("gzip.txt", b"b"))),
                     struct.pack(">I", 0x80000000 | len(archive(("dvzip.txt", b"c")))) + archive(("dvzip.txt", b"c"))):
            saved, _ = self.upload(data)
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0].read_bytes(), {"raw.txt": b"a", "gzip.txt": b"b", "dvzip.txt": b"c"}[saved[0].name])

    def test_manifest_rejects_name_size_count_and_total_override(self):
        self.assertIn("approved_manifest", __import__("inspect").signature(self.rx["stream_upload_to_dir"]).parameters)
        for body in (archive(("evil.command", b"a")), archive(("safe.txt", b"ab")),
                     archive(("safe.txt", b"a"), ("extra.txt", b"b")), archive()):
            with self.subTest(body=body[:20]), self.assertRaises((ValueError, EOFError)):
                self.upload(body, expected_total=1, approved_manifest=[("safe.txt", 1)])
        good = archive(("safe.txt", b"a"))
        saved, _ = self.upload(good, expected_total=1, approved_manifest=[("safe.txt", 1)])
        self.assertEqual(saved[0].read_bytes(), b"a")

    def test_consent_cannot_be_reused_by_other_session(self):
        self.rx["load_settings"] = lambda: {"autoAccept": False}
        self.rx["_is_local_rx_cancelled"] = lambda: True
        (self.root / "wp2p_authorized_session.json").write_text(json.dumps({
            "senderName": "Alice", "authorizedAt": time.time(), "token": "ab" * 32,
            "peerIp": "192.168.73.1", "ssid": "DIRECT-test"}))
        with patch.object(threading, "Thread"):
            self.assertFalse(self.rx["wait_for_user_accept"]("Mallory", ["other.txt"], 1))

    def test_publication_never_clobbers_concurrent_file(self):
        dest = self.root / "race"
        payload = archive(("victim.txt", b"new"))
        class RaceStream:
            def __init__(self): self.f = io.BytesIO(payload)
            def read_exact(self, n): return self.f.read(n)
            def read(self, n):
                (dest / "victim.txt").write_bytes(b"existing")
                return self.f.read(n)
        saved = self.rx["extract_cpio_stream"](RaceStream(), dest, fsync_files=False)
        self.assertEqual((dest / "victim.txt").read_bytes(), b"existing")
        self.assertEqual(saved[0].read_bytes(), b"new")
        self.assertNotEqual(saved[0].name, "victim.txt")

    def test_forwarding_failure_keeps_recoverable_files(self):
        staging = self.root / "staging"; staging.mkdir()
        file = staging / "note.txt"; file.write_text("recover me")
        self.rx.update(SCRIPT_PATH=str(SOURCE), safe_notify=lambda *a: None)
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            self.rx["forward_to_peer_worker"](staging, [file])
        self.assertTrue(file.exists())

    def test_tls_handshakes_are_dispatched_to_bounded_workers(self):
        # Actual accept loop with fake sockets; a queued idle client must not negotiate inline.
        accepted = Mock()
        listener = Mock()
        listener.accept.side_effect = [(accepted, ("192.168.73.1", 1)), OSError("stop")]
        context = Mock()
        self.rx.update(ctx=context, is_authorized_peer_ip=lambda ip: True,
                       validate_peer_route=lambda host, port: {"interface": "en0"})
        with patch.object(socket, "socket", return_value=listener), patch.object(threading, "Thread") as worker:
            listener.getsockname.return_value = ("::", 8772)
            self.rx["serve_port"](8772, False)
            context.wrap_socket.assert_not_called()
            self.assertTrue(worker.called)
            self.assertTrue(worker.return_value.start.called)

    def exchange(self, files, body, total=None, proxy=False):
        token = "ab" * 32
        (self.root / "p2p_session_token.json").write_text(json.dumps(dict(token=token, expires_at=time.time()+120)))
        self.rx.update(DOWNLOADS=self.root / "received", safe_notify=lambda *a: None,
                       enqueue_claude_processing=lambda *a: None, append_history=lambda *a: None,
                       wait_for_user_accept=lambda *a, **k: True, get_active_peers=lambda *a: [],
                       load_settings=lambda: {"autoAccept":False, "deviceName":"Test Mac"})
        approved = plistlib.dumps(dict(SenderComputerName="Sender", Files=files))
        def request(path, payload, extra=""):
            return (f"POST {path} HTTP/1.1\r\nX-GlideDrop-Token: {token}\r\n"
                    f"Content-Length: {len(payload)}\r\n{extra}\r\n").encode() + payload
        server, client = socket.socketpair(); client.settimeout(2)
        thread = threading.Thread(target=self.rx["handle_client"], args=(server, ("127.0.0.1" if proxy else "192.168.73.1", 1234), proxy), daemon=True)
        thread.start()
        try:
            client.sendall(request("/Ask", approved))
            f = client.makefile("rb")
            def response():
                status = f.readline().split()[1]
                headers = {}
                while True:
                    line = f.readline()
                    if line == b"\r\n": break
                    if not line: raise EOFError("Missing response headers")
                    key, value = line.split(b":", 1); headers[key.lower()] = value.strip()
                f.read(int(headers[b"content-length"]))
                return int(status)
            self.assertEqual(response(), 200)
            extra = f"TotalBytes: {total}\r\n" if total is not None else ""
            client.sendall(request("/Upload", body, extra))
            status = response()
            f.close()
            return status
        finally:
            client.close(); thread.join(2)

    def test_http_upload_enforces_approved_manifest_and_total(self):
        metadata = [dict(FileName="safe.txt", FileSize=1)]
        self.assertEqual(self.exchange(metadata, archive(("safe.txt", b"a")), total=1000000000), 400)
        self.assertEqual(self.exchange(metadata, archive(("evil.command", b"a")), total=1), 400)
        self.assertFalse((self.root / "received" / "evil.command").exists())
        self.assertEqual(self.exchange(metadata, archive(("safe.txt", b"a")), total=1), 200)
        self.assertEqual((self.root / "received" / "safe.txt").read_bytes(), b"a")

    def test_finder_does_not_acknowledge_failed_downstream_delivery(self):
        self.rx["forward_to_peer_worker"] = Mock(return_value=False)
        status = self.exchange([dict(FileName="safe.txt", FileSize=1)], archive(("safe.txt", b"a")), total=1, proxy=True)
        self.assertEqual(status, 502)
        self.assertTrue(list((self.root / "finder_recovery").glob("*/safe.txt")))

    def test_finder_same_name_same_size_revisions_are_both_forwarded(self):
        delivered = []
        def forward(directory, files):
            delivered.append(files[0].read_bytes())
            return True
        self.rx["forward_to_peer_worker"] = forward
        for data in (b"abc", b"xyz"):
            self.assertEqual(self.exchange([dict(FileName="note.txt", FileSize=3)],
                             archive(("note.txt", data)), total=3, proxy=True), 200)
        self.assertEqual(delivered, [b"abc", b"xyz"])

    def test_tls_worker_releases_capacity_after_handshake_failure(self):
        raw = Mock()
        slots = Mock()
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLError("bad handshake")
        self.rx.update(ctx=context, CLIENT_SLOTS=slots)
        self.rx["serve_tls_client"](raw, "unix", True)
        raw.close.assert_called()
        slots.release.assert_called_once()

    def test_stored_dvzip_first_block_may_be_one_byte(self):
        data = archive(("split.txt", b"abc"))
        framed = struct.pack(">I", 0x80000001) + data[:1] + struct.pack(">I", 0x80000000 | (len(data) - 1)) + data[1:]
        saved, _ = self.upload(framed)
        self.assertEqual(saved[0].read_bytes(), b"abc")

    def test_compressed_dvzip_integrity_and_terminator(self):
        compressed = zlib.compress(archive(("compressed.txt", b"abc")))
        framed = struct.pack(">I", len(compressed)) + compressed + b"\0\0\0\0"
        saved, _ = self.upload(framed)
        self.assertEqual(saved[0].read_bytes(), b"abc")
        bad = struct.pack(">I", len(compressed) - 4) + compressed[:-4]
        with self.assertRaises((ValueError, EOFError)):
            self.upload(bad)

    def test_session_bound_consent_is_consumed_once(self):
        self.session()
        self.rx["load_settings"] = lambda: {"autoAccept": False}
        self.rx["_is_local_rx_cancelled"] = lambda: True
        auth = self.root / "wp2p_authorized_session.json"
        auth.write_text(json.dumps(dict(senderName="Alice", authorizedAt=time.time(), token="ab" * 32,
                                        peerIp="192.168.73.1", ssid="DIRECT-test")))
        self.assertTrue(self.rx["wait_for_user_accept"]("Alice", ["one.txt"], 1,
                        session_token="ab" * 32, peer_ip="192.168.73.1"))
        self.assertFalse(auth.exists())
        with patch.object(threading, "Thread"):
            self.assertFalse(self.rx["wait_for_user_accept"]("Alice", ["one.txt"], 1,
                             session_token="ab" * 32, peer_ip="192.168.73.1"))

    def test_session_bound_consent_tolerates_ble_placeholder_name_difference(self):
        self.session()
        self.rx["load_settings"] = lambda: {"autoAccept": False}
        self.rx["_is_local_rx_cancelled"] = lambda: True
        auth = self.root / "wp2p_authorized_session.json"
        auth.write_text(json.dumps(dict(senderName="Android Peer (40BB)", authorizedAt=time.time(), token="cd" * 32,
                                        peerIp="192.168.73.1", ssid="DIRECT-test")))
        # Wrong token or IP must still fail even when BLE placeholder differs
        with patch.object(threading, "Thread"):
            self.assertFalse(self.rx["wait_for_user_accept"]("Samsung SM-S911B", ["one.txt"], 1,
                             session_token="ef" * 32, peer_ip="192.168.73.1"))
            self.assertFalse(self.rx["wait_for_user_accept"]("Samsung SM-S911B", ["one.txt"], 1,
                             session_token="cd" * 32, peer_ip="192.168.73.99"))
        self.assertTrue(auth.exists())
        # Matching cryptographic token + IP + SSID reuses WP2P consent without a second popup
        self.assertTrue(self.rx["wait_for_user_accept"]("Samsung SM-S911B", ["one.txt"], 1,
                        session_token="cd" * 32, peer_ip="192.168.73.1"))
        self.assertFalse(auth.exists())

    def test_staging_collision_does_not_delete_another_writers_file(self):
        dest = self.root / "collision"; dest.mkdir()
        original_open = os.open
        other = dest / "one.txt.part"
        def collide(path, flags, mode=0o777, **kwargs):
            if str(path).endswith("one.txt.part"):
                other.write_bytes(b"other writer")
                raise FileExistsError(str(path))
            return original_open(path, flags, mode, **kwargs)
        payload = archive(("one.txt", b"abc"))
        stream = self.rx["StreamDecompressor"](self.rx["FixedLengthReader"](io.BytesIO(payload), len(payload)))
        with patch.object(os, "open", side_effect=collide):
            with self.assertRaises(FileExistsError):
                self.rx["extract_cpio_stream"](stream, dest, fsync_files=False)
        self.assertEqual(other.read_bytes(), b"other writer")

    def test_zero_copy_sender_multichunk_roundtrip(self):
        import textwrap
        src_dir = self.root / "tx_src"
        src_dir.mkdir()
        payload = bytes(((i * 31) ^ (i >> 7)) & 0xFF for i in range(1_250_000))
        big_file = src_dir / "large_clip.mp4"
        big_file.write_bytes(payload)

        code = python_blocks()[1]
        start = code.index("                tx_start = time.time()")
        end = code.index("                write_progress(True, \"Sending\", label, tot, tot", start)
        segment = textwrap.dedent(code[start:end])

        captured = bytearray()
        class FakeSocket:
            def sendall(self, data):
                captured.extend(memoryview(data))

        ns = dict(
            self.tx,
            s=FakeSocket(),
            raw=Mock(),
            files=[big_file],
            tot=len(payload),
            label=big_file.name,
            fcount=1,
            peer_name="Android Test",
            write_progress=lambda *a, **k: None,
            is_transfer_cancelled=lambda: False,
        )
        exec(segment, ns)
        saved, _ = self.upload(bytes(captured), {"transfer-encoding": "chunked"})
        self.assertEqual([p.name for p in saved], ["large_clip.mp4"])
        self.assertEqual(saved[0].read_bytes(), payload)


class RuntimeAssignedPortsTests(unittest.TestCase):
    """Task 3.4: no compiled-in ports; peer ports come from the handshake/session."""
    def test_script_has_no_fixed_port_literals(self):
        text = SOURCE.read_text()
        self.assertIsNone(re.search(r"\\b(8771|8772|8773|8774|1080|2080)\\b", text))

    def test_missing_session_port_is_zero_not_a_default(self):
        ns = namespace(0)
        with tempfile.TemporaryDirectory() as tmp:
            ns["STATE_DIR"] = Path(tmp)
            self.assertEqual(ns["get_active_p2p_https_port"](), 0)
            self.assertEqual(ns["active_p2p_endpoint"]("192.168.73.2"), "")
            (Path(tmp) / "active_p2p_session.json").write_text(json.dumps(dict(
                ssid="DIRECT-t", interface="en0", cidr="192.168.73.0/24",
                gatewayIp="192.168.73.1", httpsPort=40123, updatedAt=time.time())))
            self.assertEqual(ns["get_active_p2p_https_port"](), 40123)

if __name__ == "__main__":
    unittest.main()
