#!/usr/bin/env python3
"""
Claude AI Ingestion & Analysis Engine for AirDrop P2P
---------------------------------------------------
Automatically analyzes, summarizes, and extracts structured intelligence
from files dropped to macOS via Wi-Fi Direct P2P:
- Images & Screenshots: Vision OCR, diagram explanation, receipt parsing, UI analysis.
- Documents & PDFs: Executive summaries, key takeaways, action items.
- Code & Bug Traces: Automated code review and bug explanation.
- Notes & Transcripts: Polished structuring and semantic tagging.

Zero external dependencies required (uses standard library urllib with optional anthropic SDK).
"""

import sys
import os
import json
import base64
import mimetypes
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
FAST_MODEL = "claude-3-5-haiku-20241022"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

CONFIG_DIR = Path.home() / ".airdrop-p2p"
CONFIG_FILE = CONFIG_DIR / "claude_config.json"


def get_api_key() -> Optional[str]:
    """Retrieve Anthropic API key from env or config file."""
    # 1. Environment variable
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if key:
        return key

    # 2. Local config file
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            key = cfg.get("api_key", "").strip()
            if key:
                return key
        except Exception:
            pass

    # 3. Simple text file
    key_file = CONFIG_DIR / "claude_key.txt"
    if key_file.exists():
        try:
            key = key_file.read_text().strip()
            if key:
                return key
        except Exception:
            pass

    return None


def is_claude_enabled() -> bool:
    """Check if Claude auto-processing is enabled."""
    if os.environ.get("CLAUDE_AI_ENABLED", "").lower() in ("0", "false", "no"):
        return False
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            return cfg.get("enabled", True)
        except Exception:
            pass
    return True


def call_claude_api(
    messages: list,
    system_prompt: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 2048,
    api_key: Optional[str] = None
) -> str:
    """Invoke Claude API via direct HTTPS with zero dependencies."""
    key = api_key or get_api_key()
    if not key:
        raise ValueError(
            "ANTHROPIC_API_KEY is not configured. Set ANTHROPIC_API_KEY environment variable "
            f"or write it to {CONFIG_FILE}."
        )

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": messages,
    }

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
            "user-agent": "AirDrop-P2P-Claude-Bridge/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_blocks = data.get("content", [])
            text_blocks = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
            return "\n\n".join(text_blocks).strip()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Claude API HTTP {e.code}: {err_body}")
    except Exception as e:
        raise RuntimeError(f"Claude API request failed: {e}")


def analyze_image_file(image_path: Path, api_key: Optional[str] = None) -> str:
    """Perform multimodal vision analysis and OCR on an image file."""
    mime_type, _ = mimetypes.guess_type(str(image_path))
    if not mime_type or not mime_type.startswith("image/"):
        ext = image_path.suffix.lower()
        mime_map = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".gif": "image/gif"
        }
        mime_type = mime_map.get(ext, "image/jpeg")

    img_data = image_path.read_bytes()
    b64_data = base64.b64encode(img_data).decode("ascii")

    system_prompt = (
        "You are an intelligent file intake assistant running locally on macOS. "
        "The user has AirDropped an image from their mobile device. "
        "Analyze this image thoroughly: "
        "1. If it contains text/documents/receipts: extract all visible text verbatim (OCR) and tabular data. "
        "2. If it is a UI screenshot: describe the layout, identify components, and note any error messages or key interactions. "
        "3. If it is a general photo: summarize what is depicted with salient details. "
        "Format output cleanly in GitHub Flavored Markdown with clear section headings."
    )

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": mime_type,
                        "data": b64_data
                    }
                },
                {
                    "type": "text",
                    "text": f"Please analyze this AirDropped image '{image_path.name}'."
                }
            ]
        }
    ]

    return call_claude_api(messages, system_prompt, model=DEFAULT_MODEL, max_tokens=2048, api_key=api_key)


def analyze_text_file(file_path: Path, api_key: Optional[str] = None) -> str:
    """Summarize and extract action items from text/document/code files."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError(f"Could not read text file: {e}")

    # Limit to first ~100k characters for prompt safety
    truncated = len(content) > 100_000
    sample = content[:100_000]

    system_prompt = (
        "You are an intelligent file intake assistant running locally on macOS. "
        "The user has AirDropped a document/code file from their mobile device. "
        "Provide: "
        "1. Executive Summary (2-3 concise sentences). "
        "2. Key Takeaways & Action Items. "
        "3. Topics / Semantic Tags (comma-separated for indexing). "
        "If it is code, highlight its function, language, and any notable bugs or patterns. "
        "Format output cleanly in GitHub Flavored Markdown."
    )

    user_text = f"File: {file_path.name}\n\n```\n{sample}\n```"
    if truncated:
        user_text += "\n\n*(Note: Input truncated to first 100,000 characters)*"

    messages = [{"role": "user", "content": user_text}]
    return call_claude_api(messages, system_prompt, model=DEFAULT_MODEL, max_tokens=2048, api_key=api_key)


def process_dropped_file(file_path: Path, output_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Main hook called when a file is received via AirDrop P2P.
    Produces a .claude.md sidecar summary alongside the downloaded file.
    """
    if not is_claude_enabled():
        return None

    api_key = get_api_key()
    if not api_key:
        # Silently skip if no API key is provided
        return None

    file_path = Path(file_path).resolve()
    if not file_path.exists():
        return None

    ext = file_path.suffix.lower()
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
    text_exts = {".txt", ".md", ".json", ".csv", ".py", ".kt", ".swift", ".js", ".ts", ".html", ".css", ".log", ".xml", ".yaml", ".yml"}

    print(f"[Claude-AI] Processing incoming file: {file_path.name}...")
    try:
        if ext in image_exts:
            result = analyze_image_file(file_path, api_key=api_key)
        elif ext in text_exts:
            result = analyze_text_file(file_path, api_key=api_key)
        else:
            # Unsupported binary format (e.g. video/archive)
            return None

        # Write markdown sidecar
        target_dir = output_dir or file_path.parent
        sidecar_path = target_dir / f"{file_path.name}.claude.md"
        header = f"# Claude AI Analysis: {file_path.name}\n*Generated by AirDrop P2P Intelligent Ingestion Engine*\n\n---\n\n"
        sidecar_path.write_text(header + result + "\n", encoding="utf-8")
        print(f"[Claude-AI] Analysis saved to {sidecar_path}")
        return sidecar_path
    except Exception as e:
        print(f"[Claude-AI] Warning: Processing failed for {file_path.name}: {e}")
        return None


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage:")
        print("  python3 claude_processor.py <file_path>       # Process and analyze a file")
        print("  python3 claude_processor.py --test            # Verify Anthropic API connection")
        print("  python3 claude_processor.py --set-key <KEY>   # Save Anthropic API key")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "--test":
        key = get_api_key()
        if not key:
            print("[-] No Anthropic API key found. Set ANTHROPIC_API_KEY or use --set-key.")
            sys.exit(1)
        print(f"[+] Verifying Claude API key (prefix: {key[:8]}...)...")
        try:
            resp = call_claude_api(
                messages=[{"role": "user", "content": "Respond with 'Claude API connection successful!' and current date."}],
                system_prompt="You are a connection test agent. Be brief.",
                model=FAST_MODEL,
                max_tokens=50,
                api_key=key
            )
            print(f"[+] Response from Claude:\n{resp}")
            print("\n[+] Verification SUCCESS: Claude API is fully operational.")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Verification FAILED: {e}")
            sys.exit(1)

    if cmd == "--set-key":
        if len(sys.argv) < 3:
            print("[-] Missing key argument.")
            sys.exit(1)
        new_key = sys.argv[2].strip()
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps({"api_key": new_key, "enabled": True}, indent=2))
        print(f"[+] Saved API key to {CONFIG_FILE}")
        sys.exit(0)

    target_file = Path(cmd)
    if not target_file.exists():
        print(f"[-] File not found: {target_file}")
        sys.exit(1)

    out = process_dropped_file(target_file)
    if out:
        print(f"[+] Result written to: {out}")
    else:
        print("[-] File skipped (unsupported type or Claude disabled).")


if __name__ == "__main__":
    main()

