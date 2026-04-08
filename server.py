#!/usr/bin/env python3
"""
QRDrop — Local file transfer server via QR code.

Usage:
    python server.py
    python server.py --port 8080 --output ~/Desktop/Received --open-browser

Then open http://localhost:8080 in the PC browser.

Built-in security fixes:
  SEC-1  : Null byte + ValueError in safe_filename()
  SEC-2  : XSS — escHtml() in HTML templates
  SEC-3  : Per-session file isolation via subdirectory
  SEC-4  : python-multipart >= 0.0.22 (CVE-2024-53981, CVE-2026-24486)
  SEC-5  : MAX_SESSIONS limit to prevent memory DoS
  SEC-6  : Content-Length check before writing to disk (anti-TOCTOU)
  SEC-7  : WebSocket broadcast without silent except:pass
  SEC-8  : session_id via secrets.token_hex (48-bit entropy)
  SEC-9  : HTTP security headers (CSP, X-Content-Type-Options, X-Frame-Options)
  SEC-10 : TrustedHostMiddleware (Host Header Injection prevention)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import io
import logging
import mimetypes
import secrets
import shutil
import socket
import sys
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import qrcode
import uvicorn
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ─── Logging ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Base paths ───────────────────────────────────────────────
BASE_DIR      = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

# ─── Constants ────────────────────────────────────────────────
DEFAULT_PORT        = 8080
MAX_UPLOAD_BYTES    = 500 * 1024 * 1024   # 500 MB
MAX_SESSIONS        = 10                  # 🔒 SEC-5: memory DoS protection limit
SESSION_TIMEOUT     = 30 * 60             # 30 minutes of inactivity

# Active sessions: session_id → {"websockets", "files", "texts", "last_activity"}
sessions: dict[str, dict] = {}


async def _session_cleanup_loop() -> None:
    """Automatically expires inactive sessions every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        now = time.monotonic()
        expired = [
            sid for sid, data in list(sessions.items())
            if now - data.get("last_activity", now) > SESSION_TIMEOUT
        ]
        for sid in expired:
            logger.info("Session expired (30 min inactivity): %s", sid)
            await _broadcast(sid, {"type": "session_expired"})
            for ws in set(sessions.get(sid, {}).get("websockets", set())):
                with contextlib.suppress(Exception):
                    await ws.close()
            sessions.pop(sid, None)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    task = asyncio.create_task(_session_cleanup_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="QRDrop", lifespan=lifespan)

# ─── Security middlewares ─────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects HTTP security headers on all responses."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        # 🔒 SEC-9: Minimal security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["Referrer-Policy"]        = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' ws: wss:"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ─── Utilities ────────────────────────────────────────────────

def get_local_ip() -> str:
    """Detects the local IP address of the machine on the network (WiFi/LAN)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def generate_qr_base64(url: str) -> str:
    """Generates a PNG QR code for *url* and returns its base64 encoding."""
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def read_template(name: str) -> str:
    """Reads an HTML file from the templates/ directory."""
    path = TEMPLATES_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Template not found: {path}\n"
            f"Make sure the 'templates/' directory is in: {BASE_DIR}"
        )
    return path.read_text(encoding="utf-8")


def safe_filename(name: str | None, output_dir: Path) -> Path:
    """Sanitizes a filename against path traversal and null bytes.

    Args:
        name: Raw filename provided by the client.
        output_dir: Destination directory (already session-isolated).

    Returns:
        Safe absolute path under output_dir.

    Raises:
        ValueError: If the resolved path escapes output_dir.
    """
    # 🔒 SEC-1: Strip null bytes and control characters first
    cleaned = (name or "upload").replace("\x00", "").strip()
    raw = Path(cleaned).name  # Remove any path component (../, /etc/…)

    if not raw or raw in (".", ".."):
        raw = f"upload_{uuid.uuid4().hex[:8]}"

    try:
        dest = (output_dir / raw).resolve()
    except (ValueError, OSError):
        # 🔒 SEC-1: Unrecoverable filename (e.g. residual embedded null byte) → UUID fallback
        logger.warning("Unrecoverable filename, UUID fallback: %r", name)
        dest = output_dir / f"upload_{uuid.uuid4().hex[:8]}"

    # Anti path-traversal: resolved path must stay under output_dir
    if not str(dest).startswith(str(output_dir.resolve())):
        raise ValueError(f"Suspicious filename rejected: {name!r}")

    # Collision avoidance
    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        counter = 1
        while dest.exists():
            dest = output_dir / f"{stem}_{counter}{suffix}"
            counter += 1

    return dest


def _resolve_safe_path(session_id: str, filename: str) -> Path:
    """Resolves and validates a file path within the session subdirectory.

    Raises:
        HTTPException 404: Unknown session or missing file.
        HTTPException 400: Path traversal detected.
    """
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    output_dir: Path = app.state.output_dir / session_id
    safe_name = Path(filename.replace("\x00", "")).name  # SEC-1: null byte

    if not safe_name or safe_name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    try:
        dest = (output_dir / safe_name).resolve()
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="Invalid filename.") from exc

    if not str(dest).startswith(str(output_dir.resolve())):
        raise HTTPException(status_code=400, detail="Access denied.")

    if not dest.exists() or not dest.is_file():
        raise HTTPException(status_code=404, detail="File not found.")

    return dest


# ─── HTML routes ──────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def page_pc() -> HTMLResponse:
    try:
        return HTMLResponse(read_template("pc.html"))
    except FileNotFoundError as exc:
        logger.error("Missing template: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/mobile/{session_id}", response_class=HTMLResponse)
async def page_mobile(session_id: str) -> HTMLResponse:
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")
    try:
        return HTMLResponse(read_template("mobile.html"))
    except FileNotFoundError as exc:
        logger.error("Missing template: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ─── API — Session ────────────────────────────────────────────

@app.post("/api/session/new")
async def create_session() -> JSONResponse:
    """Creates a new session (capped at MAX_SESSIONS simultaneous sessions)."""
    # 🔒 SEC-5: Memory DoS protection limit
    if len(sessions) >= MAX_SESSIONS:
        raise HTTPException(
            status_code=429,
            detail=f"Limit of {MAX_SESSIONS} simultaneous sessions reached.",
        )

    # 🔒 SEC-8: Cryptographic entropy (48 bits) instead of truncated UUID (32 bits)
    session_id = secrets.token_hex(6)
    sessions[session_id] = {
        "websockets": set(),
        "files":      [],
        "texts":      [],
        "last_activity": time.monotonic(),
    }

    port: int = app.state.port
    ip        = get_local_ip()
    url       = f"http://{ip}:{port}/mobile/{session_id}"
    qr_b64    = generate_qr_base64(url)

    logger.info("New session: %s → %s", session_id, url)

    return JSONResponse({
        "session_id":      session_id,
        "url":             url,
        "qr_base64":       qr_b64,
        "timeout_seconds": SESSION_TIMEOUT,
    })


@app.delete("/api/session/{session_id}")
async def close_session(session_id: str) -> JSONResponse:
    """Gracefully closes a session and disconnects its WebSockets."""
    if session_id in sessions:
        for ws in set(sessions[session_id]["websockets"]):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        del sessions[session_id]
        logger.info("Session closed: %s (files kept in %s)", session_id, app.state.output_dir / session_id)
    return JSONResponse({"status": "closed"})


@app.post("/api/session/{session_id}/renew")
async def renew_session(session_id: str) -> JSONResponse:
    """Resets the session's last_activity timestamp to push back expiration."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")
    sessions[session_id]["last_activity"] = time.monotonic()
    return JSONResponse({"status": "renewed"})


# ─── API — Upload (Mobile → PC) ───────────────────────────────

@app.post("/api/upload/{session_id}")
async def upload_file(
    request: Request, session_id: str, file: UploadFile = File(...)
) -> JSONResponse:
    """Receives a file and saves it to the session subdirectory."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    # 🔒 SEC-6: Check Content-Length BEFORE writing to disk (anti-TOCTOU)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large (max {MAX_UPLOAD_BYTES // 1_048_576} MB).",
                )
        except ValueError:
            pass  # Unparseable Content-Length → let through, post-write check as fallback

    output_dir: Path = app.state.output_dir / session_id
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        dest = safe_filename(file.filename, output_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid filename.") from exc

    try:
        written = await asyncio.get_running_loop().run_in_executor(
            None, _write_file_sync, file.file, dest
        )
    except OSError as exc:
        logger.error("File write error: %s", exc)
        raise HTTPException(status_code=500, detail="Error while saving file.") from exc
    finally:
        await file.close()

    # Post-write check (safety net if Content-Length was absent)
    if written > MAX_UPLOAD_BYTES:
        dest.unlink(missing_ok=True)
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {MAX_UPLOAD_BYTES // 1_048_576} MB).",
        )

    logger.info("Received: %s (%.1f MB) → %s", file.filename, written / 1_048_576, dest)

    mime_type, _ = mimetypes.guess_type(dest.name)

    event: dict = {
        "type": "file_received",
        "name": dest.name,
        "size": written,
        "mime": mime_type or "application/octet-stream",
        "path": str(dest),
    }
    sessions[session_id]["files"].append(event)
    sessions[session_id]["last_activity"] = time.monotonic()
    await _broadcast(session_id, event)

    return JSONResponse({"status": "ok", "saved_as": dest.name})


def _write_file_sync(src_file: object, dest: Path) -> int:
    """Writes src_file to dest (sync, for run_in_executor). Returns bytes written."""
    with open(dest, "wb") as out:
        shutil.copyfileobj(src_file, out)  # type: ignore[arg-type]
    return dest.stat().st_size


# ─── API — Files (PC → Mobile) ───────────────────────────────

@app.get("/api/files/{session_id}")
async def list_files(session_id: str) -> JSONResponse:
    """Lists files available in the session output directory."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    output_dir: Path = app.state.output_dir / session_id
    if not output_dir.exists():
        return JSONResponse([])

    files: list[dict] = []
    for f in sorted(output_dir.iterdir()):
        if not f.is_file():
            continue
        mime, _ = mimetypes.guess_type(f.name)
        files.append({
            "name": f.name,
            "size": f.stat().st_size,
            "mime": mime or "application/octet-stream",
        })

    return JSONResponse(files)


@app.get("/api/download/{session_id}/{filename}")
async def download_file(session_id: str, filename: str) -> FileResponse:
    """Serves a file from the session subdirectory to the phone."""
    dest = _resolve_safe_path(session_id, filename)
    sessions[session_id]["last_activity"] = time.monotonic()
    mime, _ = mimetypes.guess_type(dest.name)
    logger.info("Download: %s → session %s", dest.name, session_id)
    return FileResponse(
        path=dest,
        filename=dest.name,
        media_type=mime or "application/octet-stream",
    )


# ─── API — Text (Mobile → PC) ────────────────────────────────

@app.post("/api/text/{session_id}")
async def share_text(session_id: str, request: Request) -> JSONResponse:
    """Receives a text from mobile and broadcasts it to the PC via WebSocket."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc

    content = body.get("content", "")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="Empty content.")
    if len(content) > 10_000:
        raise HTTPException(status_code=413, detail="Text too long (max 10,000 characters).")

    sessions[session_id]["texts"].append(content)
    sessions[session_id]["last_activity"] = time.monotonic()
    await _broadcast(session_id, {"type": "text_received", "content": content})

    logger.info("Text received (session %s): %d chars", session_id, len(content))
    return JSONResponse({"status": "ok"})


@app.get("/api/texts/{session_id}")
async def list_texts(session_id: str) -> JSONResponse:
    """Returns the text history for the session."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")
    return JSONResponse(sessions[session_id].get("texts", []))


# ─── API — Text (PC → Mobile) ────────────────────────────────

@app.post("/api/text-to-mobile/{session_id}")
async def share_text_to_mobile(session_id: str, request: Request) -> JSONResponse:
    """Receives a text from the PC and broadcasts it to mobile via WebSocket."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc

    content = body.get("content", "")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="Empty content.")
    if len(content) > 10_000:
        raise HTTPException(status_code=413, detail="Text too long (max 10,000 characters).")

    sessions[session_id]["last_activity"] = time.monotonic()
    await _broadcast(session_id, {"type": "text_to_mobile", "content": content})

    logger.info("Text PC→mobile (session %s): %d chars", session_id, len(content))
    return JSONResponse({"status": "ok"})


# ─── API — ZIP download (PC → Mobile) ────────────────────────

@app.get("/api/download-all/{session_id}")
async def download_all(session_id: str) -> StreamingResponse:
    """Builds a ZIP of all session files in a thread executor and streams it."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")

    output_dir: Path = app.state.output_dir / session_id
    if not output_dir.exists():
        raise HTTPException(status_code=404, detail="No files available.")

    files = [f for f in output_dir.iterdir() if f.is_file()]
    if not files:
        raise HTTPException(status_code=404, detail="No files available.")

    def _build_zip() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.write(f, arcname=f.name)
        return buf.getvalue()

    zip_bytes = await asyncio.get_running_loop().run_in_executor(None, _build_zip)
    sessions[session_id]["last_activity"] = time.monotonic()

    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="QRDrop_{session_id}.zip"'},
    )


# ─── API — File deletion ──────────────────────────────────────

@app.delete("/api/files/{session_id}/{filename}")
async def delete_file(session_id: str, filename: str) -> JSONResponse:
    """Deletes a file from the session directory and notifies clients via WebSocket."""
    dest = _resolve_safe_path(session_id, filename)
    safe_name = dest.name
    try:
        dest.unlink()
    except OSError as exc:
        logger.error("Delete error %s: %s", safe_name, exc)
        raise HTTPException(status_code=500, detail="Could not delete file.") from exc

    sessions[session_id]["files"] = [
        f for f in sessions[session_id]["files"] if f.get("name") != safe_name
    ]
    sessions[session_id]["last_activity"] = time.monotonic()
    await _broadcast(session_id, {"type": "file_deleted", "name": safe_name})

    logger.info("File deleted: %s (session %s)", safe_name, session_id)
    return JSONResponse({"status": "deleted"})


# ─── WebSocket ────────────────────────────────────────────────

async def _broadcast(session_id: str, event: dict) -> None:
    """Broadcasts an event to all WebSockets in the session.

    🔒 SEC-7: Dead sockets are removed without silencing errors.
    """
    if session_id not in sessions:
        return
    dead: set = set()
    for ws in set(sessions[session_id]["websockets"]):
        try:
            await ws.send_json(event)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Dead WebSocket removed: %s", exc)
            dead.add(ws)
    sessions[session_id]["websockets"] -= dead


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str) -> None:
    """Real-time notifications for PC and mobile."""
    if session_id not in sessions:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    sessions[session_id]["websockets"].add(websocket)
    logger.debug("WebSocket connected: session %s", session_id)

    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        logger.debug("WebSocket disconnected: session %s", session_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("WebSocket error (session %s): %s", session_id, exc)
    finally:
        sessions.get(session_id, {}).get("websockets", set()).discard(websocket)


# ─── Startup ──────────────────────────────────────────────────

def _check_templates() -> None:
    missing = [t for t in ("pc.html", "mobile.html") if not (TEMPLATES_DIR / t).exists()]
    if missing:
        for tpl in missing:
            logger.error("Missing template: %s", TEMPLATES_DIR / tpl)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QRDrop — File transfer via QR code")
    parser.add_argument("--port",         type=int,  default=DEFAULT_PORT)
    parser.add_argument("--output",       type=Path, default=Path.home() / "Downloads" / "QRDrop")
    parser.add_argument("--open-browser", action="store_true")
    return parser.parse_args()


def main() -> None:
    import threading
    import webbrowser

    args = parse_args()
    app.state.port       = args.port
    app.state.output_dir = args.output

    _check_templates()

    ip  = get_local_ip()
    url = f"http://localhost:{args.port}"

    # 🔒 SEC-10: Restrict accepted hosts (anti Host Header Injection)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", ip, f"{ip}:{args.port}"],
    )

    logger.info("══════════════════════════════════════════════════")
    logger.info("  QRDrop started!")
    logger.info("  Open on your PC  : %s", url)
    logger.info("  Local IP detected: %s", ip)
    logger.info("  Files saved to   : %s", args.output)
    logger.info("  Max upload size  : %d MB", MAX_UPLOAD_BYTES // 1_048_576)
    logger.info("  Max sessions     : %d", MAX_SESSIONS)
    logger.info("══════════════════════════════════════════════════")

    if args.open_browser:
        def _open() -> None:
            import time
            time.sleep(1.5)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
