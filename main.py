from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import jwt
from fastapi import FastAPI, HTTPException, Response, Request, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

TOTP_SECRET = os.environ.get("TOTP_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "filebox-change-me")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
FILES_DIR = DATA_DIR / "files"
DB_PATH = DATA_DIR / "filebox.db"
JWT_EXPIRY_DAYS = int(os.environ.get("JWT_EXPIRY_DAYS", "7"))
COOKIE_NAME = "fb_session"
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "500"))

FILES_DIR.mkdir(parents=True, exist_ok=True)

if not TOTP_SECRET:
    TOTP_SECRET = pyotp.random_base32()
    uri = pyotp.totp.TOTP(TOTP_SECRET).provisioning_uri("ganamia", issuer_name="FileBox")
    print(f"[FileBox] TOTP_SECRET={TOTP_SECRET}")
    print(f"[FileBox] Authenticator URI: {uri}")


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id       TEXT PRIMARY KEY,
                name     TEXT NOT NULL,
                size     INTEGER NOT NULL,
                mime     TEXT,
                ts       TEXT NOT NULL
            )
        """)


_init_db()

app = FastAPI(title="FileBox", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_token() -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRY_DAYS)
    return jwt.encode({"sub": "user", "exp": exp}, JWT_SECRET, algorithm="HS256")


def _check_auth(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False


def _require_auth(request: Request) -> None:
    if not _check_auth(request):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── auth ─────────────────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    code: str


@app.post("/auth/login")
async def login(body: LoginBody, response: Response):
    totp = pyotp.TOTP(TOTP_SECRET)
    if not totp.verify(body.code.strip(), valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid code")
    token = _make_token()
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True, secure=True, samesite="strict",
        max_age=JWT_EXPIRY_DAYS * 86400,
    )
    return {"ok": True}


@app.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, samesite="strict")
    return {"ok": True}


@app.get("/auth/check")
async def auth_check(request: Request):
    return {"ok": _check_auth(request)}


# ── files ─────────────────────────────────────────────────────────────────────

@app.get("/api/files")
async def list_files(request: Request):
    _require_auth(request)
    with _db() as conn:
        rows = conn.execute("SELECT * FROM files ORDER BY ts DESC").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/files")
async def upload(request: Request, file: UploadFile = File(...)):
    _require_auth(request)
    fid = str(uuid.uuid4())
    dest = FILES_DIR / fid
    size = 0
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_MB} MB limit")
            f.write(chunk)
    with _db() as conn:
        conn.execute(
            "INSERT INTO files (id,name,size,mime,ts) VALUES (?,?,?,?,?)",
            (fid, file.filename or fid, size, file.content_type,
             datetime.now(timezone.utc).isoformat()),
        )
    return {"id": fid, "name": file.filename, "size": size}


@app.get("/api/files/{fid}")
async def download(fid: str, request: Request):
    _require_auth(request)
    with _db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not row:
        raise HTTPException(404)
    path = FILES_DIR / fid
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(
        path,
        filename=row["name"],
        media_type=row["mime"] or "application/octet-stream",
    )


@app.delete("/api/files/{fid}")
async def delete(fid: str, request: Request):
    _require_auth(request)
    with _db() as conn:
        row = conn.execute("SELECT id FROM files WHERE id=?", (fid,)).fetchone()
    if not row:
        raise HTTPException(404)
    (FILES_DIR / fid).unlink(missing_ok=True)
    with _db() as conn:
        conn.execute("DELETE FROM files WHERE id=?", (fid,))
    return {"ok": True}


@app.get("/api/storage")
async def storage_info(request: Request):
    _require_auth(request)
    total = sum(f.stat().st_size for f in FILES_DIR.iterdir() if f.is_file())
    return {"used_bytes": total}


# ── SPA ──────────────────────────────────────────────────────────────────────

@app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
async def spa(full_path: str = ""):
    return FileResponse("static/index.html")
