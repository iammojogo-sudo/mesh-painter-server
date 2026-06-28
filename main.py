import os
import hashlib
import hmac
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

app = FastAPI(title="Mesh Painter API")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
HMAC_SECRET = os.environ.get("HMAC_SECRET", "")

if not HMAC_SECRET:
    HMAC_SECRET = hashlib.sha256(b"fallback-dev-only").hexdigest()

class VerifyRequest(BaseModel):
    supabase_token: str

class ExportRequest(BaseModel):
    capability: str
    mesh_info: dict = {}

def _sign_data(data: dict) -> str:
    raw = ",".join(f"{k}={v}" for k, v in sorted(data.items()))
    sig = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        raw.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return sig

async def _validate_supabase_token(token: str) -> dict:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return {"sub": "anonymous", "email": None}
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {token}",
            },
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Supabase token")
        return resp.json()

async def _is_paid_user(user_id: str) -> bool:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return False
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/paid_users",
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            },
            params={"user_id": f"eq.{user_id}", "select": "id"},
        )
        if resp.status_code == 200 and len(resp.json()) > 0:
            return True
        return False

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/verify")
async def verify(req: VerifyRequest):
    user = await _validate_supabase_token(req.supabase_token)
    user_id = user.get("sub", "anonymous")
    email = user.get("email", None)
    has_email = email is not None and email != ""
    paid = False
    if has_email and user_id != "anonymous":
        paid = await _is_paid_user(user_id)
    is_demo = not paid
    features = "paint"
    if paid:
        features = "paint,export"
    exp = int(time.time()) + 3600
    capability_data = {
        "user_id": user_id,
        "features": features,
        "exp": str(exp),
    }
    sig = _sign_data(capability_data)
    capability_token = f"{user_id}:{exp}:{features}:{sig}"
    return {"capability": capability_token, "expires_at": exp, "is_demo": is_demo}

@app.post("/api/export")
async def do_export(req: ExportRequest):
    parts = req.capability.split(":")
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="Malformed capability")
    user_id, exp_str, sig = parts
    exp = int(exp_str)
    if time.time() > exp:
        raise HTTPException(status_code=401, detail="Capability expired")
    expected_sig = _sign_data({
        "user_id": user_id,
        "features": "paint,export",
        "exp": exp_str,
    })
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=401, detail="Invalid capability signature")
    receipt = f"receipt:{user_id}:{int(time.time())}:{_sign_data({'receipt': user_id, 'ts': str(int(time.time()))})}"
    return {"receipt": receipt, "status": "approved"}
