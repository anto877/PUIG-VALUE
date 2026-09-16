
from __future__ import annotations

import csv
import io
import json
import math
import os
import sqlite3
import asyncio
import html
import secrets
import hashlib
import hmac
import time
import base64
from datetime import date, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("PUIG_DATA_DIR", BASE_DIR / "data"))
CACHE_DIR = DATA_DIR / "cache"
DB_PATH = DATA_DIR / "puig_value.sqlite3"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

GEOCODE_URL = "https://data.geopf.fr/geocodage/search"
DVF_BASE = "https://files.data.gouv.fr/geo-dvf/latest/csv"
DVF_CACHE_MAX_AGE_DAYS = int(os.getenv("DVF_CACHE_MAX_AGE_DAYS", "7"))
DVF_SYNC_INTERVAL_HOURS = int(os.getenv("DVF_SYNC_INTERVAL_HOURS", "24"))

app = FastAPI(title="PUIG VALUE WEB", version="2.8.0")

# ============================================================
# PUIG VALUE V2.4 - AUTHENTIFICATION PRIVEE
# Les identifiants sont définis exclusivement dans Render.
# ============================================================
PUIG_ADMIN_USER = os.getenv("PUIG_ADMIN_USER", "").strip()
PUIG_ADMIN_PASSWORD = os.getenv("PUIG_ADMIN_PASSWORD", "")
PUIG_SESSION_SECRET = os.getenv("PUIG_SESSION_SECRET", "").strip()
SESSION_COOKIE = "puig_value_session"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 heures

def auth_configured() -> bool:
    return bool(PUIG_ADMIN_USER and PUIG_ADMIN_PASSWORD and PUIG_SESSION_SECRET)

def ensure_users_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'expert',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.commit()

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt64, digest64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256": return False
        salt = base64.urlsafe_b64decode(salt64.encode())
        expected = base64.urlsafe_b64decode(digest64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def get_user_row(username: str):
    try:
        with get_db() as conn:
            ensure_users_table(conn)
            return conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE",(username,)).fetchone()
    except Exception:
        return None

def make_session_token(username: str, role: str, expires: int) -> str:
    msg=f"{username}|{role}|{expires}".encode()
    sig=hmac.new(PUIG_SESSION_SECRET.encode(),msg,hashlib.sha256).hexdigest()
    return f"{username}|{role}|{expires}|{sig}"

def session_identity(token: str | None):
    if not auth_configured() or not token: return None
    try:
        username,role,expires_s,sig=token.rsplit("|",3)
        expires=int(expires_s)
        if expires<int(time.time()): return None
        expected=hmac.new(PUIG_SESSION_SECRET.encode(),f"{username}|{role}|{expires}".encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected): return None
        if secrets.compare_digest(username,PUIG_ADMIN_USER) and role=="superadmin":
            return {"username":username,"display_name":username,"role":"superadmin"}
        row=get_user_row(username)
        if not row or not row["active"] or row["role"]!=role: return None
        return {"username":row["username"],"display_name":row["display_name"] or row["username"],"role":row["role"]}
    except Exception: return None

def require_admin(request: Request):
    ident=session_identity(request.cookies.get(SESSION_COOKIE))
    if not ident or ident["role"] not in ("superadmin","admin"):
        raise HTTPException(403,"Accès administrateur requis.")
    return ident

PUBLIC_PATHS={"/login","/api/login","/api/health"}

@app.middleware("http")
async def authentication_middleware(request: Request,call_next):
    if request.url.path in PUBLIC_PATHS: return await call_next(request)
    ident=session_identity(request.cookies.get(SESSION_COOKIE))
    if ident:
        request.state.user=ident
        return await call_next(request)
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=401,content={"detail":"Authentification requise"})
    return RedirectResponse("/login",status_code=303)

@app.get("/login",response_class=HTMLResponse)
def login_page(request: Request):
    if session_identity(request.cookies.get(SESSION_COOKIE)): return RedirectResponse("/",status_code=303)
    warning="" if auth_configured() else '<div class="warning">La protection n’est pas encore configurée dans Render.</div>'
    return HTMLResponse(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Connexion · PUIG VALUE™</title>
<style>*{{box-sizing:border-box}}body{{margin:0;background:#090e14;color:#f8fafc;font-family:Arial;min-height:100vh;display:grid;place-items:center;padding:20px}}.card{{width:min(430px,100%);background:#151b24;border:1px solid #2d3748;border-radius:18px;padding:30px}}.brand{{display:flex;gap:14px;align-items:center;margin-bottom:26px}}.logo{{background:#ed0a72;border-radius:12px;width:50px;height:50px;display:grid;place-items:center;font-weight:900}}h1{{font-size:23px;margin:0}}.sub{{color:#9ca3af;font-size:13px}}label{{display:block;color:#aeb7c4;font-size:12px;margin:16px 0 6px}}input{{width:100%;padding:13px;border-radius:10px;border:1px solid #344050;background:#0d131b;color:white;font-size:16px}}button{{width:100%;margin-top:22px;padding:14px;border:0;border-radius:11px;background:#ed0a72;color:white;font-weight:800;font-size:16px}}.error{{color:#ff8d8d;font-size:13px;min-height:18px;margin-top:12px}}.warning{{background:#3a2418;padding:11px;border-radius:9px;font-size:12px;margin-bottom:16px}}.secure{{text-align:center;color:#687386;font-size:11px;margin-top:18px}}</style></head>
<body><div class="card"><div class="brand"><div class="logo">PV</div><div><h1>PUIG VALUE™</h1><div class="sub">Accès privé · PUIG EXPERTISES</div></div></div>{{warning}}<form id="f"><label>Identifiant</label><input id="u" autocomplete="username" required autofocus><label>Mot de passe</label><input id="p" type="password" autocomplete="current-password" required><button>Se connecter</button><div id="e" class="error"></div></form><div class="secure">Compte personnel · session sécurisée 12 heures</div></div>
<script>f.onsubmit=async(x)=>{{x.preventDefault();let r=await fetch("/api/login",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{username:u.value,password:p.value}})}});if(r.ok)location.replace("/");else{{let d=await r.json().catch(()=>({{}}));e.textContent=d.detail||"Identifiant ou mot de passe incorrect.";}}}}</script></body></html>""".replace("{warning}",warning))

@app.post("/api/login")
async def login(request: Request):
    if not auth_configured(): raise HTTPException(503,"Authentification non configurée sur Render.")
    data=await request.json(); username=str(data.get("username","")).strip(); password=str(data.get("password",""))
    role=None; canonical=username
    if secrets.compare_digest(username,PUIG_ADMIN_USER) and secrets.compare_digest(password,PUIG_ADMIN_PASSWORD):
        role="superadmin"; canonical=PUIG_ADMIN_USER
    else:
        row=get_user_row(username)
        if row and row["active"] and verify_password(password,row["password_hash"]):
            role=row["role"]; canonical=row["username"]
    if not role: raise HTTPException(401,"Identifiant ou mot de passe incorrect.")
    expires=int(time.time())+SESSION_MAX_AGE
    response=JSONResponse({"ok":True,"username":canonical,"role":role})
    response.set_cookie(SESSION_COOKIE,make_session_token(canonical,role,expires),max_age=SESSION_MAX_AGE,httponly=True,secure=True,samesite="lax",path="/")
    return response

@app.post("/api/logout")
def logout():
    response=JSONResponse({"ok":True}); response.delete_cookie(SESSION_COOKIE,path="/",secure=True,httponly=True,samesite="lax"); return response

@app.get("/api/auth")
def auth_status(request: Request):
    ident=session_identity(request.cookies.get(SESSION_COOKIE))
    return {"authenticated":bool(ident),**(ident or {})}

@app.get("/api/users")
def list_users(request: Request):
    require_admin(request)
    with get_db() as conn:
        ensure_users_table(conn)
        rows=conn.execute("SELECT id,username,display_name,role,active,created_at,created_by FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return [dict(x) for x in rows]

@app.post("/api/users")
async def create_user(request: Request):
    admin=require_admin(request); d=await request.json()
    username=str(d.get("username","")).strip(); name=str(d.get("display_name","")).strip(); password=str(d.get("password","")); role=str(d.get("role","expert"))
    if len(username)<3 or len(password)<8: raise HTTPException(400,"Identifiant : 3 caractères minimum. Mot de passe : 8 caractères minimum.")
    if role not in ("admin","expert","viewer"): raise HTTPException(400,"Rôle invalide.")
    if username.lower()==PUIG_ADMIN_USER.lower(): raise HTTPException(400,"Identifiant réservé au Super Administrateur.")
    try:
        with get_db() as conn:
            ensure_users_table(conn)
            cur=conn.execute("INSERT INTO users(username,display_name,password_hash,role,active,created_at,created_by) VALUES(?,?,?,?,1,?,?)",(username,name,hash_password(password),role,datetime.utcnow().isoformat()+"Z",admin["username"]))
            conn.commit()
        return {"ok":True,"id":cur.lastrowid}
    except sqlite3.IntegrityError: raise HTTPException(409,"Cet identifiant existe déjà.")

@app.patch("/api/users/{user_id}")
async def update_user(user_id:int,request:Request):
    require_admin(request); d=await request.json()
    with get_db() as conn:
        ensure_users_table(conn); row=conn.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
        if not row: raise HTTPException(404,"Utilisateur introuvable.")
        role=str(d.get("role",row["role"])); active=1 if bool(d.get("active",row["active"])) else 0; name=str(d.get("display_name",row["display_name"])).strip(); password=str(d.get("password",""))
        if role not in ("admin","expert","viewer"): raise HTTPException(400,"Rôle invalide.")
        if password and len(password)<8: raise HTTPException(400,"Mot de passe : 8 caractères minimum.")
        if password: conn.execute("UPDATE users SET display_name=?,role=?,active=?,password_hash=? WHERE id=?",(name,role,active,hash_password(password),user_id))
        else: conn.execute("UPDATE users SET display_name=?,role=?,active=? WHERE id=?",(name,role,active,user_id))
        conn.commit()
    return {"ok":True}

@app.delete("/api/users/{user_id}")
def delete_user(user_id:int,request:Request):
    require_admin(request)
    with get_db() as conn:
        ensure_users_table(conn); cur=conn.execute("DELETE FROM users WHERE id=?",(user_id,)); conn.commit()
    if not cur.rowcount: raise HTTPException(404,"Utilisateur introuvable.")
    return {"ok":True}

@app.get("/admin/users",response_class=HTMLResponse)
def users_page(request:Request):
    require_admin(request)
    return HTMLResponse("""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Utilisateurs · PUIG VALUE</title><style>
*{box-sizing:border-box}body{margin:0;background:#090e14;color:#f8fafc;font-family:Arial}.wrap{max-width:1050px;margin:auto;padding:24px}a{color:#ff2d86;text-decoration:none}.card{background:#151b24;border:1px solid #2d3748;border-radius:16px;padding:20px;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}input,select{width:100%;padding:11px;border-radius:9px;border:1px solid #344050;background:#0d131b;color:white}button{padding:10px 14px;border:0;border-radius:9px;background:#ed0a72;color:white;font-weight:700;cursor:pointer}.secondary{background:#303a49}.danger{background:#7f1d1d}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #293241;text-align:left;font-size:13px}.muted{color:#9ca3af;font-size:12px}@media(max-width:700px){.grid{grid-template-columns:1fr}.tablewrap{overflow:auto}}</style></head><body><div class="wrap"><a href="/">← Retour à PUIG VALUE</a><h1>Gestion des utilisateurs</h1><div class="muted">Ton compte Render reste le Super Administrateur de secours.</div>
<div class="card"><h2>Créer un compte</h2><div class="grid"><input id="u" placeholder="Identifiant"><input id="n" placeholder="Nom affiché"><input id="p" type="password" placeholder="Mot de passe (8 caractères minimum)"><select id="r"><option value="expert">Expert</option><option value="admin">Administrateur</option><option value="viewer">Consultation</option></select></div><button onclick="createU()">Créer le compte</button> <span id="msg" class="muted"></span></div>
<div class="card"><h2>Comptes</h2><div class="tablewrap"><table><thead><tr><th>Identifiant</th><th>Nom</th><th>Rôle</th><th>Actif</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table></div></div></div>
<script>async function api(url,opt={}){let r=await fetch(url,opt),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||"Erreur");return d}function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function load(){let a=await api("/api/users");rows.innerHTML=a.map(x=>`<tr><td><b>${esc(x.username)}</b></td><td><input id="n${x.id}" value="${esc(x.display_name||"")}"></td><td><select id="r${x.id}"><option value="admin" ${x.role=="admin"?"selected":""}>Administrateur</option><option value="expert" ${x.role=="expert"?"selected":""}>Expert</option><option value="viewer" ${x.role=="viewer"?"selected":""}>Consultation</option></select></td><td><input id="a${x.id}" type="checkbox" ${x.active?"checked":""}></td><td><button class="secondary" onclick="save(${x.id})">Enregistrer</button> <button class="secondary" onclick="pwd(${x.id})">Mot de passe</button> <button class="danger" onclick="delU(${x.id},'${esc(x.username)}')">Supprimer</button></td></tr>`).join("")}
async function createU(){try{await api("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u.value,display_name:n.value,password:p.value,role:r.value})});u.value=n.value=p.value="";msg.textContent="Compte créé.";load()}catch(e){msg.textContent=e.message}}
async function save(id){try{await api("/api/users/"+id,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({display_name:document.getElementById("n"+id).value,role:document.getElementById("r"+id).value,active:document.getElementById("a"+id).checked})});alert("Compte mis à jour.")}catch(e){alert(e.message)}}
async function pwd(id){let q=prompt("Nouveau mot de passe (8 caractères minimum) :");if(!q)return;try{await api("/api/users/"+id,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:q})});alert("Mot de passe modifié.")}catch(e){alert(e.message)}}
async function delU(id,name){if(!confirm("Supprimer le compte "+name+" ?"))return;try{await api("/api/users/"+id,{method:"DELETE"});load()}catch(e){alert(e.message)}}load();</script></body></html>""")

app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")


class SavedEstimateRequest(BaseModel):
    title: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=5000)
    payload: dict[str, Any]
    result: dict[str, Any]


class ReportRequest(BaseModel):
    payload: dict[str, Any]
    result: dict[str, Any]
    report_title: str = Field(default="Rapport d’expertise en évaluation immobilière", max_length=250)


class EstimateRequest(BaseModel):
    address: str = Field(min_length=3)
    property_type: str = Field(pattern="^(Maison|Appartement)$")
    surface: float = Field(gt=5, le=1500)
    land: float = Field(default=0, ge=0, le=100000)
    rooms: int = Field(default=0, ge=0, le=50)
    condition: int = Field(default=7, ge=1, le=10)
    dpe: str = Field(default="D", pattern="^[A-G]$")
    radius_m: int = Field(default=1000, ge=100, le=5000)
    surface_tolerance: float = Field(default=0.20, ge=0.05, le=0.75)
    pressure: int = Field(default=50, ge=0, le=100)
    expert_value: float | None = Field(default=None, gt=0)
    garage: bool = False
    micro_location: int = Field(default=7, ge=1, le=10)
    architecture: int = Field(default=7, ge=1, le=10)
    nuisance: int = Field(default=0, ge=0, le=3)
    years: list[int] = Field(default_factory=lambda: [2021, 2022, 2023, 2024, 2025])


def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS valuations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            address TEXT NOT NULL,
            payload TEXT NOT NULL,
            result TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_estimations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            payload TEXT NOT NULL,
            result TEXT NOT NULL
        )
    """)
    ensure_users_table(conn)
    conn.commit()
    return conn


@app.get("/")
def home():
    return FileResponse(BASE_DIR / "app" / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "service": "PUIG VALUE WEB", "time": datetime.utcnow().isoformat() + "Z"}


async def enrich_location(citycode: str) -> dict[str, str]:
    if not citycode:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get(
                f"https://geo.api.gouv.fr/communes/{citycode}",
                params={"fields": "nom,code,codesPostaux,departement,region"}
            )
        if not r.is_success:
            return {}
        d = r.json()
        return {
            "commune": d.get("nom") or "",
            "department": (d.get("departement") or {}).get("nom") or "",
            "department_code": (d.get("departement") or {}).get("code") or "",
            "region": (d.get("region") or {}).get("nom") or "",
            "region_code": (d.get("region") or {}).get("code") or "",
        }
    except Exception:
        return {}


async def geocode_address(address: str) -> dict[str, Any]:
    params = {"q": address, "limit": 5}
    timeout = httpx.Timeout(20.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(GEOCODE_URL, params=params)
        r.raise_for_status()
        data = r.json()
    feats = data.get("features") or []
    if not feats:
        raise HTTPException(404, "Adresse introuvable par la Géoplateforme IGN.")
    f = feats[0]
    coords = f.get("geometry", {}).get("coordinates", [])
    if len(coords) != 2:
        raise HTTPException(502, "Réponse de géocodage incomplète.")
    p = f.get("properties") or {}
    citycode = str(p.get("citycode") or p.get("city_code") or "")
    postcode = str(p.get("postcode") or "")
    if not citycode and postcode:
        # fallback : le code INSEE n'est normalement pas absent, mais on le signale.
        raise HTTPException(502, "Le géocodeur n'a pas retourné de code INSEE.")
    return {
        "label": p.get("label") or address,
        "lon": float(coords[0]),
        "lat": float(coords[1]),
        "city": p.get("city") or "",
        "postcode": postcode,
        "citycode": citycode,
        "score": p.get("score"),
    }


@app.get("/api/geocode")
async def geocode(q: str = Query(min_length=3)):
    return await geocode_address(q)


@app.get("/api/address-search")
async def address_search(q: str = Query(min_length=3), limit: int = Query(default=6, ge=1, le=10)):
    params = {"q": q, "limit": limit, "autocomplete": 1}
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(GEOCODE_URL, params=params)
        r.raise_for_status()
        data = r.json()
    out = []
    for f in (data.get("features") or []):
        p = f.get("properties") or {}
        coords = f.get("geometry", {}).get("coordinates", [])
        if len(coords) != 2:
            continue
        out.append({
            "label": p.get("label") or "",
            "name": p.get("name") or p.get("street") or "",
            "street": p.get("street") or p.get("name") or "",
            "postcode": str(p.get("postcode") or ""),
            "city": p.get("city") or "",
            "citycode": str(p.get("citycode") or ""),
            "lon": float(coords[0]),
            "lat": float(coords[1]),
            "score": p.get("score"),
        })
    return out


def dept_from_insee(insee: str) -> str:
    if insee.startswith(("2A", "2B")):
        return insee[:2]
    return insee[:2]


async def ensure_dvf_file(year: int, citycode: str, force: bool = False) -> Path:
    dept = dept_from_insee(citycode)
    local = CACHE_DIR / f"dvf_{year}_{citycode}.csv"
    if local.exists() and local.stat().st_size > 50 and not force:
        age_seconds = datetime.now().timestamp() - local.stat().st_mtime
        if age_seconds < DVF_CACHE_MAX_AGE_DAYS * 86400:
            return local

    url = f"{DVF_BASE}/{year}/communes/{dept}/{citycode}.csv"
    timeout = httpx.Timeout(60.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url, headers={"User-Agent": "PUIG-VALUE/2.0"})
    if r.status_code == 404:
        if local.exists() and local.stat().st_size > 50:
            return local
        raise FileNotFoundError(url)
    r.raise_for_status()
    tmp = local.with_suffix(".csv.tmp")
    tmp.write_bytes(r.content)
    tmp.replace(local)
    return local


def cached_dvf_entries():
    entries = []
    for p in sorted(CACHE_DIR.glob("dvf_*_*.csv")):
        try:
            parts = p.stem.split("_")
            entries.append({
                "year": int(parts[1]),
                "citycode": parts[2],
                "path": p,
                "updated_at": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
            })
        except Exception:
            continue
    return entries


async def sync_cached_dvf(force: bool = False):
    updated, failed = [], []
    for e in cached_dvf_entries():
        try:
            p = await ensure_dvf_file(e["year"], e["citycode"], force=force)
            updated.append({"year": e["year"], "citycode": e["citycode"], "updated_at": datetime.fromtimestamp(p.stat().st_mtime).isoformat()})
        except Exception as exc:
            failed.append({"year": e["year"], "citycode": e["citycode"], "error": str(exc)})
    return {"updated": updated, "failed": failed}


async def dvf_sync_loop():
    while True:
        try:
            await sync_cached_dvf(force=False)
        except Exception:
            pass
        await asyncio.sleep(max(1, DVF_SYNC_INTERVAL_HOURS) * 3600)


@app.on_event("startup")
async def startup_tasks():
    get_db().close()
    asyncio.create_task(dvf_sync_loop())


@app.get("/api/dvf/status")
def dvf_status():
    entries = cached_dvf_entries()
    return {
        "cache_entries": len(entries),
        "last_sync": max((e["updated_at"] for e in entries), default=None),
        "check_every_hours": DVF_SYNC_INTERVAL_HOURS,
        "cache_max_age_days": DVF_CACHE_MAX_AGE_DAYS,
        "official_schedule": "Publication DVF semestrielle : avril et octobre.",
    }


@app.post("/api/dvf/sync")
async def dvf_sync_now():
    return await sync_cached_dvf(force=True)


def fnum(v: Any) -> float:
    if v is None:
        return 0.0
    try:
        return float(str(v).replace(",", "."))
    except Exception:
        return 0.0


def fint(v: Any) -> int:
    try:
        return int(float(str(v).replace(",", ".")))
    except Exception:
        return 0


def normalize_row(row: dict[str, str]) -> dict[str, Any] | None:
    if row.get("nature_mutation") != "Vente":
        return None
    typ = row.get("type_local")
    if typ not in {"Maison", "Appartement"}:
        return None
    price = fnum(row.get("valeur_fonciere"))
    surface = fnum(row.get("surface_reelle_bati"))
    lat = fnum(row.get("latitude"))
    lon = fnum(row.get("longitude"))
    if not price or not surface or not lat or not lon:
        return None
    ppm = price / surface
    if price < 20000 or price > 4_000_000 or surface < 9 or surface > 1000 or ppm < 200 or ppm > 15000:
        return None
    addr = " ".join(x for x in [
        row.get("adresse_numero") or "",
        row.get("adresse_suffixe") or "",
        row.get("adresse_nom_voie") or ""
    ] if x).strip()
    return {
        "id_mutation": row.get("id_mutation") or "",
        "date": row.get("date_mutation") or "",
        "price": price,
        "type": typ,
        "surface": surface,
        "land": fnum(row.get("surface_terrain")),
        "rooms": fint(row.get("nombre_pieces_principales")),
        "lat": lat,
        "lon": lon,
        "address": addr,
        "commune": row.get("nom_commune") or "",
        "postcode": row.get("code_postal") or "",
        "parcel": row.get("id_parcelle") or "",
    }


def load_simple_sales(paths: list[Path]) -> list[dict[str, Any]]:
    # Une mutation peut comporter plusieurs locaux : on groupe et on privilégie les ventes
    # ne comportant qu'un seul local résidentiel exploitable.
    groups: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                r = normalize_row(row)
                if not r:
                    continue
                mid = r["id_mutation"]
                groups.setdefault(mid, []).append(r)
    out = []
    for rows in groups.values():
        if len(rows) != 1:
            continue
        out.append(rows[0])
    return out


def haversine(lat1, lon1, lat2, lon2) -> float:
    R = 6371000.0
    p = math.pi / 180.0
    a1, a2 = lat1*p, lat2*p
    da, dl = (lat2-lat1)*p, (lon2-lon1)*p
    a = math.sin(da/2)**2 + math.cos(a1)*math.cos(a2)*math.sin(dl/2)**2
    return 2*R*math.atan2(math.sqrt(a), math.sqrt(1-a))


def distance_score(d):
    if d < 100: return 100
    if d < 250: return 95
    if d < 500: return 88
    if d < 750: return 78
    if d < 1000: return 68
    if d < 2000: return 50
    return 30


def age_months(date_str: str) -> int:
    try:
        d = date.fromisoformat(date_str[:10])
    except Exception:
        return 120
    t = date.today()
    return max(0, (t.year-d.year)*12 + t.month-d.month)


def age_score(m):
    if m <= 6: return 100
    if m <= 12: return 95
    if m <= 18: return 88
    if m <= 24: return 80
    if m <= 36: return 65
    if m <= 48: return 52
    return 45


def surface_score(a, b):
    return min(a, b) / max(a, b) * 100


def land_score(a, b):
    if a <= 0 or b <= 0:
        return 70
    return max(0, min(100, 100 - abs(math.log(a/b))*35))


def norm_address(s: str) -> str:
    import unicodedata, re
    s = unicodedata.normalize("NFD", (s or "").lower())
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = re.sub(r"\\s+", " ", s).strip()
    return s


def street_only(s: str) -> str:
    import re
    s = norm_address(s)
    return re.sub(r"^\\d+[a-z]?\\s+", "", s).strip()


DPE_ADJ = {"A": 0.0, "B": 0.0, "C": 0.0, "D": 0.0, "E": 0.0, "F": 0.0, "G": 0.0}


def subject_quality_adjustment(req: EstimateRequest) -> dict[str, float]:
    # Coefficients V1.2 explicités et volontairement plafonnés.
    # Ils sont à recalibrer ultérieurement par apprentissage sur ventes réelles.
    condition = max(-0.125, min(0.075, (req.condition - 7) * 0.025))
    # EVS 2025 : le DPE est documenté et analysé, mais aucune correction automatique n’est appliquée.
    dpe = 0.0
    garage = 0.025 if req.garage else 0.0
    micro = max(-0.06, min(0.06, (req.micro_location - 7) * 0.02))
    architecture = max(-0.045, min(0.045, (req.architecture - 7) * 0.015))
    nuisance = -0.025 * req.nuisance
    total = condition + dpe + garage + micro + architecture + nuisance
    total = max(-0.22, min(0.18, total))
    return {
        "condition": condition,
        "dpe": dpe,
        "garage": garage,
        "micro_location": micro,
        "architecture": architecture,
        "nuisance": nuisance,
        "total": total,
    }


def simple_linear_regression(points: list[tuple[float, float]]) -> dict[str, float] | None:
    pts = [(float(x), float(y)) for x, y in points if x is not None and y is not None and math.isfinite(float(x)) and math.isfinite(float(y))]
    if len(pts) < 3:
        return None
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    xm = sum(xs)/len(xs); ym = sum(ys)/len(ys)
    sxx = sum((x-xm)**2 for x in xs)
    if sxx == 0:
        return None
    slope = sum((x-xm)*(y-ym) for x,y in pts)/sxx
    intercept = ym - slope*xm
    sst = sum((y-ym)**2 for y in ys)
    sse = sum((y-(intercept+slope*x))**2 for x,y in pts)
    r2 = 1 - sse/sst if sst else 0
    return {"slope": slope, "intercept": intercept, "r2": max(0, min(1, r2))}


def comp_score(req: EstimateRequest, sale, distance):
    room_score = 70
    if req.rooms and sale["rooms"]:
        room_score = max(40, min(100, 100 - abs(req.rooms-sale["rooms"])*15))
    return max(0, min(100,
        .30*distance_score(distance) +
        .24*surface_score(req.surface, sale["surface"]) +
        .14*age_score(age_months(sale["date"])) +
        .10*land_score(req.land, sale["land"]) +
        .08*room_score +
        .14*100
    ))


def percentile(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    k = (len(s)-1)*p
    f = math.floor(k); c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f]*(c-k)+s[c]*(k-f)


def confidence(comps, expert_present: bool):
    scores = [c["score"] for c in comps]
    quality = min(30, (sum(scores)/len(scores))/100*30)
    n = len(comps)
    npts = 15 if n >= 10 else 13 if n >= 7 else 10 if n >= 5 else 6 if n >= 3 else 2
    fresh = min(10, sum(age_score(c["months"]) for c in comps)/len(comps)/10)
    ppms = [c["price"]/c["surface"] for c in comps]
    mean = sum(ppms)/len(ppms)
    sd = math.sqrt(sum((x-mean)**2 for x in ppms)/len(ppms))
    cv = sd/mean if mean else 1
    disp = 15 if cv < .05 else 12 if cv < .08 else 9 if cv < .12 else 5 if cv < .18 else 2
    parts = {
        "Qualité comparables": quality,
        "Nombre de comparables": npts,
        "Fraîcheur": fresh,
        "Dispersion": disp,
        "Données du bien": 10,
        "Micro-localisation": 5,
        "Marché actif": 5,
        "Validation expert": 5 if expert_present else 2,
        "Absence d'anomalies": 5,
    }
    return max(20, min(100, sum(parts.values()))), parts, cv


@app.post("/api/estimate")
async def estimate(req: EstimateRequest):
    geo = await geocode_address(req.address)
    citycode = geo["citycode"]
    geo["territory"] = await enrich_location(citycode)

    files = []
    missing = []
    for y in sorted(set(req.years)):
        if y < 2014 or y > date.today().year:
            continue
        try:
            files.append(await ensure_dvf_file(y, citycode))
        except FileNotFoundError:
            missing.append(y)
        except httpx.HTTPError as e:
            raise HTTPException(502, f"DVF indisponible pour {y}: {e}")

    if not files:
        raise HTTPException(404, "Aucun fichier DVF n'a pu être chargé pour cette commune.")

    sales = load_simple_sales(files)
    candidates = []
    subject_addr = norm_address(geo["label"])
    subject_street = street_only(geo["label"])

    for s in sales:
        if s["type"] != req.property_type:
            continue
        surf_gap = abs(s["surface"] - req.surface) / req.surface
        if surf_gap > req.surface_tolerance:
            continue
        d = haversine(geo["lat"], geo["lon"], s["lat"], s["lon"])
        sale_addr = norm_address(s["address"])
        # Appartement : "même immeuble" = même adresse normalisée exacte.
        # On évite les tests par sous-chaîne (ex. 1 rue X vs 11 rue X).
        same_building = bool(subject_addr and sale_addr and sale_addr == subject_addr)
        same_street = bool(subject_street and street_only(s["address"]) == subject_street)
        sc = comp_score(req, s, d)
        if same_building:
            sc = min(100, sc + 12)
        elif same_street:
            sc = min(100, sc + 6)
        candidates.append({
            **s,
            "distance": round(d, 1),
            "months": age_months(s["date"]),
            "score": round(sc, 1),
            "price_per_m2": round(s["price"]/s["surface"], 0),
            "same_building": same_building,
            "same_street": same_street,
        })

    # Hiérarchie géographique stricte V2.1.
    # APPARTEMENT : s'il existe au moins une mutation à la même adresse exacte,
    # seules ces mutations sont utilisées. On n'élargit que s'il n'y en a aucune.
    # MAISON : 100 m -> 200 -> 300 -> 400 -> 500 -> 750 -> 1000 m.
    selected = []
    seen = set()
    effective_radius = 0

    if req.property_type == "Appartement":
        same_address = sorted(
            [c for c in candidates if c["same_building"] and c["score"] >= 60],
            key=lambda x: (x["score"], -x["months"]), reverse=True
        )
        if same_address:
            selected = same_address[:10]
            seen = {c["id_mutation"] for c in selected}
            effective_radius = max((c["distance"] for c in selected), default=0)
            selection_method = "Appartement : références exclusivement à la même adresse"
        else:
            radius_steps = [100, 200, 300, 400, 500, 750, 1000, 1500, 2000]
            allowed_steps = [r for r in radius_steps if r <= req.radius_m]
            if not allowed_steps:
                allowed_steps = [100]
            tiers = []
            if 100 in allowed_steps:
                tiers.append(("même rue / 100 m", [c for c in candidates if c["same_street"] and c["distance"] <= 100]))
            if 200 in allowed_steps:
                tiers.append(("même rue / 200 m", [c for c in candidates if c["same_street"] and c["distance"] <= 200]))
            for rr in [r for r in allowed_steps if r >= 300]:
                label = f"{rr} m" if rr < 1000 else f"{rr/1000:g} km"
                tiers.append((label, [c for c in candidates if c["distance"] <= rr]))
            selection_method = "Appartement : aucune vente à la même adresse, élargissement progressif"
            for label, tier in tiers:
                for c in sorted(tier, key=lambda x: (str(x.get("date") or x.get("date_mutation") or ""), x.get("score", 0)), reverse=True):
                    if c["score"] < 60 or c["id_mutation"] in seen:
                        continue
                    seen.add(c["id_mutation"]); selected.append(c)
                    effective_radius = max(effective_radius, c["distance"])
                    if len(selected) >= 10:
                        break
                if len(selected) >= 5:
                    selection_method += f" jusqu'à {label}"
                    break
    else:
        radius_steps = [100, 200, 300, 400, 500, 750, 1000, 1500, 2000]
        allowed_steps = [r for r in radius_steps if r <= req.radius_m]
        if not allowed_steps:
            allowed_steps = [100]
        tiers = [
            (f"{r} m" if r < 1000 else f"{r/1000:g} km",
             [c for c in candidates if c["distance"] <= r])
            for r in allowed_steps
        ]
        selection_method = "Maison : élargissement progressif"
        for label, tier in tiers:
            for c in sorted(tier, key=lambda x: (str(x.get("date") or x.get("date_mutation") or ""), x.get("score", 0)), reverse=True):
                if c["score"] < 60 or c["id_mutation"] in seen:
                    continue
                seen.add(c["id_mutation"]); selected.append(c)
                effective_radius = max(effective_radius, c["distance"])
                if len(selected) >= 12:
                    break
            if len(selected) >= 5:
                selection_method += f" jusqu'à {label}"
                break

    # Nombre maximal de références conservées après la recherche progressive.
    target_n = 10 if req.property_type == "Appartement" else 12

    # V2.6 — priorité chronologique DVF :
    # parmi les références admissibles trouvées par la recherche progressive,
    # on conserve/affiche les mutations de la plus récente à la plus ancienne.
    # À date identique, le score de comparabilité départage les références.
    selected = sorted(
        selected,
        key=lambda c: (
            str(c.get("date") or c.get("date_mutation") or ""),
            float(c.get("score", 0) or 0)
        ),
        reverse=True
    )
    selected = selected[:target_n]
    expanded_radius = round(effective_radius or req.radius_m)

    if not selected:
        raise HTTPException(422, "Aucun comparable DVF suffisamment pertinent dans les critères disponibles.")

    num = den = 0.0
    for c in selected:
        base = (c["price"]/c["surface"]) * req.surface
        surf_adj = max(-.04, min(.04, ((c["surface"]-req.surface)/req.surface)*.10))
        land_adj = 0.0
        if req.land > 0 and c["land"] > 0:
            land_adj = max(-.06, min(.06, math.log(req.land/c["land"])*.035))
        adjusted = base*(1+surf_adj+land_adj)
        weight = (c["score"]/100)**4
        c["adjusted_value"] = round(adjusted, 0)
        c["weight"] = round(weight, 4)
        num += adjusted*weight
        den += weight

    vcomp = num/den
    quality_adj = subject_quality_adjustment(req)
    model_value = vcomp * (1 + quality_adj["total"])
    central = model_value if not req.expert_value else model_value*.90 + req.expert_value*.10

    conf, parts, cv = confidence(selected, req.expert_value is not None)
    spread = .03 if conf >= 90 else .05 if conf >= 80 else .07 if conf >= 70 else .10 if conf >= 60 else .15
    low, high = central*(1-spread), central*(1+spread)
    listing = central*(1.02 + (req.pressure-50)/2500)
    quick = central*.95
    ambitious = central*1.06

    med_ppm = percentile([c["price_per_m2"] for c in selected], .5)
    med_dist = percentile([c["distance"] for c in selected], .5)
    med_age = percentile([c["months"] for c in selected], .5)

    regression_surface = simple_linear_regression([(c["surface"], c["price_per_m2"]) for c in selected])
    regression_distance = simple_linear_regression([(c["distance"], c["price_per_m2"]) for c in selected])
    regression_age = simple_linear_regression([(c["months"], c["price_per_m2"]) for c in selected])

    sensitivity = []
    for cond in range(4, 11):
        fake_req = req.model_copy(update={"condition": cond})
        adj = subject_quality_adjustment(fake_req)
        sensitivity.append({"criterion": "condition", "x": cond, "value": round(vcomp*(1+adj["total"]))})
    for dpe_label in ["A","B","C","D","E","F","G"]:
        fake_req = req.model_copy(update={"dpe": dpe_label})
        adj = subject_quality_adjustment(fake_req)
        sensitivity.append({"criterion": "dpe", "x": dpe_label, "value": round(vcomp*(1+adj["total"]))})

    alerts = []
    if len(selected) < 5: alerts.append("Moins de 5 comparables significatifs.")
    if cv > .18: alerts.append("Dispersion élevée des prix au m².")
    if med_dist and med_dist > 1200: alerts.append("Comparables géographiquement éloignés.")
    if med_age and med_age > 36: alerts.append("Références relativement anciennes : vérifier une correction d'évolution du marché avant conclusion.")
    if sum(1 for c in selected if int(c.get("months", 9999)) <= 24) < 3:
        alerts.append("Peu de références N/N-1 : l'élargissement temporel doit être justifié dans le rapport.")
    if not req.expert_value: alerts.append("Valeur non encore validée par l'expert après visite.")

    # PUIG VALUE V2.8 — contrôle de cohérence inspiré du support EVS 2025.
    # Il rend le raisonnement visible sans prétendre remplacer le jugement de l'expert.
    ppm_values = [float(c["price_per_m2"]) for c in selected if c.get("price_per_m2")]
    ppm_min = min(ppm_values) if ppm_values else 0
    ppm_max = max(ppm_values) if ppm_values else 0
    global_values = [float(c["price"]) for c in selected if c.get("price")]
    global_min = min(global_values) if global_values else 0
    global_max = max(global_values) if global_values else 0
    recent_count = sum(1 for c in selected if int(c.get("months", 9999)) <= 24)
    evs_checks = {
        "framework": "Approche → Méthode → Modèle → Jugement",
        "approach": "Marché",
        "method": "Comparaison directe pondérée",
        "model": "Score de pertinence + ajustements explicites + contrôle statistique",
        "expert_judgment": "Validation finale requise",
        "surface_rule": "Comparables proches de ±20 % par défaut ; élargissement seulement si justifié",
        "time_rule": "Priorité N/N-1 ; références plus anciennes possibles si le marché l'exige",
        "dpe_rule": "DPE analysé sans correction automatique",
        "offer_rule": "Prix d'offre = indice de marché / recoupement, jamais transaction assimilée",
        "recent_24m_count": recent_count,
        "ppm_bracket": {"low": round(ppm_min), "high": round(ppm_max)},
        "global_value_bracket": {"low": round(global_min), "high": round(global_max)},
        "black_box_check": "Critères, références, scores, poids et ajustements affichés",
    }

    result = {
        "geocode": geo,
        "source": {
            "dvf_years_loaded": [int(p.name.split("_")[1]) for p in files],
            "dvf_years_missing": missing,
            "citycode": citycode,
            "sales_scanned": len(sales),
            "scope_note": "V1 WEB recherche dans la commune géocodée ; l'extension intercommunale sera ajoutée ensuite.",
        },
        "search": {
            "requested_radius_m": req.radius_m,
            "effective_radius_m": expanded_radius,
            "selection_method": selection_method,
            "surface_tolerance": req.surface_tolerance,
            "comparables_found": len(candidates),
            "comparables_selected": len(selected),
        },
        "valuation": {
            "comparables_value": round(vcomp),
            "quality_adjusted_value": round(model_value),
            "quality_adjustment": {k: round(v*100, 2) for k,v in quality_adj.items()},
            "central": round(central),
            "low": round(low),
            "high": round(high),
            "listing": round(listing),
            "quick_sale": round(quick),
            "ambitious": round(ambitious),
        },
        "confidence": {
            "score": round(conf, 1),
            "parts": {k: round(v,1) for k,v in parts.items()},
            "dispersion_cv": round(cv, 4),
        },
        "market": {
            "median_price_per_m2": round(med_ppm or 0),
            "median_distance_m": round(med_dist or 0),
            "median_age_months": round(med_age or 0),
        },
        "regression": {
            "surface_vs_ppm": regression_surface,
            "distance_vs_ppm": regression_distance,
            "age_vs_ppm": regression_age,
            "sensitivity": sensitivity,
        },
        "alerts": alerts,
        "evs2025": evs_checks,
        "comparables": selected,
    }

    return result


@app.post("/api/saved-estimates")
def save_estimate(req: SavedEstimateRequest):
    address = str(req.payload.get("address") or req.result.get("geocode", {}).get("label") or "")
    title = req.title.strip() or address or "Estimation"
    now = datetime.utcnow().isoformat() + "Z"
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO saved_estimations(created_at,updated_at,title,address,notes,payload,result) VALUES(?,?,?,?,?,?,?)",
            (now, now, title, address, req.notes, json.dumps(req.payload, ensure_ascii=False), json.dumps(req.result, ensure_ascii=False))
        )
        conn.commit()
        sid = cur.lastrowid
    return {"id": sid, "created_at": now, "title": title, "address": address}


@app.get("/api/saved-estimates")
def list_saved_estimates(limit: int = Query(default=50, ge=1, le=200)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id,created_at,updated_at,title,address,notes,result FROM saved_estimations ORDER BY updated_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    out = []
    for row in rows:
        result = json.loads(row["result"])
        out.append({
            "id": row["id"], "created_at": row["created_at"], "updated_at": row["updated_at"],
            "title": row["title"], "address": row["address"], "notes": row["notes"],
            "central": result.get("valuation", {}).get("central"),
            "confidence": result.get("confidence", {}).get("score"),
        })
    return out


@app.get("/api/saved-estimates/{estimate_id}")
def get_saved_estimate(estimate_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM saved_estimations WHERE id=?", (estimate_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Estimation sauvegardée introuvable.")
    return {
        "id": row["id"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        "title": row["title"], "address": row["address"], "notes": row["notes"],
        "payload": json.loads(row["payload"]), "result": json.loads(row["result"]),
    }


@app.delete("/api/saved-estimates/{estimate_id}")
def delete_saved_estimate(estimate_id: int):
    with get_db() as conn:
        cur = conn.execute("DELETE FROM saved_estimations WHERE id=?", (estimate_id,))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Estimation sauvegardée introuvable.")
    return {"ok": True}


def _esc(value):
    return html.escape(str(value if value is not None else ""))


def _euro(value):
    try:
        return f"{round(float(value)/1000)*1000:,.0f} €".replace(",", " ")
    except Exception:
        return "—"


def _svg_scatter(comps, xkey, regression, title, x_label):
    W, H = 720, 300
    pl, pr, pt, pb = 65, 25, 35, 45
    pts = []
    for comp in comps:
        try:
            x = float(comp.get(xkey, 0))
            y = float(comp.get("price_per_m2", 0))
            if y > 0:
                pts.append((x, y))
        except Exception:
            pass
    if not pts:
        return ""
    xs = [x for x,_ in pts]
    ys = [y for _,y in pts]
    xmin, xmax, ymin, ymax = min(xs), max(xs), min(ys), max(ys)
    if xmax == xmin: xmax += 1
    if ymax == ymin: ymax += 1
    my = (ymax-ymin)*0.08
    ymin = max(0, ymin-my); ymax += my
    sx = lambda x: pl + (x-xmin)/(xmax-xmin)*(W-pl-pr)
    sy = lambda y: pt + (ymax-y)/(ymax-ymin)*(H-pt-pb)
    circles = "".join([f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="4" fill="#e41270" opacity=".75"/>' for x,y in pts])
    line = ""
    r2 = ""
    if regression:
        y1 = regression["intercept"] + regression["slope"]*xmin
        y2 = regression["intercept"] + regression["slope"]*xmax
        line = f'<line x1="{sx(xmin):.1f}" y1="{sy(y1):.1f}" x2="{sx(xmax):.1f}" y2="{sy(y2):.1f}" stroke="#111827" stroke-width="2"/>'
        r2 = f'R² = {regression["r2"]:.2f}'
    grid = ""
    labels = ""
    for i in range(5):
        yy = pt + i*(H-pt-pb)/4
        val = ymax - i*(ymax-ymin)/4
        grid += f'<line x1="{pl}" y1="{yy:.1f}" x2="{W-pr}" y2="{yy:.1f}" stroke="#e5e7eb"/>'
        labels += f'<text x="{pl-8}" y="{yy+4:.1f}" text-anchor="end" font-size="10" fill="#4b5563">{round(val)}</text>'
    return (
        f'<svg viewBox="0 0 {W} {H}" width="100%">'
        f'<text x="{pl}" y="20" font-size="14" font-weight="700">{_esc(title)}</text>'
        f'{grid}{labels}'
        f'<line x1="{pl}" y1="{H-pb}" x2="{W-pr}" y2="{H-pb}" stroke="#6b7280"/>'
        f'<line x1="{pl}" y1="{pt}" x2="{pl}" y2="{H-pb}" stroke="#6b7280"/>'
        f'{circles}{line}'
        f'<text x="{W/2}" y="{H-10}" text-anchor="middle" font-size="11">{_esc(x_label)}</text>'
        f'<text x="16" y="{H/2}" transform="rotate(-90 16 {H/2})" text-anchor="middle" font-size="11">Prix au m² (€)</text>'
        f'<text x="{W-pr}" y="20" text-anchor="end" font-size="11" fill="#4b5563">{r2}</text>'
        '</svg>'
    )


@app.post("/api/report", response_class=HTMLResponse)
def build_report(req: ReportRequest):
    p = req.payload
    r = req.result
    g = r.get("geocode", {})
    territory = g.get("territory") or {}
    v = r.get("valuation", {})
    m = r.get("market", {})
    reg = r.get("regression", {})
    comps = r.get("comparables", [])[:12]
    q = v.get("quality_adjustment", {})
    now = datetime.now().strftime("%d/%m/%Y")
    address = g.get("label") or p.get("address") or ""
    region = territory.get("region") or ""
    department = territory.get("department") or ""
    commune = territory.get("commune") or g.get("city") or ""
    radius = r.get("search", {}).get("effective_radius_m", "")
    method = r.get("search", {}).get("selection_method", "")
    surface_svg = _svg_scatter(comps, "surface", reg.get("surface_vs_ppm"), "Régression : surface et prix au m²", "Surface habitable (m²)")
    distance_svg = _svg_scatter(comps, "distance", reg.get("distance_vs_ppm"), "Régression : distance et prix au m²", "Distance au bien (m)")

    comp_rows = "".join(
        f"<tr><td>{_esc(c.get('address') or c.get('parcel'))}</td><td>{_esc(c.get('date'))}</td>"
        f"<td>{_euro(c.get('price'))}</td><td>{_esc(round(c.get('price_per_m2',0)))} €/m²</td>"
        f"<td>{_esc(c.get('surface'))} m²</td><td>{_esc(round(c.get('distance',0)))} m</td><td>{_esc(c.get('score'))}/100</td></tr>"
        for c in comps
    )

    qual_parts = []
    for key, label in [
        ("condition","État général"),("dpe","DPE"),("garage","Garage/stationnement"),
        ("micro_location","Micro-localisation"),("architecture","Architecture/cachet"),("nuisance","Nuisances")
    ]:
        val = float(q.get(key,0) or 0)
        if abs(val) >= .01:
            qual_parts.append(f"{label}: {val:+.2f}%")
    qualitative = " ; ".join(qual_parts) if qual_parts else "Aucune correction qualitative significative."

    surf_reg = reg.get("surface_vs_ppm") or {}
    dist_reg = reg.get("distance_vs_ppm") or {}

    report_html = f'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>{_esc(req.report_title)}</title>
<style>
@page{{size:A4;margin:18mm}}
body{{font-family:Arial,sans-serif;color:#1f2937;line-height:1.45;font-size:11pt;margin:0}}
h1{{font-size:23pt;margin:0 0 6px}} h2{{font-size:16pt;margin-top:26px;border-bottom:2px solid #e41270;padding-bottom:5px}}
h3{{font-size:12pt;margin-top:18px}} .brand{{color:#e41270;font-weight:800;letter-spacing:.04em}}
.muted{{color:#6b7280}} .summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:15px 0}}
.box{{border:1px solid #d1d5db;border-radius:8px;padding:10px}} .value{{font-size:18pt;font-weight:800}}
table{{width:100%;border-collapse:collapse;font-size:9pt}} th,td{{border-bottom:1px solid #e5e7eb;padding:6px;text-align:left}} th{{background:#f3f4f6}}
.callout{{border-left:4px solid #e41270;background:#f9fafb;padding:10px 12px;margin:12px 0}}
.pagebreak{{page-break-before:always}} svg{{max-width:100%;height:auto}}
@media print{{button{{display:none}}}}
</style></head><body>
<div class="brand">PUIG EXPERTISES · PUIG VALUE™</div>
<h1>{_esc(req.report_title)}</h1>
<div class="muted">Bien : {_esc(address)} · Rapport généré le {now}</div>
<div class="summary">
<div class="box"><div class="muted">Valeur vénale centrale</div><div class="value">{_euro(v.get("central"))}</div></div>
<div class="box"><div class="muted">Fourchette</div><div class="value">{_euro(v.get("low"))} – {_euro(v.get("high"))}</div></div>
<div class="box"><div class="muted">Confiance</div><div class="value">{_esc(r.get("confidence",{}).get("score","—"))}/100</div></div>
</div>

<h2>1. Objet de la mission et principe d’évaluation</h2>
<p>Le présent document constitue une analyse d’évaluation immobilière fondée sur une approche comparative de marché, complétée par une analyse statistique des transactions DVF et par des corrections qualitatives liées aux caractéristiques propres du bien.</p>

<h2>2. Situation géographique : du territoire au micro-secteur</h2>
<h3>2.1 Région et département</h3>
<p>Le bien est situé en <strong>{_esc(region or "territoire non renseigné")}</strong>, dans le département <strong>{_esc(department or "non renseigné")}</strong>.</p>
<h3>2.2 Commune</h3>
<p>Il se situe sur la commune de <strong>{_esc(commune)}</strong> ({_esc(g.get("postcode",""))}).</p>
<h3>2.3 Secteur et environnement immédiat</h3>
<p>Le micro-marché a été recherché autour de l’adresse <strong>{_esc(address)}</strong>. Le rayon effectivement utilisé est d’environ <strong>{_esc(radius)} m</strong>. Méthode : {_esc(method)}.</p>
<div class="callout">Distance médiane : <strong>{_esc(m.get("median_distance_m","—"))} m</strong> · Prix médian observé : <strong>{_esc(m.get("median_price_per_m2","—"))} €/m²</strong>.</div>

<h2>3. Description synthétique du bien</h2>
<table><tr><th>Type</th><th>Surface</th><th>Terrain</th><th>Pièces</th><th>État</th><th>DPE</th></tr>
<tr><td>{_esc(p.get("property_type",""))}</td><td>{_esc(p.get("surface",""))} m²</td><td>{_esc(p.get("land",0))} m²</td><td>{_esc(p.get("rooms",0))}</td><td>{_esc(p.get("condition",""))}/10</td><td>{_esc(p.get("dpe",""))}</td></tr></table>

<h2>4. Méthodologie comparative</h2>
<p>La sélection suit un processus explicite : aire de marché pertinente, type de bien, proximité de surface, proximité temporelle et pertinence. Pour les appartements, la priorité est donnée à la même adresse ; pour les maisons, la recherche part de 100 m et s'élargit progressivement. Les mutations sont présentées de la plus récente à la plus ancienne. Chaque référence reçoit un score de pertinence et un poids non linéaire.</p>
<p>Règle de gabarit par défaut : références proches de ±20 % de la surface du bien, sauf élargissement justifié par les données disponibles.</p>
<p>Valeur issue des comparables : <strong>{_euro(v.get("comparables_value"))}</strong>. Après correction des caractéristiques : <strong>{_euro(v.get("quality_adjusted_value"))}</strong>.</p>
<p>{_esc(qualitative)} Ajustement total : <strong>{_esc(q.get("total",0))}%</strong>.</p>

<h2>5. Références de marché retenues</h2>
<table><thead><tr><th>Adresse</th><th>Date</th><th>Prix</th><th>€/m²</th><th>Surface</th><th>Distance</th><th>Score</th></tr></thead><tbody>{comp_rows}</tbody></table>

<div class="pagebreak"></div>
<h2>6. Analyse statistique et courbes de régression</h2>
<p>Les courbes permettent d’observer la relation entre les caractéristiques des références et leur niveau de prix. Le coefficient R² est présenté pour mesurer la force de la relation linéaire.</p>
{surface_svg}
<p>Pente surface : <strong>{_esc(round(surf_reg.get("slope",0),2))}</strong> €/m² par m² · R² : <strong>{_esc(round(surf_reg.get("r2",0),2))}</strong>.</p>
{distance_svg}
<p>Pente distance : <strong>{_esc(round(dist_reg.get("slope",0),2))}</strong> €/m² par mètre · R² : <strong>{_esc(round(dist_reg.get("r2",0),2))}</strong>.</p>

<h2>7. DPE, état et caractéristiques qualitatives</h2>
<p>DPE retenu : <strong>{_esc(p.get("dpe",""))}</strong>. Conformément au principe retenu dans le support EVS 2025, aucune correction automatique de valeur n'est appliquée au seul classement DPE. Son incidence doit être démontrée par le marché et appréciée par l'expert. État retenu : <strong>{_esc(p.get("condition",""))}/10</strong>. Les autres corrections qualitatives sont explicitées séparément.</p>

<h2>8. Contrôle de cohérence EVS 2025</h2>
<p>Architecture du raisonnement : <strong>Approche → Méthode → Modèle → Jugement</strong>. L'approche principale retenue pour ce bien résidentiel est l'approche par le marché, mise en œuvre par comparaison directe pondérée. Les prix d'offre, lorsqu'ils seront intégrés au moteur de marché actif, ne devront servir que de repère ou de recoupement et devront être retraités.</p>
<p>Le contrôle final doit vérifier la cohérence entre la fourchette de prix au m², la valeur globale du segment, la qualité des comparables et les constatations de visite. Le recours à une autre méthode ne se justifie que si elle apporte une information pertinente et documentée.</p>

<h2>9. Synthèse et conclusion de valeur</h2>
<div class="callout"><strong>Valeur vénale centrale : {_euro(v.get("central"))}</strong><br>
Fourchette : {_euro(v.get("low"))} à {_euro(v.get("high"))}<br>
Prix de commercialisation indicatif : {_euro(v.get("listing"))}<br>
Scénario de vente rapide : {_euro(v.get("quick_sale"))}</div>

<h2>10. Sources et réserves</h2>
<p>Sources principales : DVF géolocalisé, géocodage IGN/Géoplateforme, données territoriales publiques et informations saisies lors de l’expertise. La conclusion doit être rapprochée des constatations de visite et des documents juridiques, techniques et urbanistiques.</p>
<p class="muted">Rapport généré uniquement à la demande depuis PUIG VALUE™.</p>
<button onclick="window.print()">Imprimer / enregistrer en PDF</button>
</body></html>'''
    return HTMLResponse(report_html)


@app.get("/api/valuations")
def valuations(limit: int = Query(default=20, ge=1, le=100)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id,created_at,address,result FROM valuations ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    out = []
    for r in rows:
        result = json.loads(r["result"])
        out.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "address": r["address"],
            "central": result["valuation"]["central"],
            "confidence": result["confidence"]["score"],
        })
    return out
