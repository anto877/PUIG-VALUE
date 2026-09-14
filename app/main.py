
from __future__ import annotations

import csv
import io
import json
import math
import os
import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("PUIG_DATA_DIR", BASE_DIR / "data"))
CACHE_DIR = DATA_DIR / "cache"
DB_PATH = DATA_DIR / "puig_value.sqlite3"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

GEOCODE_URL = "https://data.geopf.fr/geocodage/search"
DVF_BASE = "https://files.data.gouv.fr/geo-dvf/latest/csv"

app = FastAPI(title="PUIG VALUE", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")


class EstimateRequest(BaseModel):
    address: str = Field(min_length=3)
    property_type: str = Field(pattern="^(Maison|Appartement)$")
    surface: float = Field(gt=5, le=1500)
    land: float = Field(default=0, ge=0, le=100000)
    rooms: int = Field(default=0, ge=0, le=50)
    condition: int = Field(default=7, ge=1, le=10)
    dpe: str = Field(default="D", pattern="^[A-G]$")
    radius_m: int = Field(default=1000, ge=100, le=5000)
    surface_tolerance: float = Field(default=0.25, ge=0.05, le=0.75)
    pressure: int = Field(default=50, ge=0, le=100)
    expert_value: float | None = Field(default=None, gt=0)
    garage: bool = False
    micro_location: int = Field(default=7, ge=1, le=10)
    architecture: int = Field(default=7, ge=1, le=10)
    nuisance: int = Field(default=0, ge=0, le=3)
    years: list[int] = Field(default_factory=lambda: [2021, 2022, 2023, 2024, 2025])


def get_db():
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
    conn.commit()
    return conn


@app.get("/")
def home():
    return FileResponse(BASE_DIR / "app" / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "service": "PUIG VALUE WEB", "time": datetime.utcnow().isoformat() + "Z"}


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


def dept_from_insee(insee: str) -> str:
    if insee.startswith(("2A", "2B")):
        return insee[:2]
    return insee[:2]


async def ensure_dvf_file(year: int, citycode: str) -> Path:
    dept = dept_from_insee(citycode)
    local = CACHE_DIR / f"dvf_{year}_{citycode}.csv"
    if local.exists() and local.stat().st_size > 50:
        return local

    url = f"{DVF_BASE}/{year}/communes/{dept}/{citycode}.csv"
    timeout = httpx.Timeout(60.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url)
    if r.status_code == 404:
        raise FileNotFoundError(url)
    r.raise_for_status()
    local.write_bytes(r.content)
    return local


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


DPE_ADJ = {"A": 0.05, "B": 0.03, "C": 0.015, "D": 0.0, "E": -0.02, "F": -0.05, "G": -0.08}


def subject_quality_adjustment(req: EstimateRequest) -> dict[str, float]:
    # Coefficients V1.2 explicités et volontairement plafonnés.
    # Ils sont à recalibrer ultérieurement par apprentissage sur ventes réelles.
    condition = max(-0.125, min(0.075, (req.condition - 7) * 0.025))
    dpe = DPE_ADJ.get(req.dpe, 0.0)
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
        same_building = bool(subject_addr and sale_addr and (
            sale_addr in subject_addr or subject_addr in sale_addr
        ))
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

    # Hiérarchie stricte des comparables.
    if req.property_type == "Appartement":
        tier1 = [c for c in candidates if c["same_building"]]
        tier2 = [c for c in candidates if c["same_street"] and c["distance"] <= 250]
        tier3 = [c for c in candidates if c["distance"] <= 350]
        tier4 = [c for c in candidates if c["distance"] <= 600]
        tiers = [tier1, tier2, tier3, tier4]
        target_n = 10
    else:
        tier1 = [c for c in candidates if c["distance"] <= 300]
        tier2 = [c for c in candidates if c["distance"] <= 500]
        tier3 = [c for c in candidates if c["distance"] <= 750]
        tier4 = [c for c in candidates if c["distance"] <= min(req.radius_m, 1000)]
        tiers = [tier1, tier2, tier3, tier4]
        target_n = 12

    selected = []
    seen = set()
    effective_radius = 0
    for tier in tiers:
        tier = sorted(tier, key=lambda x: x["score"], reverse=True)
        for c in tier:
            if c["score"] < 60 or c["id_mutation"] in seen:
                continue
            seen.add(c["id_mutation"])
            selected.append(c)
            effective_radius = max(effective_radius, c["distance"])
            if len(selected) >= target_n:
                break
        if len(selected) >= 5:
            break

    # En dernier recours seulement : rayon élargi mais plafonné à 1 km.
    if len(selected) < 5:
        fallback = sorted([c for c in candidates if c["distance"] <= min(req.radius_m, 1000) and c["score"] >= 60],
                          key=lambda x: x["score"], reverse=True)
        for c in fallback:
            if c["id_mutation"] in seen:
                continue
            seen.add(c["id_mutation"]); selected.append(c)
            effective_radius = max(effective_radius, c["distance"])
            if len(selected) >= target_n:
                break

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
    if med_age and med_age > 36: alerts.append("Références relativement anciennes.")
    if not req.expert_value: alerts.append("Valeur non encore validée par l'expert après visite.")

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
            "selection_method": "Même immeuble/rue prioritaire pour appartements ; 300 m prioritaire pour maisons ; élargissement progressif et plafonné.",
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
        "comparables": selected,
    }

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO valuations(created_at,address,payload,result) VALUES(?,?,?,?)",
            (datetime.utcnow().isoformat()+"Z", req.address, req.model_dump_json(), json.dumps(result, ensure_ascii=False))
        )
        conn.commit()
        result["valuation_id"] = cur.lastrowid

    return result


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
