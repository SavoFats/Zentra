from __future__ import annotations

import asyncio
import binascii
import os
import re
import time
import websockets
import math
import hashlib
import json
import secrets
import stripe
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, Response, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import httpx
import uvicorn
import asyncpg
import bcrypt
from cryptography.fernet import Fernet
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

import sys
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "").strip()
if not _raw_origins or _raw_origins == "*":
    print("⚠️  WARNING: ALLOWED_ORIGINS non impostata o wildcard. Imposta il dominio Vercel in produzione.", file=sys.stderr)
    _ORIGIN_SET: set[str] = set()
    _ORIGINS_ANY = True
else:
    _ORIGIN_SET = {o.strip().rstrip("/") for o in _raw_origins.split(",") if o.strip()}
    _ORIGINS_ANY = False
    print(f"[CORS] origini consentite: {_ORIGIN_SET}", file=sys.stderr)

_CORS_METHODS = "GET, POST, PATCH, DELETE, OPTIONS"
_CORS_HEADERS = "Authorization, Content-Type"

def _url_origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}".rstrip("/")

def is_allowed_redirect_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not parts.netloc:
        return False
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1"):
        return False
    if _ORIGINS_ANY:
        return True
    return _url_origin(url) in _ORIGIN_SET

def with_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")
    allowed = _ORIGINS_ANY or (origin in _ORIGIN_SET)

    if request.method == "OPTIONS":
        resp = Response(status_code=204)
        if allowed and origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Methods"] = _CORS_METHODS
            resp.headers["Access-Control-Allow-Headers"] = _CORS_HEADERS
            resp.headers["Access-Control-Max-Age"] = "0"
            resp.headers["Vary"] = "Origin"
        return resp

    response = await call_next(request)
    if allowed and origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response

DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable non impostata — il server non può partire in modo sicuro")

STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID       = os.environ.get("STRIPE_PRICE_ID", "")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
ENABLE_DEBUG_REVX = os.environ.get("ENABLE_DEBUG_REVX", "").lower() in ("1", "true", "yes")
ENABLE_RESTORE_DEBUG = os.environ.get("ENABLE_RESTORE_DEBUG", "").lower() in ("1", "true", "yes")

def restore_debug_log(msg: str):
    if ENABLE_RESTORE_DEBUG:
        print(msg)

# ── FREE PLAN LIMITS ──────────────────────────────────────────────────────────
FREE_SESSIONS_PER_DAY  = 1
FREE_MAX_SESSION_HOURS = 2
FREE_MAX_POSITIONS     = 1
FREE_ALLOC_PCT         = 1.0    # allocazione fissa 100% — 1 posizione = tutto il capitale sessione
FREE_RSI_MIN           = 35.0
FREE_RSI_MAX           = 65.0

# ── ENCRYPTION (chiavi API) ───────────────────────────────────────────────────
def _get_fernet() -> Fernet:
    import base64, hashlib
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_key(text: str) -> str:
    """Cifra una stringa sensibile prima di salvarla nel DB."""
    if not text:
        return ""
    return _get_fernet().encrypt(text.encode()).decode()

def decrypt_key(text: str) -> str:
    """Decifra una stringa recuperata dal DB."""
    if not text:
        return ""
    try:
        return _get_fernet().decrypt(text.encode()).decode()
    except Exception:
        # Fallback per valori legacy non cifrati — logga in modo da poterli rilevare
        if len(text) > 8:
            print(f"[DECRYPT] warning: valore non cifrato nel DB (len={len(text)}, prefix={text[:4]}...)")
        return text

def sanitize_error(e: Exception, *secrets: str) -> str:
    """Rimuove stringhe sensibili dal messaggio di errore prima di loggarlo."""
    msg = str(e)
    for secret in secrets:
        if secret and len(secret) > 4:
            msg = msg.replace(secret, "[REDACTED]")
    return msg

def public_error(e: Exception, *secrets: str, max_len: int = 240) -> str:
    msg = sanitize_error(e, *secrets)
    msg = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[REDACTED PEM]", msg, flags=re.DOTALL)
    msg = re.sub(r"(?i)(api[_ -]?key|private[_ -]?key|secret|token)(['\":= ]+)([^\s,'\"}]+)", r"\1\2[REDACTED]", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:max_len] + ("..." if len(msg) > max_len else "")

db_pool = None

async def get_db():
    return db_pool

def create_token(user_id: int) -> str:
    import base64, hmac as _hmac
    payload = f"{user_id}:{int(time.time()) + 86400 * 30}"
    sig = _hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(token: str) -> int:
    import base64, hmac as _hmac
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split(":")
        if len(parts) != 3:
            raise ValueError("invalid token parts")
        user_id, expires, sig = int(parts[0]), int(parts[1]), parts[2]
        if int(time.time()) > expires:
            raise HTTPException(status_code=401, detail="Token scaduto")
        if token in _revoked_tokens:
            raise HTTPException(status_code=401, detail="Token revocato")
        payload = f"{user_id}:{expires}"
        expected = _hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=401, detail="Token non valido")
        return user_id
    except (HTTPException, ValueError, IndexError, AttributeError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(status_code=401, detail="Token non valido")

async def get_current_user(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Non autenticato")
    return verify_token(auth[7:])

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

BINANCE_BASE    = "https://api.binance.com"
BINANCE_US_BASE = "https://api.binance.us"

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# codici temporanei per il linking Telegram: code -> (user_id, expiry_timestamp)
_tg_link_codes: dict[str, tuple[int, float]] = {}
_tg_bot_username: str = ""  # caricato all'avvio via getMe
_cg_logos: dict[str, str] = {}  # symbol -> image_url, caricato da CoinGecko markets API

async def send_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}
            )
    except Exception as e:
        print(f"Telegram error: {e}")

async def send_telegram_to(chat_id: str, msg: str):
    """Invia un messaggio Telegram a uno specifico chat_id."""
    if not TELEGRAM_TOKEN or not chat_id:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}
            )
    except Exception as e:
        print(f"Telegram error (to {chat_id}): {e}")

async def notify(state: dict, msg: str):
    """Invia notifica Telegram all'utente: usa il suo chat_id personale se collegato,
    altrimenti cade sul TELEGRAM_CHAT_ID globale con prefisso username."""
    tg_chat = state.get("telegram_chat_id", "")
    if tg_chat:
        await send_telegram_to(tg_chat, msg)
    else:
        username = state.get("username", "")
        prefix = f"[{username}] " if username else ""
        await send_telegram(prefix + msg)


def make_revx_signature(api_key_id: str, private_key_pem: str, method: str, path: str, query: str = "", body: str = "") -> dict:
    """Genera gli header di autenticazione per Revolut X (Ed25519)."""
    import base64
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    timestamp = str(int(time.time() * 1000))
    message = f"{timestamp}{method}{path}{query}{body}".encode('utf-8')
    private_key = load_pem_private_key(private_key_pem.encode(), password=None)
    signature = base64.b64encode(private_key.sign(message)).decode()
    return {
        "X-Revx-API-Key": api_key_id,
        "X-Revx-Timestamp": timestamp,
        "X-Revx-Signature": signature,
        "Content-Type": "application/json",
    }

REVX_BASE = "https://revx.revolut.com"

_eur_usd_rate: float = 1.08  # tasso di fallback
_eur_usd_last_update: float = 0.0

async def get_eur_usd_rate() -> float:
    """Recupera tasso EUR/USD da API pubblica. Aggiorna ogni 5 minuti."""
    global _eur_usd_rate, _eur_usd_last_update
    import time as _time
    if _time.time() - _eur_usd_last_update < 300:
        return _eur_usd_rate
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get("https://api.frankfurter.app/latest?from=EUR&to=USD")
            data = r.json()
            rate = float(data["rates"]["USD"])
            _eur_usd_rate = rate
            _eur_usd_last_update = _time.time()
            print(f"[EUR/USD] tasso aggiornato: {rate}")
    except Exception as e:
        print(f"[EUR/USD] errore: {e}, uso fallback {_eur_usd_rate}")
    return _eur_usd_rate

async def revx_request(method: str, path: str, body: dict = None,
                        key_id: str = None, private_key: str = None,
                        params: dict = None) -> dict:
    """Esegue una richiesta autenticata a Revolut X con retry su 429."""
    from urllib.parse import urlsplit, urlencode
    body_str = json.dumps(body, separators=(',', ':')) if body else ""
    parsed = urlsplit(path)
    clean_path = parsed.path
    if params:
        query_str = urlencode(params)
    elif parsed.query:
        query_str = parsed.query
    else:
        query_str = ""
    headers = make_revx_signature(key_id, private_key, method, clean_path, query_str, body_str)
    backoff = 2
    for attempt in range(4):
        async with httpx.AsyncClient(timeout=30) as client:
            if method == "GET":
                r = await client.get(f"{REVX_BASE}{path}", headers=headers, params=params or {})
            elif method == "DELETE":
                r = await client.delete(f"{REVX_BASE}{path}", headers=headers)
            else:
                r = await client.post(f"{REVX_BASE}{path}", headers=headers, content=body_str)
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", backoff))
            print(f"[RevX] 429 rate limit su {path} — attesa {retry_after}s (tentativo {attempt+1}/4)")
            await asyncio.sleep(retry_after)
            backoff = min(backoff * 2, 30)
            continue
        if r.status_code >= 500:
            print(f"[RevX] {r.status_code} server error su {path} — attesa {backoff}s (tentativo {attempt+1}/4)")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        if r.status_code >= 400:
            try:
                err_payload = r.json()
            except Exception:
                err_payload = r.text[:500]
            raise Exception(f"RevX {method} {path} HTTP {r.status_code}: {err_payload}")
        try:
            return r.json() if r.content else {"ok": True}
        except Exception as e:
            raise Exception(f"RevX {method} {path} risposta JSON non valida: {e}")
    raise Exception(f"RevX {method} {path} fallito dopo 4 tentativi")

COINBASE_BASE = "https://api.coinbase.com"
COINBASE_HOST = "api.coinbase.com"

def normalize_coinbase_api_secret(api_secret: str) -> str:
    """Normalizza private key Coinbase copiate con newline escapati."""
    secret = (api_secret or "").strip()
    if "\\n" in secret and "\n" not in secret:
        secret = secret.replace("\\n", "\n")
    return secret

def coinbase_jwt_uri(method: str, path: str) -> str:
    from urllib.parse import urlsplit
    clean_path = urlsplit(path).path
    return f"{method.upper()} {COINBASE_HOST}{clean_path}"

def make_coinbase_jwt(api_key: str, api_secret: str, method: str, path: str) -> str:
    """Genera JWT Coinbase Advanced Trade (ES256) per una singola richiesta."""
    import jwt
    import secrets
    from cryptography.hazmat.primitives import serialization
    now = int(time.time())
    uri = coinbase_jwt_uri(method, path)
    api_secret = normalize_coinbase_api_secret(api_secret)
    private_key = serialization.load_pem_private_key(api_secret.encode("utf-8"), password=None)
    payload = {
        "sub": api_key,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,
        "uri": uri,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"kid": api_key, "nonce": secrets.token_hex(16)},
    )

async def coinbase_request(method: str, path: str, body: dict = None,
                           api_key: str = "", api_secret: str = "") -> dict:
    """Esegue una richiesta autenticata a Coinbase Advanced Trade."""
    method = method.upper()
    token = make_coinbase_jwt(api_key, api_secret, method, path)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            r = await client.get(f"{COINBASE_BASE}{path}", headers=headers)
        elif method == "DELETE":
            r = await client.delete(f"{COINBASE_BASE}{path}", headers=headers)
        else:
            r = await client.post(f"{COINBASE_BASE}{path}", headers=headers, json=body or {})
    if r.status_code >= 400:
        try:
            err_payload = r.json()
        except Exception:
            err_payload = r.text[:500]
        raise Exception(f"Coinbase {method} {path} HTTP {r.status_code}: {err_payload}")
    try:
        return r.json() if r.content else {"ok": True}
    except Exception as e:
        raise Exception(f"Coinbase {method} {path} risposta JSON non valida: {e}")

def parse_coinbase_accounts(result: object) -> list:
    accounts = result.get("accounts") if isinstance(result, dict) else None
    if not isinstance(accounts, list):
        raise ValueError("Formato accounts Coinbase non riconosciuto")
    parsed = []
    for acc in accounts:
        if not isinstance(acc, dict):
            continue
        bal = acc.get("available_balance") or {}
        value = bal.get("value") if isinstance(bal, dict) else None
        currency = bal.get("currency") if isinstance(bal, dict) else acc.get("currency", "")
        try:
            amount = float(value or 0)
        except Exception:
            amount = 0.0
        parsed.append({
            "currency": currency or acc.get("currency", ""),
            "available": amount,
            "name": acc.get("name", ""),
            "active": bool(acc.get("active", False)),
            "ready": bool(acc.get("ready", False)),
        })
    return parsed

async def fetch_coinbase_accounts(api_key: str, api_secret: str, limit: int = 250, max_pages: int = 5) -> list:
    accounts = []
    cursor = ""
    for _ in range(max_pages):
        path = f"/api/v3/brokerage/accounts?limit={limit}"
        if cursor:
            path += f"&cursor={cursor}"
        result = await coinbase_request("GET", path, api_key=api_key, api_secret=api_secret)
        accounts.extend(parse_coinbase_accounts(result))
        if not isinstance(result, dict) or not result.get("has_next"):
            break
        cursor = result.get("cursor") or ""
        if not cursor:
            break
    return accounts

async def get_coinbase_product_price(product_id: str, api_key: str, api_secret: str) -> float:
    product = await coinbase_request(
        "GET", f"/api/v3/brokerage/products/{product_id}",
        api_key=api_key, api_secret=api_secret
    )
    for key in ("price", "mid_market_price"):
        try:
            price = float(product.get(key) or 0)
        except Exception:
            price = 0.0
        if price > 0:
            return price
    raise ValueError(f"Prezzo Coinbase non disponibile per {product_id}")

def build_coinbase_preflight(accounts: list, product: dict, amount_usd: float) -> dict:
    if not isinstance(product, dict):
        raise ValueError("Formato prodotto Coinbase non riconosciuto")
    product_id = product.get("product_id", "")
    quote = product.get("quote_currency_id") or product.get("quote_display_symbol") or "USD"
    try:
        quote_min_size = float(product.get("quote_min_size") or 0)
    except Exception:
        quote_min_size = 0.0
    try:
        price = float(product.get("price") or product.get("mid_market_price") or 0)
    except Exception:
        price = 0.0
    quote_balances = {
        a.get("currency"): float(a.get("available") or 0)
        for a in accounts
        if a.get("currency") in ("USD", "USDC", "EUR")
    }
    available = 0.0
    for acc in accounts:
        if acc.get("currency") == quote:
            available += float(acc.get("available") or 0)
    blockers = []
    if product.get("is_disabled") or product.get("trading_disabled"):
        blockers.append("trading_disabled")
    if product.get("cancel_only"):
        blockers.append("cancel_only")
    if product.get("post_only"):
        blockers.append("post_only")
    if product.get("limit_only"):
        blockers.append("limit_only")
    if quote_min_size and amount_usd < quote_min_size:
        blockers.append("below_min_order")
    if available < amount_usd:
        blockers.append("insufficient_quote_balance")
    return {
        "ok": not blockers,
        "product_id": product_id,
        "quote_currency": quote,
        "available_quote": available,
        "quote_balances": quote_balances,
        "required_quote": amount_usd,
        "quote_min_size": quote_min_size,
        "price": price,
        "status": product.get("status", ""),
        "blockers": blockers,
    }

def extract_coinbase_order_id(result: object) -> str:
    if not isinstance(result, dict):
        return ""
    success_response = result.get("success_response") if isinstance(result.get("success_response"), dict) else {}
    order_configuration = result.get("order_configuration") if isinstance(result.get("order_configuration"), dict) else {}
    candidates = (
        result.get("order_id"),
        result.get("id"),
        success_response.get("order_id"),
        success_response.get("id"),
        order_configuration.get("order_id"),
    )
    return next((str(c) for c in candidates if c), "")

def summarize_coinbase_order(order_result: object) -> dict:
    order = order_result.get("order") if isinstance(order_result, dict) else {}
    if not isinstance(order, dict):
        order = {}
    return {
        "order_id": order.get("order_id") or order.get("id", ""),
        "status": order.get("status") or order.get("order_status", ""),
        "product_id": order.get("product_id", ""),
        "side": order.get("side", ""),
        "completion_percentage": order.get("completion_percentage", ""),
        "filled_size": order.get("filled_size", ""),
        "average_filled_price": order.get("average_filled_price", ""),
        "total_fees": order.get("total_fees", ""),
    }

async def wait_coinbase_order_fill(order_id: str, api_key: str, api_secret: str,
                                   attempts: int = 6, delay: float = 1.0) -> dict:
    """Attende un fill Coinbase prima di creare o chiudere posizioni reali."""
    last: dict = {}
    for _ in range(attempts):
        details = await coinbase_request(
            "GET", f"/api/v3/brokerage/orders/historical/{order_id}",
            api_key=api_key, api_secret=api_secret
        )
        last = summarize_coinbase_order(details)
        try:
            filled_size = float(last.get("filled_size") or 0)
            avg_price = float(last.get("average_filled_price") or 0)
        except Exception:
            filled_size = 0.0
            avg_price = 0.0
        status = str(last.get("status") or "").upper()
        if filled_size > 0 and avg_price > 0 and status in ("FILLED", "DONE", "SETTLED"):
            return last
        if status in ("CANCELLED", "REJECTED", "EXPIRED", "FAILED"):
            return last
        await asyncio.sleep(delay)
    return last


async def get_revx_order_details(order_id: str, key_id: str, private_key: str) -> dict:
    """GET /api/1.0/orders/{id} — ritorna prezzi e fee reali del fill."""
    try:
        await asyncio.sleep(1)
        result = await revx_request("GET", f"/api/1.0/orders/{order_id}", key_id=key_id, private_key=private_key)
        d = result.get("data") or result
        return {
            "state":               (d.get("status") or d.get("state") or "").lower(),
            "average_fill_price": float(d.get("average_fill_price") or 0),
            "filled_quantity":    float(d.get("filled_quantity") or 0),
            "filled_amount":      float(d.get("filled_amount") or 0),
            "total_fee":          float(d.get("total_fee") or 0),
            "fee_currency":       d.get("fee_currency", "USD"),
        }
    except Exception as e:
        print(f"[REVX ORDER DETAILS] errore per {order_id}: {e}")
        return {}


async def wait_revx_order_fill(order_id: str, key_id: str, private_key: str,
                               attempts: int = 6, delay: float = 1.0) -> dict:
    """Attende un fill RevX prima di aggiornare lo stato interno."""
    last: dict = {}
    for _ in range(attempts):
        last = await get_revx_order_details(order_id, key_id, private_key)
        state = last.get("state", "")
        if last.get("average_fill_price", 0) > 0 and last.get("filled_quantity", 0) > 0:
            return last
        if state in ("cancelled", "rejected", "expired", "failed"):
            return last
        await asyncio.sleep(delay)
    return last

# ── market data ───────────────────────────────────────────────────────────────

market_data = {}  # sym -> {price, change1h, change24h, volume24h, icon}
user_sessions: dict = {}
_sessions_starting: set = set()  # user_id in avvio, evita doppi /start concorrenti
_revoked_tokens: set = set()     # token revocati al logout

# ── CANDLE DATA (nuovo) ───────────────────────────────────────────────────────
# sym -> {
#   "ema20_5m": float, "ema50_5m": float,
#   "ema20_15m": float, "ema50_15m": float,
#   "last_close_5m": float,
#   "updated_at": float (timestamp)
# }
candle_data: dict = {}
_candles_last_update: float = 0
CANDLE_UPDATE_INTERVAL = 60    # secondi (1 minuto)

scanner_candle_data: dict = {}   # {tf: {sym: signal_indicators}}
_scanner_candles_ts:  dict = {}   # {tf: last_update_timestamp}
SCANNER_CACHE_TTL   = 60          # secondi — invalida cache scanner per TF non-default
VALID_TF = {"5m", "15m", "1h", "4h", "1d"}
CANDLE_UNIVERSE_SIZE   = 50    # top N coin per volume (dinamico)
COIN_WHITELIST = {"BTC","ETH","SOL","BNB","XRP","DOGE","ADA","AVAX","SUI","TON","LINK","DOT"}  # fallback iniziale

_dynamic_universe: set = set(COIN_WHITELIST)  # aggiornato ogni 30 min
_universe_last_update: float = 0
UNIVERSE_UPDATE_INTERVAL = 1800  # 30 minuti

_ws_connected: bool = False  # True quando il WebSocket Binance è attivo

_cg_price_last_fetch: float = 0  # throttle fallback CoinGecko prezzi
_ws_last_msg_ts: float = 0       # timestamp ultimo messaggio ricevuto dal WebSocket
_rest_price_last_fetch: float = 0  # throttle fetch REST periodico prezzi

def calc_ema(prices: list, period: int) -> float:
    """Calcola EMA su una lista di prezzi (close). Restituisce l'ultimo valore."""
    if len(prices) < period:
        return 0.0
    k = 2 / (period + 1)
    ema = sum(prices[:period]) / period  # SMA iniziale
    for price in prices[period:]:
        ema = price * k + ema * (1 - k)
    return ema

def calc_ema_list(data: list, period: int) -> list:
    """Calcola EMA su una serie e restituisce tutti i valori (non solo l'ultimo)."""
    if len(data) < period:
        return [0.0] * len(data)
    k = 2 / (period + 1)
    ema = sum(data[:period]) / period
    result = [ema]
    for price in data[period:]:
        ema = price * k + ema * (1 - k)
        result.append(ema)
    return result

def calc_rsi(prices: list, period: int = 14) -> float:
    """Calcola RSI su una lista di prezzi close. Restituisce l'ultimo valore (0-100)."""
    if len(prices) < period + 1:
        return 50.0  # neutro se dati insufficienti
    deltas = [prices[i] - prices[i-1] for i in range(1, len(prices))]
    gains  = [d if d > 0 else 0.0 for d in deltas]
    losses = [-d if d < 0 else 0.0 for d in deltas]
    avg_gain = sum(gains[:period]) / period
    avg_loss = sum(losses[:period]) / period
    for i in range(period, len(deltas)):
        avg_gain = (avg_gain * (period - 1) + gains[i]) / period
        avg_loss = (avg_loss * (period - 1) + losses[i]) / period
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return round(100 - (100 / (1 + rs)), 2)

LEVERAGED_KEYWORDS = {"UP", "DOWN", "BULL", "BEAR", "3L", "3S", "2L", "2S"}

async def fetch_dynamic_universe():
    """Scarica top-50 coin per volume 24h da Binance. Aggiorna _dynamic_universe."""
    global _dynamic_universe, _universe_last_update
    try:
        r = None
        async with httpx.AsyncClient(timeout=10) as client:
            for base in (BINANCE_BASE, BINANCE_US_BASE):
                r = await client.get(f"{base}/api/v3/ticker/24hr")
                if r.status_code != 451:
                    break
        if r is None or r.status_code != 200:
            return
        tickers = r.json()
        candidates = []
        for t in tickers:
            sym_pair = t.get("symbol", "")
            if not sym_pair.endswith("USDT"):
                continue
            sym = sym_pair[:-4]
            if sym in STABLES:
                continue
            if any(kw in sym for kw in LEVERAGED_KEYWORDS):
                continue
            vol = float(t.get("quoteVolume", 0))
            if not _revx_pairs and vol < 10_000_000:
                continue
            candidates.append((sym, vol))
        candidates.sort(key=lambda x: x[1], reverse=True)
        candidate_syms = {sym for sym, _ in candidates}
        # Base: top N per volume — valido per tutti gli exchange (Coinbase, RevX, sim).
        # Il filtro RevX-specifico viene applicato per-sessione nel loop agente.
        base_universe = {sym for sym, _ in candidates[:CANDLE_UNIVERSE_SIZE]}
        # Aggiungi anche le coin RevX non in top-N per garantire copertura sessioni RevX
        revx_extra = (_revx_pairs & candidate_syms) if _revx_pairs else set()
        new_universe = base_universe | revx_extra
        if new_universe:
            _dynamic_universe = new_universe
            _universe_last_update = time.time()
            print(f"Universo dinamico: {len(_dynamic_universe)} coin (base={len(base_universe)}, revx_extra={len(revx_extra)})")
    except Exception as e:
        print(f"Errore fetch universo dinamico: {e}")

async def fetch_candles_for_symbol(sym: str, client: httpx.AsyncClient) -> dict | None:
    """Scarica candele 5min, 15min e 1h da Binance. Calcola EMA20/50, RSI14, ATR."""
    pair = f"{sym}USDT"
    try:
        for base in (BINANCE_BASE, BINANCE_US_BASE):
            r5, r15, r1h = await asyncio.gather(
                client.get(f"{base}/api/v3/klines", params={"symbol": pair, "interval": "5m",  "limit": 150}),
                client.get(f"{base}/api/v3/klines", params={"symbol": pair, "interval": "15m", "limit": 150}),
                client.get(f"{base}/api/v3/klines", params={"symbol": pair, "interval": "1h",  "limit": 250}),
            )
            if r5.status_code == 451:
                continue  # prova Binance US
            if r5.status_code != 200 or r15.status_code != 200 or r1h.status_code != 200:
                return None
            break
        else:
            return None

        klines5  = r5.json()
        klines15 = r15.json()
        klines1h = r1h.json()

        if not isinstance(klines5, list) or not isinstance(klines15, list) or not isinstance(klines1h, list):
            return None
        if len(klines5) < 100 or len(klines15) < 100 or len(klines1h) < 200:
            return None

        closes5  = [float(k[4]) for k in klines5]
        closes15 = [float(k[4]) for k in klines15]
        closes1h = [float(k[4]) for k in klines1h]
        volumes5 = [float(k[5]) for k in klines5]
        highs5   = [float(k[2]) for k in klines5]
        lows5    = [float(k[3]) for k in klines5]

        # ATR 5m: media True Range sugli ultimi 14 periodi
        trs = []
        for i in range(1, len(klines5)):
            h = float(klines5[i][2])
            l = float(klines5[i][3])
            pc = float(klines5[i-1][4])
            trs.append(max(h - l, abs(h - pc), abs(l - pc)))
        atr_5m = sum(trs[-14:]) / 14 if len(trs) >= 14 else 0.0

        # ATR 15m: short (6 candele = 90 min) e long (20 candele = 5h)
        highs15 = [float(k[2]) for k in klines15]
        lows15   = [float(k[3]) for k in klines15]
        trs15 = []
        for i in range(1, len(klines15)):
            h = highs15[i]; l = lows15[i]; pc = closes15[i-1]
            trs15.append(max(h - l, abs(h - pc), abs(l - pc)))
        atr_15m_long  = sum(trs15[-21:-1]) / 20 if len(trs15) >= 21 else 0.0
        atr_15m_short = sum(trs15[-7:-1])  / 6  if len(trs15) >= 7  else 0.0

        # Minimo delle ultime 3 candele CHIUSE (escludi candela corrente aperta)
        pullback_low_5m = min(lows5[-4:-1]) if len(lows5) >= 4 else lows5[-2]

        # Prezzo chiuso 10 candele fa (50 min fa) — usato per calcolo momentum %
        close_10_ago = closes5[-11] if len(closes5) >= 11 else closes5[0]

        # Volume: usa solo candele chiuse ([-2] = ultima chiusa, [-21:-1] = 20 chiuse)
        vol_avg_20 = sum(volumes5[-21:-1]) / 20 if len(volumes5) >= 21 else 0.0
        vol_last   = volumes5[-2] if len(volumes5) >= 2 else 0.0

        # RSI(14) su 5m (su candele chiuse)
        rsi_14 = calc_rsi(closes5[:-1], 14)
        # RSI(14) su 1h (su candele chiuse) — usato per rsi_oversold
        rsi_1h = calc_rsi(closes1h[:-1], 14)

        # Corpo dell'ultima candela CHIUSA (klines5[-2], non la corrente aperta [-1])
        last_candle  = klines5[-2]
        last_open    = float(last_candle[1])
        last_close_c = float(last_candle[4])
        last_high    = float(last_candle[2])
        last_low_c   = float(last_candle[3])
        candle_range = last_high - last_low_c
        candle_body  = last_close_c - last_open  # positivo = verde
        body_ratio   = abs(candle_body) / candle_range if candle_range > 0 else 0.0

        # Slope EMA20: confronta EMA20 attuale con EMA20 di 3 candele fa
        ema20_5m_cur   = calc_ema(closes5[:-1], 20)   # su candele chiuse
        ema20_5m_prev3 = calc_ema(closes5[:-4], 20)   # EMA20 di 3 candele fa

        # Slope EMA20 su 1h: confronta EMA20 attuale con EMA20 di 3 ore fa
        ema20_1h_cur   = calc_ema(closes1h[:-1], 20)
        ema20_1h_prev3 = calc_ema(closes1h[:-4], 20)  # EMA20 di 3 ore fa

        # Crossover 15m: EMA20 e EMA50 di 6 candele fa (90 min) per rilevare incrocio fresco
        ema20_15m_prev3 = calc_ema(closes15[:-7], 20)
        ema50_15m_prev3 = calc_ema(closes15[:-7], 50)

        # Choppiness Index(14) su candele chiuse
        chop_n = 14
        atr_sum_chop = sum(trs[-chop_n:]) if len(trs) >= chop_n else sum(trs)
        hh_chop = max(highs5[-chop_n-1:-1]) if len(highs5) >= chop_n+1 else max(highs5)
        ll_chop = min(lows5[-chop_n-1:-1])  if len(lows5)  >= chop_n+1 else min(lows5)
        chop_range = hh_chop - ll_chop
        chop_14 = round(100 * math.log10(atr_sum_chop / chop_range) / math.log10(chop_n), 2) if chop_range > 0 and atr_sum_chop > 0 else 50.0

        # Keltner Channel upper band: EMA20 + 2×ATR
        keltner_upper = ema20_5m_cur + 2 * atr_5m

        # TSI(25, 13) su 15m e 1h — confluenza + slope per tsi_bullish
        def _calc_tsi(closes):
            pc     = [closes[i] - closes[i-1] for i in range(1, len(closes))]
            abs_pc = [abs(x) for x in pc]
            e1     = calc_ema_list(pc, 25)
            e2     = calc_ema_list(e1, 13)
            a1     = calc_ema_list(abs_pc, 25)
            a2     = calc_ema_list(a1, 13)
            if not a2 or len(a2) < 2:
                return 0.0, 0.0
            cur  = round(100 * e2[-1]  / a2[-1],  2) if a2[-1]  != 0 else 0.0
            prev = round(100 * e2[-2]  / a2[-2],  2) if a2[-2]  != 0 else 0.0
            return cur, prev

        closed5              = closes5[:-1]
        tsi,      _          = _calc_tsi(closed5)   # mantenuto per compatibilità segnale bot
        tsi_15m,  tsi_15m_p  = _calc_tsi(closes15[:-1])
        tsi_1h,   tsi_1h_p   = _calc_tsi(closes1h[:-1])

        # MACD(5, 13, 3) su candele chiuse
        ema5_list  = calc_ema_list(closed5, 5)
        ema13_list = calc_ema_list(closed5, 13)
        off1 = len(ema5_list) - len(ema13_list)
        macd_line   = [ema5_list[off1 + i] - ema13_list[i] for i in range(len(ema13_list))]
        signal_list = calc_ema_list(macd_line, 3)
        off2 = len(macd_line) - len(signal_list)
        hist_list   = [macd_line[off2 + i] - signal_list[i] for i in range(len(signal_list))]
        macd_hist      = hist_list[-1] if hist_list else 0.0
        macd_hist_prev = hist_list[-2] if len(hist_list) >= 2 else 0.0

        # Golden Cross / Death Cross: EMA50 vs EMA200 su 1h (definizione classica), crossover nelle ultime 24 ore
        ema50_1h_cur     = calc_ema(closes1h[:-1], 50)
        ema200_1h_cur    = calc_ema(closes1h[:-1], 200)
        ema50_1h_prev24  = calc_ema(closes1h[:-25], 50)
        ema200_1h_prev24 = calc_ema(closes1h[:-25], 200)
        golden_cross     = (ema50_1h_cur > ema200_1h_cur) and (ema50_1h_prev24 <= ema200_1h_prev24)
        death_cross      = (ema50_1h_cur < ema200_1h_cur) and (ema50_1h_prev24 >= ema200_1h_prev24)
        # RSI: entrambi su 1h per coerenza (5m è troppo rumoroso per overbought)
        rsi_oversold   = rsi_1h < 30.0
        rsi_overbought = rsi_1h > 70.0

        return {
            "ema20_5m":          ema20_5m_cur,
            "ema50_5m":          calc_ema(closes5[:-1], 50),
            "ema20_15m":         calc_ema(closes15[:-1], 20),
            "ema50_15m":         calc_ema(closes15[:-1], 50),
            "ema20_15m_prev3":   ema20_15m_prev3,
            "ema50_15m_prev3":   ema50_15m_prev3,
            "ema20_1h":          ema20_1h_cur,
            "ema50_1h":          ema50_1h_cur,
            "ema20_1h_prev3":    ema20_1h_prev3,
            "last_close_5m":    closes5[-2],   # ultimo close CONFERMATO (candela chiusa)
            "close_1h_ago":     closes1h[-2] if len(closes1h) >= 2 else 0.0,
            "atr_5m":           atr_5m,
            "pullback_low_5m":  pullback_low_5m,
            "vol_avg_20":       vol_avg_20,
            "vol_last":         vol_last,
            "rsi_14":           rsi_14,
            "rsi_1h":           rsi_1h,
            "candle_body":      candle_body,
            "body_ratio":       body_ratio,
            "ema20_5m_prev3":   ema20_5m_prev3,
            "atr_15m_long":     atr_15m_long,
            "atr_15m_short":    atr_15m_short,
            "close_10_ago":     close_10_ago,
            "close_3_ago":      closes5[-5] if len(closes5) >= 5 else closes5[0],
            "upper_wick_ratio": (last_high - max(last_close_c, last_open)) / candle_range if candle_range > 0 else 0.0,
            "chop_14":          chop_14,
            "keltner_upper":    keltner_upper,
            "tsi":              tsi,
            "tsi_15m":          tsi_15m,
            "tsi_15m_prev":     tsi_15m_p,
            "tsi_1h":           tsi_1h,
            "tsi_1h_prev":      tsi_1h_p,
            "macd_hist":        macd_hist,
            "macd_hist_prev":   macd_hist_prev,
            "golden_cross":     golden_cross,
            "death_cross":      death_cross,
            "rsi_oversold":     rsi_oversold,
            "rsi_overbought":   rsi_overbought,
            "sparkline":        closes1h[-25:-1],
            "updated_at":       time.time(),
            # ── consolidation breakout ────────────────────────────────────────
            "atr_avg_30":       sum(trs[-31:-1]) / 30 if len(trs) >= 31 else atr_5m,
            "range_high_60":    max(highs5[-63:-3]) if len(highs5) >= 63 else max(highs5[:-2]),
            "range_low_60":     min(lows5[-63:-3])  if len(lows5)  >= 63 else min(lows5[:-2]),
            "close_7_ago":      closes5[-9] if len(closes5) >= 9 else closes5[0],
            "chop_long": round(
                100 * math.log10(
                    (sum(trs[-37:-1]) if len(trs) >= 37 else sum(trs)) /
                    ((max(highs5[-39:-1]) - min(lows5[-39:-1])) if len(highs5) >= 39 else (max(highs5) - min(lows5)))
                ) / math.log10(36), 2
            ) if len(trs) >= 36 and (max(highs5[-39:-1]) - min(lows5[-39:-1])) > 0 else 50.0,
        }
    except Exception as e:
        print(f"Candle error {sym}: {e}")
        return None

async def fetch_all_candles():
    """Aggiorna candle_data per le top CANDLE_UNIVERSE_SIZE coin per volume."""
    global _candles_last_update

    # Seleziona top coin per volume tra quelle nell'universo dinamico
    universe = sorted(
        [(sym, d) for sym, d in market_data.items() if d["price"] > 0 and sym in _dynamic_universe],
        key=lambda x: x[1].get("volume24h", 0),
        reverse=True
    )
    if not _revx_pairs:
        universe = universe[:CANDLE_UNIVERSE_SIZE]

    if not universe:
        return

    syms = [sym for sym, _ in universe]
    print(f"Aggiornamento candele per {len(syms)} coin...")

    # Fetch parallelo con concorrenza limitata per rispettare rate limit Binance
    async with httpx.AsyncClient(timeout=15) as client:
        sem = asyncio.Semaphore(8)
        async def _fetch_limited(s):
            async with sem:
                return await fetch_candles_for_symbol(s, client)
        tasks = [_fetch_limited(sym) for sym in syms]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    updated = 0
    for sym, result in zip(syms, results):
        if result and not isinstance(result, Exception):
            candle_data[sym] = result
            updated += 1

    _candles_last_update = time.time()
    print(f"Candele aggiornate: {updated}/{len(syms)}")

# ──────────────────────────────────────────────────────────────
#  SCANNER MULTI-TIMEFRAME
# ──────────────────────────────────────────────────────────────

async def fetch_scanner_candles(sym: str, client: httpx.AsyncClient, timeframe: str = "1h") -> dict | None:
    """Scarica candele per UN timeframe e calcola tutti i segnali scanner su quel TF."""
    pair   = f"{sym}USDT"
    limits = {"5m": 300, "15m": 300, "1h": 250, "4h": 250, "1d": 300}
    limit  = limits.get(timeframe, 250)
    try:
        for base in (BINANCE_BASE, BINANCE_US_BASE):
            r = await client.get(f"{base}/api/v3/klines",
                                 params={"symbol": pair, "interval": timeframe, "limit": limit})
            if r.status_code == 451:
                continue
            if r.status_code != 200:
                return None
            break
        else:
            return None

        klines = r.json()
        if not isinstance(klines, list) or len(klines) < 220:
            return None

        closes  = [float(k[4]) for k in klines]
        volumes = [float(k[5]) for k in klines]
        highs   = [float(k[2]) for k in klines]
        lows    = [float(k[3]) for k in klines]
        closed  = closes[:-1]   # escludi candela corrente ancora aperta

        # EMA 20 / 50 / 200
        ema20      = calc_ema(closed, 20)
        ema50      = calc_ema(closed, 50)
        ema200     = calc_ema(closed, 200)
        ema50_p24  = calc_ema(closed[:-24], 50)
        ema200_p24 = calc_ema(closed[:-24], 200)

        # RSI(14)
        rsi = calc_rsi(closed, 14)

        # MACD(5,13,3)
        e5   = calc_ema_list(closed, 5)
        e13  = calc_ema_list(closed, 13)
        off  = len(e5) - len(e13)
        macd_line   = [e5[off + i] - e13[i] for i in range(len(e13))]
        sig_list    = calc_ema_list(macd_line, 3)
        off2        = len(macd_line) - len(sig_list)
        hist        = [macd_line[off2 + i] - sig_list[i] for i in range(len(sig_list))]
        macd_hist      = hist[-1]  if hist           else 0.0
        macd_hist_prev = hist[-2]  if len(hist) >= 2 else 0.0

        # TSI(25,13)
        pc     = [closed[i] - closed[i-1] for i in range(1, len(closed))]
        abs_pc = [abs(x) for x in pc]
        e1 = calc_ema_list(pc,     25);  e2 = calc_ema_list(e1, 13)
        a1 = calc_ema_list(abs_pc, 25);  a2 = calc_ema_list(a1, 13)
        tsi_cur  = round(100 * e2[-1] / a2[-1], 2) if a2 and a2[-1]  != 0 else 0.0
        tsi_prev = round(100 * e2[-2] / a2[-2], 2) if a2 and len(a2) >= 2 and a2[-2] != 0 else 0.0

        # Volume
        vol_last  = volumes[-2] if len(volumes) >= 2 else 0.0
        vol_avg20 = sum(volumes[-21:-1]) / 20 if len(volumes) >= 21 else 0.0

        # Breakout: ultima chiusura supera il massimo delle 10 candele chiuse precedenti
        last_close = closed[-1]
        high10     = max(highs[-12:-2]) if len(highs) >= 12 else max(highs[:-2])

        vol_spike    = (vol_last > 2.0 * vol_avg20) if vol_avg20 > 0 else False
        golden_cross = (ema50 > ema200) and (ema50_p24 <= ema200_p24)
        death_cross  = (ema50 < ema200) and (ema50_p24 >= ema200_p24)

        return {
            "golden_cross":   golden_cross,
            "death_cross":    death_cross,
            "rsi_14":         round(rsi, 1),
            "rsi_oversold":   rsi < 30.0,
            "rsi_overbought": rsi > 70.0,
            "ema_stack":      (last_close > ema20 > ema50) if ema50 > 0 else False,
            "macd_hist":      round(macd_hist, 6),
            "macd_hist_prev": round(macd_hist_prev, 6),
            "macd_bullish":   macd_hist > 0 and macd_hist > macd_hist_prev,
            "macd_bearish":   macd_hist < 0 and macd_hist < macd_hist_prev,
            "tsi_bullish":    tsi_cur > 0 and tsi_cur >= tsi_prev,
            "breakout":       last_close > high10 and vol_spike,
            "volume_spike":   vol_spike,
            "vol_ratio":      round(vol_last / vol_avg20, 2) if vol_avg20 > 0 else 0.0,
            "sparkline":      closes[-25:-1],
        }
    except Exception as e:
        print(f"Scanner candle error {sym} {timeframe}: {e}")
        return None


async def fetch_all_scanner_candles(timeframe: str = "1h"):
    """Aggiorna scanner_candle_data[timeframe] per tutte le coin dell'universo."""
    global _scanner_candles_ts
    universe = sorted(
        [(sym, d) for sym, d in market_data.items() if d["price"] > 0 and sym in _dynamic_universe],
        key=lambda x: x[1].get("volume24h", 0), reverse=True
    )
    if not _revx_pairs:
        universe = universe[:CANDLE_UNIVERSE_SIZE]
    if not universe:
        return
    syms = [s for s, _ in universe]
    print(f"Scanner [{timeframe}] per {len(syms)} coin...")
    async with httpx.AsyncClient(timeout=15) as client:
        sem = asyncio.Semaphore(8)
        async def _fetch(s):
            async with sem:
                return await fetch_scanner_candles(s, client, timeframe)
        results = await asyncio.gather(*[_fetch(s) for s in syms], return_exceptions=True)
    if timeframe not in scanner_candle_data:
        scanner_candle_data[timeframe] = {}
    updated = 0
    for sym, res in zip(syms, results):
        if res and not isinstance(res, Exception):
            scanner_candle_data[timeframe][sym] = res
            updated += 1
    _scanner_candles_ts[timeframe] = time.time()
    print(f"Scanner [{timeframe}] aggiornate: {updated}/{len(syms)}")


def get_momentum_signal(sym: str, current_price: float,
                        max_stop_pct: float = 0.02,
                        vol_multiplier: float = 1.2,
                        momentum_threshold: float = 0.01) -> dict:
    """
    Segnale momentum: entra quando il prezzo è salito >= 1% rispetto a 50 minuti fa
    (10 candele 5m) con volume sopra 1.2× la media delle ultime 20 candele.
    """
    cd = candle_data.get(sym)
    if not cd:
        return {"signal": False, "reason": "no candle data", "stop_price": 0.0,
                "breakout_ok": False, "vol_ok": False, "freshness_ok": False, "rsi_ok": False,
                "decomp_ok": False, "wick_ok": False, "chop_ok": False, "keltner_ok": False,
                "tsi_ok": False, "macd_ok": False}

    close_10_ago     = cd.get("close_10_ago", 0.0)
    close_3_ago      = cd.get("close_3_ago", close_10_ago)
    last_close       = cd.get("last_close_5m", 0.0)
    vol_avg_20       = cd.get("vol_avg_20", 0.0)
    vol_last         = cd.get("vol_last", 0.0)
    rsi_14           = cd.get("rsi_14", 50.0)
    upper_wick_ratio = cd.get("upper_wick_ratio", 0.0)
    chop_14          = cd.get("chop_14", 100.0)
    keltner_upper    = cd.get("keltner_upper", 0.0)
    tsi              = cd.get("tsi", -1.0)
    tsi_15m          = cd.get("tsi_15m", -1.0)
    tsi_15m_p        = cd.get("tsi_15m_prev", -1.0)
    tsi_1h           = cd.get("tsi_1h", -1.0)
    tsi_1h_p         = cd.get("tsi_1h_prev", -1.0)
    macd_hist        = cd.get("macd_hist", -1.0)
    macd_hist_prev   = cd.get("macd_hist_prev", 0.0)

    momentum_pct = (last_close - close_10_ago) / close_10_ago if close_10_ago > 0 else 0.0
    total_move   = last_close - close_10_ago
    recent_move  = last_close - close_3_ago

    breakout_ok  = momentum_pct >= momentum_threshold
    vol_ok       = (vol_last >= vol_avg_20 * vol_multiplier) if vol_avg_20 > 0 else False
    rsi_ok       = 45 <= rsi_14 <= 72
    decomp_ok    = (recent_move / total_move) >= 0.25 if total_move > 0 else False
    wick_ok      = upper_wick_ratio <= 0.55
    keltner_ok   = last_close > keltner_upper if keltner_upper > 0 else False
    tsi_ok       = tsi_1h > 0 and tsi_1h >= tsi_1h_p
    macd_ok      = macd_hist > 0 and macd_hist > macd_hist_prev

    stop_price = current_price * (1 - max_stop_pct)

    signal = (breakout_ok and vol_ok and rsi_ok and
              decomp_ok and wick_ok and keltner_ok and tsi_ok and macd_ok)

    if not breakout_ok:
        reason = f"momentum debole | +{momentum_pct*100:.2f}% in 50min (soglia +{momentum_threshold*100:.0f}%)"
    elif not vol_ok:
        ratio = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        reason = f"volume basso ({ratio:.2f}x < {vol_multiplier}x richiesto)"
    elif not rsi_ok:
        reason = f"RSI {rsi_14:.0f} fuori range [45-72]"
    elif not decomp_ok:
        pct = (recent_move / total_move * 100) if total_move > 0 else 0
        reason = f"move esaurito | solo {pct:.0f}% nelle ultime 3 candele (min 25%)"
    elif not wick_ok:
        reason = f"rigetto venditori | wick {upper_wick_ratio*100:.0f}% del range (max 55%)"
    elif not keltner_ok:
        reason = f"sotto Keltner upper | prezzo non ha rotto EMA20+2×ATR"
    elif not tsi_ok:
        reason = f"TSI 1h {tsi_1h:.2f} — trend orario non confermato"
    elif not macd_ok:
        reason = f"MACD histogram non accelera | hist {macd_hist:.6f}"
    else:
        ratio = vol_last / vol_avg_20
        pct   = (recent_move / total_move * 100) if total_move > 0 else 0
        reason = (f"MOMENTUM +{momentum_pct*100:.2f}% | vol {ratio:.1f}x | RSI {rsi_14:.0f} | "
                  f"TSI1h {tsi_1h:.2f} | Keltner OK | decomp {pct:.0f}% | SL -{max_stop_pct*100:.1f}%")

    return {
        "signal":       signal,
        "reason":       reason,
        "stop_price":   round(stop_price, 8),
        "breakout_ok":  breakout_ok,
        "vol_ok":       vol_ok,
        "rsi_ok":       rsi_ok,
        "decomp_ok":    decomp_ok,
        "wick_ok":      wick_ok,
        "keltner_ok":   keltner_ok,
        "tsi_ok":       tsi_ok,
        "macd_ok":      macd_ok,
    }

def get_breakout_signal(sym: str, current_price: float, max_stop_pct: float = 0.02,
                        chop_min: float = 61.8, atr_ratio_max: float = 0.85,
                        vol_multiplier: float = 1.5) -> dict:
    """Segnale consolidation breakout: rileva compressione poi rottura del range con volume."""
    cd = candle_data.get(sym, {})
    if not cd:
        return {"signal": False, "reason": "no candle data", "stop_price": 0.0,
                "consolidation_ok": False, "atr_contracted": False,
                "breakout_ok": False, "vol_ok": False, "fresh_ok": False}

    atr_5m       = cd.get("atr_5m", 0.0)
    atr_avg_30   = cd.get("atr_avg_30", atr_5m)
    range_high   = cd.get("range_high_60", 0.0)
    range_low    = cd.get("range_low_60", 0.0)
    chop_long    = cd.get("chop_long", 50.0)
    last_close   = cd.get("last_close_5m", current_price)
    close_7_ago  = cd.get("close_7_ago", current_price)
    vol_last     = cd.get("vol_last", 0.0)
    vol_avg_20   = cd.get("vol_avg_20", 0.0)

    # 1. Consolidazione: CHOP alto su 3h = mercato laterale
    consolidation_ok = chop_long >= chop_min

    # 2. ATR contratto: volatilità compressa rispetto alla sua media
    atr_contracted = (atr_5m < atr_avg_30 * atr_ratio_max) if atr_avg_30 > 0 else False

    # 3. Breakout: chiusura sopra il tetto del range (con piccolo buffer 0.1%)
    breakout_ok = (last_close > range_high * 1.001) if range_high > 0 else False

    # 4. Volume: spike sul breakout
    vol_ok = (vol_last >= vol_avg_20 * vol_multiplier) if vol_avg_20 > 0 else False

    # 5. Freshness: 35 minuti fa era ancora dentro il range (breakout appena avvenuto)
    fresh_ok = close_7_ago < range_high if range_high > 0 else False

    # Stop sotto il range di consolidazione (supporto naturale)
    stop_price = max(range_low * 0.998, current_price * (1 - max_stop_pct)) if range_low > 0 else current_price * (1 - max_stop_pct)

    # atr_contracted non è nel gate: la candela di breakout ha ATR elevato per definizione.
    # Viene calcolato e restituito come metadato ma non blocca il segnale.
    signal = consolidation_ok and breakout_ok and vol_ok and fresh_ok

    if not consolidation_ok:
        reason = f"nessuna consolidazione | CHOP3h {chop_long:.1f} (min {chop_min:.0f})"
    elif not breakout_ok:
        pct_to = (range_high / last_close - 1) * 100 if last_close > 0 else 0
        reason = f"nessun breakout | -{pct_to:.2f}% dal tetto range {range_high:.6f}"
    elif not vol_ok:
        ratio = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        reason = f"volume breakout basso ({ratio:.2f}x < {vol_multiplier}x)"
    elif not fresh_ok:
        reason = f"breakout non fresco | prezzo sopra range da >35min"
    else:
        pct = (last_close / range_high - 1) * 100
        vol_r = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        atr_r = atr_5m / atr_avg_30 if atr_avg_30 > 0 else 0
        reason = f"BREAKOUT +{pct:.2f}% dal range | CHOP3h {chop_long:.1f} | vol {vol_r:.1f}x | ATR {atr_r:.2f}x"

    return {
        "signal":           signal,
        "reason":           reason,
        "stop_price":       round(stop_price, 8),
        "consolidation_ok": consolidation_ok,
        "atr_contracted":   atr_contracted,
        "breakout_ok":      breakout_ok,
        "vol_ok":           vol_ok,
        "fresh_ok":         fresh_ok,
    }

# ── rest of market data ───────────────────────────────────────────────────────

STABLES = {'USDT','USDC','BUSD','DAI','FDUSD','TUSD','USDP','GUSD','FRAX',
           'LUSD','SUSD','EUR','GBP','USD','USDD','USTC','PAX','CBBTC','WBTC'}

_global_revx_key_id: str = ""
_global_revx_private_key: str = ""
_revx_pairs: set = set()  # simboli EUR disponibili su Revolut X es. {"BTC","ETH","ADA"} — caricato all'avvio
_products_last_update: float = 0

REVX_BASE_PUB = "https://revx.revolut.com"

async def fetch_revx_market_data(key_id: str = "", private_key: str = "") -> dict:
    """
    Scarica ticker da Revolut X usando le chiavi utente.
    Path: GET /api/1.0/tickers — risposta: {"data": [...], "metadata": {...}}
    Simboli formato: "BTC/EUR" (slash, non trattino)
    Restituisce dict sym -> {price_eur, change24h, volume24h, symbol_pair}
    """
    result = {}
    if not key_id or not private_key:
        return result
    try:
        data = await revx_request("GET", "/api/1.0/tickers",
                                   key_id=key_id, private_key=private_key, params={})
        # Risposta: {"data": [...tickers...], "metadata": {...}}
        tickers = data.get("data", []) if isinstance(data, dict) else data
        if not isinstance(tickers, list):
            print(f"[REVX TICKER] risposta inattesa: {str(data)[:200]}")
            return result
        for t in tickers:
            if not isinstance(t, dict):
                continue
            symbol = t.get("symbol", "")  # es. "BTC/EUR"
            # Filtra coppie USD (con slash)
            if not symbol.endswith("/USD"):
                continue
            sym = symbol[:-4]  # rimuove "/USD"
            if not sym or sym in STABLES:
                continue
            price = float(t.get("last_price") or t.get("mid") or t.get("ask") or 0)
            change24h = float(t.get("price_change_24h_pct") or t.get("change_24h") or 0)
            volume24h = float(t.get("volume_24h") or t.get("volume") or 0)
            if price > 0:
                result[sym] = {
                    "price_usd": price,
                    "change24h": change24h,
                    "volume24h_usd": volume24h,
                    "symbol_pair": symbol.replace("/", "-"),  # normalizza a BTC-USD
                }
        print(f"[REVX TICKER] {len(result)} coppie USD caricate")
    except Exception as e:
        print(f"[REVX TICKER] error: {e}")
    return result

async def fetch_prices_coingecko():
    """Fallback CoinGecko quando Binance è bloccato (451). Throttlato a 1 fetch/60s."""
    global _cg_price_last_fetch
    if time.time() - _cg_price_last_fetch < 60:
        return
    _cg_price_last_fetch = time.time()
    try:
        fetched = 0
        async with httpx.AsyncClient(timeout=20) as client:
            for page in (1, 2):
                r = await client.get(
                    "https://api.coingecko.com/api/v3/coins/markets",
                    params={
                        "vs_currency": "usd",
                        "order": "volume_desc",
                        "per_page": 250,
                        "page": page,
                        "price_change_percentage": "1h,24h",
                    }
                )
                if r.status_code != 200:
                    print(f"[CG] fetch_prices HTTP {r.status_code}")
                    break
                coins = r.json()
                if not isinstance(coins, list):
                    break
                for coin in coins:
                    sym = (coin.get("symbol") or "").upper()
                    if not sym or not sym.isalpha() or sym in STABLES:
                        continue
                    price = coin.get("current_price") or 0.0
                    if price <= 0:
                        continue
                    change24h = coin.get("price_change_percentage_24h") or 0.0
                    change1h  = coin.get("price_change_percentage_1h_in_currency") or 0.0
                    vol_usd   = coin.get("total_volume") or 0.0
                    if sym not in market_data:
                        market_data[sym] = {"price": 0.0, "change1h": 0.0, "change24h": 0.0, "volume24h": 0.0, "icon": sym[0]}
                    market_data[sym]["price"]     = float(price)
                    market_data[sym]["change1h"]  = float(change1h)
                    market_data[sym]["change24h"] = float(change24h)
                    market_data[sym]["volume24h"] = float(vol_usd)
                    for state in list(user_sessions.values()):
                        for pos in list(state["positions"]):
                            if pos["symbol"] == sym:
                                pos["currentPrice"] = float(price)
                                if float(price) > pos["highPrice"]:
                                    pos["highPrice"] = float(price)
                    fetched += 1
                await asyncio.sleep(1.5)
        print(f"[CG] fetch_prices fallback: {fetched} coin aggiornate")
    except Exception as e:
        print(f"[CG] fetch_prices error: {e}")


async def fetch_prices():
    try:
        r = None
        async with httpx.AsyncClient(timeout=15) as client:
            for base in (BINANCE_BASE, BINANCE_US_BASE):
                r = await client.get(f"{base}/api/v3/ticker/24hr")
                if r.status_code != 451:
                    break
        if r is None or r.status_code != 200:
            print(f"[BINANCE] fetch_prices HTTP {r.status_code if r else '?'}: {r.text[:200] if r else ''}")
            await fetch_prices_coingecko()
            return
        tickers = r.json()
        if not isinstance(tickers, list):
            print(f"[BINANCE] fetch_prices risposta non-lista: {str(tickers)[:200]}")
            await fetch_prices_coingecko()
            return

        for t in tickers:
            pair = t.get("symbol", "")
            if not pair.endswith("USDT"):
                continue
            sym = pair[:-4]
            if not sym.isascii() or not sym.isalpha() or sym in STABLES:
                continue
            try:
                price    = float(t["lastPrice"])
                change24h = float(t["priceChangePercent"])
                vol_usd  = float(t["quoteVolume"])
            except (ValueError, TypeError):
                continue
            if price <= 0:
                continue

            if sym not in market_data:
                market_data[sym] = {"price": 0.0, "change1h": 0.0, "change24h": 0.0, "volume24h": 0.0, "icon": sym[0]}

            cd = candle_data.get(sym)
            change1h = ((price - cd["close_1h_ago"]) / cd["close_1h_ago"] * 100
                        if cd and cd.get("close_1h_ago", 0) > 0
                        else market_data[sym].get("change1h", 0.0))

            market_data[sym]["price"]     = price
            market_data[sym]["change1h"]  = change1h
            market_data[sym]["change24h"] = change24h
            market_data[sym]["volume24h"] = vol_usd

            for state in list(user_sessions.values()):
                for pos in list(state["positions"]):
                    if pos["symbol"] == sym:
                        pos["currentPrice"] = price
                        if price > pos["highPrice"]:
                            pos["highPrice"] = price

    except Exception as e:
        print(f"Fetch error: {e}")

# ── session ───────────────────────────────────────────────────────────────────

def make_session() -> dict:
    return {
        "running": False, "capital": 0.0, "currentCapital": 0.0,
        "positions": [], "pnlHistory": [], "sessionStart": None,
        "sessionDuration": 0, "config": {}, "cooldowns": {},
        "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "consecutiveLosses": 0,
        "plan": "free",
        "paused": False,
    }

def get_session(user_id: int) -> dict:
    if user_id not in user_sessions:
        user_sessions[user_id] = make_session()
    return user_sessions[user_id]

def add_log(state: dict, type_: str, label: str, desc: str):
    log = state.setdefault("log", [])
    log.insert(0, {
        "type": type_, "label": label, "desc": desc,
        "ts": int(time.time() * 1000)
    })
    if len(log) > 200:
        log.pop()

def unrealized_pnl(state: dict) -> float:
    total = 0.0
    for p in state["positions"]:
        size = p.get("size_remaining", p["size"])
        gross = (p["currentPrice"] - p["entryPrice"]) / p["entryPrice"] * size
        exit_fee = size * p.get("fee_pct", 0.0009)
        total += gross - exit_fee
    return total

# ── trading ───────────────────────────────────────────────────────────────────

def parse_revx_balances(result: object) -> list:
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and isinstance(result.get("balances"), list):
        return result["balances"]
    if isinstance(result, dict) and isinstance(result.get("data"), list):
        return result["data"]
    raise ValueError(f"Risposta balances RevX inattesa: {str(result)[:200]}")


async def get_revx_usd_balance(key_id: str, private_key: str) -> float:
    """Legge il saldo USD disponibile su Revolut X."""
    result = await revx_request("GET", "/api/1.0/balances", key_id=key_id, private_key=private_key)
    balances = parse_revx_balances(result)
    for b in balances:
        if b.get("currency") == "USD":
            return float(b.get("available", 0) or 0)
    return 0.0


async def enter_position(state: dict, sym_data: dict, tradable_capital: float):
    cfg      = state["config"]
    price    = sym_data["price"]
    sym      = sym_data["symbol"]
    is_real  = cfg.get("realMode", False)

    alloc_pct  = min(cfg.get("allocPct", 0.20), 1.0)
    use_revx         = state.get("use_revx", False)
    use_coinbase_pos = state.get("use_coinbase", False)
    TRADING_FEE = 0.012 if use_coinbase_pos else 0.0009  # Coinbase ~1.2%, RevX taker 0.09%
    fixed_amt  = cfg.get("tradeAmountUsd", 0)
    size = round(fixed_amt, 2) if fixed_amt and fixed_amt > 0 else tradable_capital * alloc_pct
    if size < 1:
        return

    entry_fee = size * TRADING_FEE

    # Funzione per formattare prezzi con abbastanza decimali (gestisce coin micro come PEPE)
    def fmt_price(p: float) -> str:
        if p >= 1: return f"${p:.4f}"
        if p >= 0.0001: return f"${p:.6f}"
        return f"${p:.8f}"

    # Stop price: dalla funzione EMA signal (contestuale ATR/low)
    # Fallback: stop fisso da config
    stop_price = sym_data.get("stop_price", 0.0)
    if stop_price <= 0 or stop_price >= price:
        fallback_sl = cfg.get("maxStopPct", 0.05)
        stop_price  = price * (1 - fallback_sl)

    R_pct = (price - stop_price) / price  # rischio in % per questa posizione

    # TP1 = entry + tp1R (default 2R), TP2 = entry + tp2R (default 4R)
    tp1_multiplier = cfg.get("tp1R", 2.0)
    tp2_multiplier = cfg.get("tp2R", 4.0)
    tp1_price = price * (1 + R_pct * tp1_multiplier)
    tp2_price = price * (1 + R_pct * tp2_multiplier)

    # Determina exchange da usare
    use_revx = state.get("use_revx", False)

    if is_real:
        if use_revx:
            # ── REVOLUT X ────────────────────────────────────────────────────
            revx_key_id  = state.get("revx_key_id", "")
            revx_priv    = state.get("revx_private_key", "")
            try:
                symbol_revx = f"{sym}-USD"
                import uuid as _uuid
                order_body = {
                    "client_order_id": str(_uuid.uuid4()),
                    "symbol": symbol_revx,
                    "side": "BUY",
                    "order_configuration": {"market": {"quote_size": str(round(size, 2))}}
                }
                add_log(state, "info", "DEBUG", f"Ordine RevX {symbol_revx} size=${size:.2f}")
                # Retry su errori di rete con lo stesso client_order_id: cambiarlo può duplicare ordini.
                result = None
                for attempt in range(2):
                    try:
                        result = await revx_request(
                            "POST", "/api/1.0/orders", order_body,
                            key_id=revx_key_id, private_key=revx_priv
                        )
                        break
                    except Exception as net_err:
                        if attempt == 0:
                            print(f"[REVX ORDER] tentativo 1 fallito: {net_err}, riprovo...")
                            await asyncio.sleep(2)
                        else:
                            raise
                print(f"[REVX ORDER RESULT] {sym}: {result}")
                data = result.get("data") or result
                order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
                if not order_id:
                    err_msg = result.get("message") or result.get("error") or result.get("detail") or str(result)
                    add_log(state, "info", "ERRORE", f"Ordine RevX {sym} fallito: {err_msg}")
                    await notify(state, f"ERRORE ORDINE RevX {sym}: {err_msg[:100]}")
                    return
                # Fetch dati reali del fill per P&L accurato. Non creare posizioni stimate.
                od = await wait_revx_order_fill(order_id, revx_key_id, revx_priv)
                actual_price = od.get("average_fill_price", 0.0)
                qty_purchased = od.get("filled_quantity", 0.0)
                if actual_price <= 0 or qty_purchased <= 0:
                    state_txt = od.get("state") or "sconosciuto"
                    add_log(state, "info", "ERRORE", f"Ordine RevX {sym} non fillato (state={state_txt}) — verifica su RevX")
                    await notify(state, f"ERRORE ORDINE RevX {sym}: ordine non fillato (state={state_txt}). Verifica manualmente su RevX.")
                    return
                # Fee buy in base currency → converti in USD
                buy_fee = od.get("total_fee", 0.0)
                buy_fee_currency = od.get("fee_currency", "USD")
                buy_fee_usd = buy_fee * actual_price if buy_fee_currency != "USD" else buy_fee
                print(f"[REVX BUY] qty={qty_purchased:.6f} @ ${actual_price:.4f} USD size=${size:.2f} fee={buy_fee} {buy_fee_currency}")
                stop_price  = actual_price * (1 - R_pct)
                tp1_price   = actual_price * (1 + R_pct * tp1_multiplier)
                tp2_price   = actual_price * (1 + R_pct * tp2_multiplier)
                add_log(state, "buy", "ACQUISTO REALE (RevX)",
                    f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | Qty: {qty_purchased:.6f} | "
                    f"SL: ${stop_price:.4f}")
                await notify(state, f"ACQUISTO REALE RevX\n{sym} @ ${actual_price:.4f}\nSize: ${size:.2f}")
            except Exception as e:
                add_log(state, "info", "ERRORE", f"RevX error: {e}")
                return
            # Aggiorna stato posizione
            state["currentCapital"] -= size
            pos = {
                "symbol": sym, "icon": sym_data["icon"],
                "entryPrice": actual_price, "currentPrice": actual_price, "highPrice": actual_price,
                "peak_price": actual_price,
                "size": size, "size_remaining": size, "tp1_hit": False,
                "entryTime": datetime.utcnow().isoformat() + "Z",
                "stopPrice": stop_price, "tp1Price": tp1_price, "tp2Price": tp2_price,
                "R_pct": R_pct, "atr_5m": candle_data.get(sym, {}).get("atr_5m", 0.0),
                "realMode": True, "fee_pct": 0.0009,
                "qty_purchased": qty_purchased, "exchange": "revx", "symbol_pair": symbol_revx,
                "entry_usd": round(size, 2),
                "buy_fee_usd": round(buy_fee_usd, 4),
            }
            state["positions"].append(pos)
            await persist_sessions()
            return
        elif state.get("use_coinbase"):
            # ── COINBASE ──────────────────────────────────────────────────────
            cb_key = state.get("coinbase_api_key_agent", "")
            cb_sec = state.get("coinbase_api_secret_agent", "")
            if not cb_key:
                try:
                    cb_key, cb_sec = await load_coinbase_keys_for_user(user_id)
                except Exception as ke:
                    add_log(state, "info", "ERRORE", f"Coinbase keys mancanti: {ke}")
                    return
            try:
                preflight = await get_coinbase_preflight_result(cb_key, cb_sec, sym, size)
                if not preflight.get("ok"):
                    blockers = preflight.get("blockers", [])
                    add_log(state, "info", "ERRORE", f"Coinbase preflight {sym}: {blockers}")
                    return
                import uuid as _uuid
                product_id = preflight["product_id"]
                order_body = {
                    "client_order_id": str(_uuid.uuid4()),
                    "product_id": product_id,
                    "side": "BUY",
                    "order_configuration": {
                        "market_market_ioc": {
                            "quote_size": f"{size:.2f}",
                            "rfq_disabled": True,
                        }
                    },
                }
                result = await coinbase_request(
                    "POST", "/api/v3/brokerage/orders",
                    body=order_body, api_key=cb_key, api_secret=cb_sec
                )
                if result.get("success") is False:
                    err = result.get("error_response") or result.get("failure_reason") or result
                    add_log(state, "info", "ERRORE", f"Ordine Coinbase {sym} fallito: {str(err)[:120]}")
                    await notify(state, f"ERRORE ORDINE Coinbase {sym}: {str(err)[:100]}")
                    return
                order_id = extract_coinbase_order_id(result)
                if not order_id:
                    add_log(state, "info", "ERRORE", f"Ordine Coinbase {sym} senza order_id: {result}")
                    return
                od = await wait_coinbase_order_fill(order_id, cb_key, cb_sec)
                actual_price = float(od.get("average_filled_price") or 0)
                qty_purchased = float(od.get("filled_size") or 0)
                buy_fee_usd = float(od.get("total_fees") or 0)
                if actual_price <= 0 or qty_purchased <= 0:
                    state_txt = od.get("status") or "sconosciuto"
                    add_log(state, "info", "ERRORE", f"Coinbase {sym} non fillato (state={state_txt})")
                    await notify(state, f"ERRORE Coinbase {sym}: ordine non fillato (state={state_txt})")
                    return
                stop_price  = actual_price * (1 - R_pct)
                tp1_price   = actual_price * (1 + R_pct * tp1_multiplier)
                tp2_price   = actual_price * (1 + R_pct * tp2_multiplier)
                add_log(state, "buy", "ACQUISTO REALE (Coinbase)",
                    f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | Qty: {qty_purchased:.8f} | "
                    f"SL: ${stop_price:.4f} | Fee: ${buy_fee_usd:.4f}")
                await notify(state, f"ACQUISTO REALE Coinbase\n{sym} @ ${actual_price:.4f}\nSize: ${size:.2f}")
            except Exception as e:
                add_log(state, "info", "ERRORE", f"Coinbase buy error: {e}")
                return
            state["currentCapital"] -= size
            pos = {
                "symbol": sym, "icon": sym_data["icon"],
                "entryPrice": actual_price, "currentPrice": actual_price,
                "highPrice": actual_price, "peak_price": actual_price,
                "size": size, "size_remaining": size, "tp1_hit": False,
                "entryTime": datetime.utcnow().isoformat() + "Z",
                "stopPrice": stop_price, "tp1Price": tp1_price, "tp2Price": tp2_price,
                "R_pct": R_pct, "atr_5m": candle_data.get(sym, {}).get("atr_5m", 0.0),
                "realMode": True, "fee_pct": 0.012,
                "qty_purchased": qty_purchased, "exchange": "coinbase",
                "symbol_pair": product_id,
                "entry_usd": round(size, 2),
                "buy_fee_usd": round(buy_fee_usd, 4),
            }
            state["positions"].append(pos)
            await persist_sessions()
            return
        else:
            add_log(state, "info", "WARN", "Nessun exchange reale disponibile — trade annullato")
            return
    else:
        actual_price = price
        add_log(state, "buy", "ACQUISTO SIM",
            f"{sym} @ {fmt_price(actual_price)} | Size: ${size:.0f} | Fee: ${entry_fee:.2f} | "
            f"SL: {fmt_price(stop_price)}")
        await notify(state,
            "ACQUISTO SIM\n" + sym + " @ " + fmt_price(actual_price) +
            "\nSize: $" + f"{size:.0f}" +
            "\nSL: " + fmt_price(stop_price) +
            "\nTP1: " + fmt_price(tp1_price) + " | TP2: " + fmt_price(tp2_price)
        )

    # In sim sottraiamo anche la fee di entrata dal capitale disponibile
    state["currentCapital"] -= size + (entry_fee if not is_real else 0)
    pos = {
        "symbol":        sym,
        "icon":          sym_data["icon"],
        "entryPrice":    actual_price,
        "currentPrice":  actual_price,
        "highPrice":     actual_price,
        "peak_price":    actual_price,
        "size":          size,
        "size_remaining": size,
        "tp1_hit":       False,
        "entryTime":     datetime.utcnow().isoformat() + "Z",
        "stopPrice":     stop_price,
        "tp1Price":      tp1_price,
        "tp2Price":      tp2_price,
        "R_pct":         R_pct,
        "atr_5m":        candle_data.get(sym, {}).get("atr_5m", 0.0),
        "realMode":      is_real,
        "fee_pct":       TRADING_FEE,
        "qty_purchased": qty_purchased if is_real else 0.0,
    }
    state["positions"].append(pos)

REVX_LIMIT_DROPS = [0.01, 0.02, 0.04, 0.06, 0.09, 0.12, 0.16, 0.20, 0.25, 0.30]

async def _place_revx_gtc_limit(state: dict, pos: dict, attempt: int, user_id: int = None):
    import uuid as _uuid
    sym = pos["symbol"]
    revx_key_id = state.get("revx_key_id", "")
    revx_priv = state.get("revx_private_key", "")
    symbol_pair = pos.get("symbol_pair", f"{sym}-USD").replace("/", "-")
    qty_to_sell = pos.get("_sell_qty", pos.get("qty_purchased", 0.0))
    if qty_to_sell <= 0:
        add_log(state, "info", "ERRORE", f"{sym}: qty_to_sell={qty_to_sell} non valida — GTC annullato")
        return

    if attempt >= len(REVX_LIMIT_DROPS):
        add_log(state, "info", "WARN", f"{sym}: 10 tentativi GTC limit esauriti — market sell emergenza")
        await notify(state, f"⚠️ {sym}: 10 GTC falliti. Tentativo market sell emergenza...")
        pos.pop("_sell_mode", None)
        pos.pop("_sell_limit_order_id", None)
        try:
            emergency_body = {
                "client_order_id": str(_uuid.uuid4()),
                "symbol": symbol_pair,
                "side": "SELL",
                "order_configuration": {"market": {"base_size": str(qty_to_sell)}}
            }
            em_result = await revx_request("POST", "/api/1.0/orders", emergency_body,
                                           key_id=revx_key_id, private_key=revx_priv)
            em_data = em_result.get("data") or em_result
            em_id = em_data.get("venue_order_id") or em_data.get("order_id") or em_data.get("id", "")
            if em_id:
                od = await wait_revx_order_fill(em_id, revx_key_id, revx_priv)
                sell_price = od.get("average_fill_price", 0.0)
                filled_qty = od.get("filled_quantity", 0.0)
                if sell_price <= 0 or filled_qty <= 0:
                    add_log(state, "info", "ERRORE", f"{sym}: emergency market sell non confermato — verifica manualmente su RevX")
                    await notify(state, f"🚨 {sym}: market sell emergenza non confermato. Verifica manualmente su RevX.")
                    return
                sell_fee = od.get("total_fee", 0.0)
                fee_currency = od.get("fee_currency", "USD")
                pos["currentPrice"] = sell_price
                pos["sell_fee_usd"] = pos.get("sell_fee_usd", 0.0) + (sell_fee if fee_currency == "USD" else sell_fee * sell_price)
                pos["_already_sold"] = True
                pos["_sell_type"] = "Emergency Market"
                await exit_position(state, pos, "EMERGENZA MARKET SELL (10 GTC falliti)", user_id=user_id)
            else:
                err = em_result.get("message") or em_result.get("error") or str(em_result)
                add_log(state, "info", "ERRORE", f"{sym}: market sell emergenza fallito: {err[:80]} — vendi manualmente su RevX")
                await notify(state, f"🚨 {sym}: impossibile vendere automaticamente. Vendi manualmente su RevX!")
        except Exception as _em_e:
            add_log(state, "info", "ERRORE", f"{sym}: market sell emergenza eccezione: {_em_e} — vendi manualmente su RevX")
            await notify(state, f"🚨 {sym}: errore market sell ({_em_e}). Vendi manualmente su RevX!")
        return

    drop = REVX_LIMIT_DROPS[attempt]
    orig_price = pos.get("_sell_original_price", pos["currentPrice"])
    calc_price = round(orig_price * (1 - drop), 8)
    limit_price = max(calc_price, round(pos["currentPrice"], 8))

    order_body = {
        "client_order_id": str(_uuid.uuid4()),
        "symbol": symbol_pair,
        "side": "SELL",
        "order_configuration": {
            "limit": {
                "base_size": str(qty_to_sell),
                "price": str(limit_price)
            }
        }
    }
    try:
        result = await revx_request("POST", "/api/1.0/orders", order_body, key_id=revx_key_id, private_key=revx_priv)
        print(f"[GTC PLACE] {sym} #{attempt+1} raw result: {result}")
        data = result.get("data") or result
        order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
        if order_id and data.get("state", "") not in ("cancelled", "rejected"):
            pos["_sell_mode"] = "retry_limit"
            pos["_sell_attempt"] = attempt
            pos["_sell_limit_order_id"] = order_id
            pos["_sell_limit_placed_at"] = time.time()
            pos["_sell_limit_price"] = limit_price
            print(f"[GTC PLACE] {sym}: tentativo #{attempt+1} OK — order_id={order_id} price=${limit_price:.4f}")
            add_log(state, "info", "LIMIT GTC", f"{sym}: tentativo #{attempt+1} — limite a ${limit_price:.4f} (-{drop*100:.0f}%)")
            await notify(state, f"LIMIT GTC {sym}: #{attempt+1} a ${limit_price:.4f} (-{int(drop*100)}% dal prezzo originale)")
        else:
            err = result.get("message") or result.get("error") or str(result)
            print(f"[GTC PLACE] {sym}: tentativo #{attempt+1} FALLITO — {str(err)[:120]}")
            add_log(state, "info", "ERRORE", f"{sym}: GTC limit #{attempt+1} fallito: {str(err)[:80]}")
            await _place_revx_gtc_limit(state, pos, attempt + 1, user_id)
    except Exception as e:
        print(f"[GTC PLACE] {sym}: eccezione #{attempt+1}: {e}")
        add_log(state, "info", "ERRORE", f"{sym}: eccezione piazzamento GTC limit: {e}")


async def _poll_revx_gtc_limit(state: dict, pos: dict, user_id: int = None):
    sym = pos["symbol"]
    order_id = pos.get("_sell_limit_order_id", "")
    attempt = pos.get("_sell_attempt", 0)
    placed_at = pos.get("_sell_limit_placed_at", time.time())
    revx_key_id = state.get("revx_key_id", "")
    revx_priv = state.get("revx_private_key", "")
    if not order_id:
        return
    try:
        result = await revx_request("GET", f"/api/1.0/orders/{order_id}", key_id=revx_key_id, private_key=revx_priv)
        d = result.get("data") or result
        order_state = (d.get("status") or d.get("state") or "").lower()
        filled_qty = float(d.get("filled_quantity") or 0)
        avg_fill = float(d.get("average_fill_price") or 0)
        total_fee = float(d.get("total_fee") or 0)
        fee_currency = d.get("fee_currency", "USD")
        elapsed = time.time() - placed_at

        print(f"[GTC POLL] {sym}: order_id={order_id} raw={result}")
        print(f"[GTC POLL] {sym}: state='{order_state}' filled_qty={filled_qty} avg_fill={avg_fill} elapsed={elapsed:.0f}s attempt={attempt}")

        if order_state in ("filled", "completed"):
            sell_price = avg_fill or pos.get("_sell_limit_price", pos["currentPrice"])
            sell_fee_usd = total_fee if fee_currency == "USD" else total_fee * sell_price
            pos["sell_fee_usd"] = pos.get("sell_fee_usd", 0.0) + sell_fee_usd
            pos["currentPrice"] = sell_price
            pos["_already_sold"] = True
            pos["_sell_type"] = f"Limit GTC #{attempt+1}"
            reason = pos.get("_sell_reason", "LIMIT GTC")
            print(f"[GTC POLL] {sym}: FILLATO #{attempt+1} @ ${sell_price:.4f} fee={sell_fee_usd:.4f} — chiamo exit_position")
            add_log(state, "info", "VENDUTO RevX", f"{sym} GTC limit #{attempt+1} fillato @ ${sell_price:.4f} fee=${sell_fee_usd:.4f}")
            await exit_position(state, pos, reason, user_id=user_id)
            pos.pop("_sell_mode", None)  # rimosso dopo exit_position per proteggere il loop SL/TP in caso di eccezione

        elif order_state in ("cancelled", "rejected", "expired"):
            print(f"[GTC POLL] {sym}: stato '{order_state}' — passo al livello {attempt+2}")
            add_log(state, "info", "INFO", f"{sym}: GTC limit #{attempt+1} cancellato — prossimo livello")
            await _place_revx_gtc_limit(state, pos, attempt + 1, user_id)

        elif order_state in ("new", "open", "pending", "active"):
            if elapsed >= 300 and filled_qty == 0:
                print(f"[GTC POLL] {sym}: timeout 5min senza fill — cancello e passo al livello {attempt+2}")
                add_log(state, "info", "INFO", f"{sym}: GTC limit #{attempt+1} non fillato dopo 5 min — prossimo livello")
                await revx_request("DELETE", f"/api/1.0/orders/{order_id}", key_id=revx_key_id, private_key=revx_priv)
                await _place_revx_gtc_limit(state, pos, attempt + 1, user_id)
            else:
                print(f"[GTC POLL] {sym}: ancora aperto — aspetto (filled={filled_qty}, elapsed={elapsed:.0f}s)")
            # < 5 min oppure parzialmente fillato: aspetta
        else:
            print(f"[GTC POLL] {sym}: stato SCONOSCIUTO '{order_state}' — raw={result}")
    except Exception as e:
        print(f"[GTC POLL] {sym}: ECCEZIONE — {e}")
        add_log(state, "info", "ERRORE", f"Poll GTC {sym}: {e}")


async def exit_position(state: dict, pos: dict, reason: str, partial: bool = False, user_id: int = None):
    """
    Se partial=True: chiude il 50% della posizione (TP1).
    Se partial=False: chiude tutto.
    """
    def _fp(p: float) -> str:
        if p >= 1: return f"${p:.4f}"
        if p >= 0.0001: return f"${p:.6f}"
        return f"${p:.8f}"

    cur  = pos["currentPrice"]
    sym  = pos["symbol"]

    # Evita doppia vendita concorrente sullo stesso simbolo
    _exiting = state.setdefault("_exiting", set())
    if sym in _exiting:
        return
    _exiting.add(sym)
    dur  = (datetime.utcnow() - datetime.fromisoformat(pos["entryTime"].replace("Z", ""))).total_seconds() / 60

    # Dimensione effettiva da chiudere
    close_size = pos["size_remaining"] * 0.5 if partial else pos["size_remaining"]
    qty_to_sell = round(pos.get("qty_purchased", 0.0) * (0.5 if partial else 1.0), 8)

    if pos.get("realMode", False):
        # ── REVOLUT X EXIT ────────────────────────────────────────────────────
        if pos.get("exchange") == "revx" and not pos.get("_already_sold"):
            revx_key_id = state.get("revx_key_id", "")
            revx_priv   = state.get("revx_private_key", "")
            qty_purchased = pos.get("qty_purchased", 0.0)
            if qty_purchased <= 0:
                add_log(state, "info", "ERRORE", f"qty_purchased non disponibile per {sym} RevX — vendita annullata")
                _exiting.discard(sym); return
            try:
                import uuid as _uuid
                qty_to_sell = round(qty_purchased * 0.5, 8) if partial else round(qty_purchased, 8)
                symbol_pair = pos.get("symbol_pair", f"{sym}-USD")
                # Normalizza: usa sempre formato "SYM-USD" non "SYM/USD"
                symbol_pair = symbol_pair.replace("/", "-")
                print(f"[REVX SELL] {sym} symbol_pair={symbol_pair} qty_purchased={qty_purchased}")
                sold_externally = False
                # Leggi saldo reale da RevX — se 0 la coin è già stata venduta esternamente
                try:
                    balances = await revx_request("GET", "/api/1.0/balances",
                                                  key_id=revx_key_id, private_key=revx_priv)
                    bal_list = parse_revx_balances(balances)
                    for b in bal_list:
                        if b.get("currency") == sym:
                            real_qty = float(b.get("available", 0) or 0)
                            if real_qty > 0:
                                qty_to_sell_real = round(real_qty * (0.5 if partial else 1.0), 8)
                                print(f"[REVX SELL] {sym} qty_tracciata={qty_to_sell:.6f} qty_reale={real_qty:.6f} -> vendo {qty_to_sell_real:.6f}")
                                qty_to_sell = qty_to_sell_real
                                pos["qty_purchased"] = real_qty
                            else:
                                add_log(state, "info", "WARN", f"{sym}: saldo RevX = 0 — venduto esternamente, registro trade")
                                sold_externally = True
                            break
                except Exception as be:
                    print(f"[REVX SELL] errore lettura saldo: {be}")
                if not sold_externally:
                    # Market order — fill immediato, nessun polling, nessuna race condition
                    order_body = {
                        "client_order_id": str(_uuid.uuid4()),
                        "symbol": symbol_pair,
                        "side": "SELL",
                        "order_configuration": {"market": {"base_size": str(qty_to_sell)}}
                    }
                    print(f"[REVX SELL] {sym} market qty={qty_to_sell:.6f}")
                    result = None
                    for attempt in range(2):
                        try:
                            result = await revx_request(
                                "POST", "/api/1.0/orders", order_body,
                                key_id=revx_key_id, private_key=revx_priv
                            )
                            break
                        except Exception as net_err:
                            if attempt == 0:
                                print(f"[REVX SELL] tentativo 1 fallito: {net_err}, riprovo...")
                                await asyncio.sleep(2)
                            else:
                                raise
                    print(f"[REVX SELL RESULT] {sym}: {result}")
                    data = result.get("data") or result
                    order_id    = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
                    order_state = data.get("state", "")
                    market_cancelled = order_state in ("cancelled", "rejected")
                    if not order_id or market_cancelled:
                        err_msg = result.get("message") or result.get("error") or result.get("detail") or str(result)
                        if "insufficient" in str(err_msg).lower():
                            pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                            add_log(state, "info", "WARN", f"{sym}: Insufficient balance su market order ({pos['_sell_failures']}x) — balance locked su RevX, riprova")
                            await notify(state, f"WARN {sym}: balance insufficiente su RevX (tentativo {pos['_sell_failures']}). Posizione mantenuta, riprovando.")
                            if pos.get("_sell_failures", 0) >= 3:
                                pos["_manual_action_required"] = True
                                add_log(state, "info", "WARN", f"{sym}: 3 vendite fallite — posizione mantenuta, verifica manualmente su RevX")
                                await notify(state, f"WARN: {sym} ha 3 vendite fallite. Posizione mantenuta in Zentra, verifica manualmente su RevX.")
                                _exiting.discard(sym); return
                            else:
                                _exiting.discard(sym); return
                        elif market_cancelled:
                            # RevX slippage protection: market order rifiutato — avvia retry GTC limit
                            add_log(state, "info", "WARN", f"{sym}: market sell cancellato (slippage protection) → retry GTC limit")
                            print(f"[REVX SELL] {sym} market cancelled (slippage), avvio GTC retry")
                            pos["_sell_reason"] = reason
                            pos["_sell_original_price"] = cur
                            pos["_sell_qty"] = qty_to_sell
                            await _place_revx_gtc_limit(state, pos, 0, user_id)
                            _exiting.discard(sym); return
                        else:
                            pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                            add_log(state, "info", "ERRORE", f"Vendita RevX {sym} fallita ({pos['_sell_failures']}x): {err_msg}")
                            await notify(state, f"ERRORE VENDITA RevX {sym}: {err_msg[:100]}")
                            if pos.get("_sell_failures", 0) >= 3:
                                pos["_manual_action_required"] = True
                                add_log(state, "info", "WARN", f"{sym}: 3 vendite fallite — posizione mantenuta, verifica manualmente su RevX")
                                await notify(state, f"WARN: {sym} ha 3 vendite fallite. Posizione mantenuta in Zentra, verifica manualmente su RevX.")
                                _exiting.discard(sym); return
                            else:
                                _exiting.discard(sym); return
                    if not sold_externally and order_id and not market_cancelled:
                        od = await wait_revx_order_fill(order_id, revx_key_id, revx_priv)
                        filled_price = od.get("average_fill_price", 0.0)
                        filled_qty = od.get("filled_quantity", 0.0)
                        if filled_price <= 0 or filled_qty <= 0:
                            state_txt = od.get("state") or "sconosciuto"
                            pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                            add_log(state, "info", "WARN", f"{sym}: vendita market non confermata (state={state_txt}) — posizione mantenuta")
                            await notify(state, f"WARN {sym}: vendita market non confermata (state={state_txt}). Posizione mantenuta, verifica RevX.")
                            _exiting.discard(sym); return
                        cur = filled_price
                        sell_fee_usd = od.get("total_fee", 0.0) if od.get("fee_currency", "USD") == "USD" else od.get("total_fee", 0.0) * cur
                        pos["sell_fee_usd"] = pos.get("sell_fee_usd", 0.0) + sell_fee_usd
                        pos["_sell_type"] = "Market"
                        add_log(state, "info", "VENDUTO RevX", f"{sym} qty: {qty_to_sell:.6f} @ ${cur:.4f} fee=${sell_fee_usd:.4f}")
                        if partial:
                            pos["qty_purchased"] = qty_purchased - qty_to_sell
                if sold_externally:
                    add_log(state, "info", "VENDUTO RevX (ext)", f"{sym} venduto esternamente @ ${cur:.4f} (prezzo stimato)")
                    await notify(state, f"WARN: {sym} venduto esternamente su RevX. Trade registrato al prezzo corrente.")
            except Exception as e:
                add_log(state, "info", "ERRORE", f"RevX exit error: {e}")
                _exiting.discard(sym); return

        # ── COINBASE EXIT ────────────────────────────────────────────────────
        if pos.get("exchange") == "coinbase" and not pos.get("_already_sold"):
            qty_purchased = pos.get("qty_purchased", 0.0)
            if qty_purchased <= 0:
                add_log(state, "info", "ERRORE", f"qty_purchased non disponibile per {sym} Coinbase — vendita annullata")
                _exiting.discard(sym); return
            if not user_id:
                add_log(state, "info", "ERRORE", f"user_id mancante per vendita Coinbase {sym}")
                _exiting.discard(sym); return
            try:
                import uuid as _uuid
                api_key, api_secret = await load_coinbase_keys_for_user(user_id)
                qty_to_sell = round(qty_purchased * 0.5, 8) if partial else round(qty_purchased, 8)
                symbol_pair = pos.get("symbol_pair", f"{sym}-USDC").replace("/", "-")
                try:
                    accounts = await fetch_coinbase_accounts(api_key, api_secret)
                    real_qty = sum(float(a.get("available") or 0) for a in accounts if a.get("currency") == sym)
                    if real_qty > 0:
                        qty_to_sell_real = round(real_qty * (0.5 if partial else 1.0), 8)
                        qty_to_sell = min(qty_to_sell, qty_to_sell_real)
                        pos["qty_purchased"] = real_qty
                    else:
                        pos["_manual_action_required"] = True
                        add_log(state, "info", "WARN", f"{sym}: saldo disponibile Coinbase = 0 — vendita annullata, posizione mantenuta")
                        await notify(state, f"WARN {sym}: saldo disponibile Coinbase = 0. Posizione mantenuta in Zentra, verifica su Coinbase.")
                        _exiting.discard(sym); return
                except Exception as be:
                    err = public_error(be)
                    pos["_manual_action_required"] = True
                    add_log(state, "info", "WARN", f"{sym}: impossibile leggere saldo Coinbase — posizione mantenuta: {err}")
                    _exiting.discard(sym); return
                order_body = {
                    "client_order_id": str(_uuid.uuid4()),
                    "product_id": symbol_pair,
                    "side": "SELL",
                    "order_configuration": {
                        "market_market_ioc": {
                            "base_size": f"{qty_to_sell:.8f}",
                            "rfq_disabled": True,
                        }
                    },
                }
                result = await coinbase_request(
                    "POST", "/api/v3/brokerage/orders",
                    body=order_body, api_key=api_key, api_secret=api_secret
                )
                if result.get("success") is False:
                    err = result.get("error_response") or result.get("failure_reason") or result
                    pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                    add_log(state, "info", "ERRORE", f"Vendita Coinbase {sym} fallita ({pos['_sell_failures']}x): {str(err)[:120]}")
                    await notify(state, f"ERRORE VENDITA Coinbase {sym}: {str(err)[:100]}")
                    if pos.get("_sell_failures", 0) >= 3:
                        pos["_manual_action_required"] = True
                    _exiting.discard(sym); return
                order_id = extract_coinbase_order_id(result)
                if not order_id:
                    pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                    add_log(state, "info", "ERRORE", f"Vendita Coinbase {sym} senza order_id")
                    _exiting.discard(sym); return
                od = await wait_coinbase_order_fill(order_id, api_key, api_secret)
                try:
                    filled_price = float(od.get("average_filled_price") or 0)
                    filled_qty = float(od.get("filled_size") or 0)
                    sell_fee_usd = float(od.get("total_fees") or 0)
                except Exception:
                    filled_price = 0.0
                    filled_qty = 0.0
                    sell_fee_usd = 0.0
                if filled_price <= 0 or filled_qty <= 0:
                    state_txt = od.get("status") or "sconosciuto"
                    pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                    add_log(state, "info", "WARN", f"{sym}: vendita Coinbase non confermata (state={state_txt}) — posizione mantenuta")
                    await notify(state, f"WARN {sym}: vendita Coinbase non confermata (state={state_txt}). Posizione mantenuta.")
                    _exiting.discard(sym); return
                cur = filled_price
                pos["sell_fee_usd"] = pos.get("sell_fee_usd", 0.0) + sell_fee_usd
                pos["_sell_type"] = "Coinbase Market"
                add_log(state, "info", "VENDUTO Coinbase", f"{sym} qty: {filled_qty:.8f} @ ${cur:.4f} fee=${sell_fee_usd:.4f}")
                if partial:
                    pos["qty_purchased"] = max(qty_purchased - filled_qty, 0.0)
            except Exception as e:
                err = public_error(e)
                add_log(state, "info", "ERRORE", f"Coinbase exit error: {err}")
                _exiting.discard(sym); return

    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * close_size
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    fee_pct = pos.get("fee_pct", 0.0009)
    exit_fee = close_size * fee_pct
    # Per real mode usa fee reali dagli exchange supportati, altrimenti stima
    if pos.get("realMode") and pos.get("exchange") in ("revx", "coinbase"):
        sell_fee_real = pos.get("sell_fee_usd", exit_fee)
        pnl = pnl - sell_fee_real - pos.get("buy_fee_usd", 0.0)
        exit_fee = sell_fee_real
    else:
        pnl -= exit_fee

    if partial:
        # TP1: restituisce metà capitale, aggiorna size_remaining
        # Il nuovo stop viene gestito dal trailing in scan_and_trade
        state["currentCapital"] += close_size + pnl
        pos["size_remaining"] -= close_size
        pos["stopPrice"]       = pos["entryPrice"]  # breakeven minimo
        pos["tp1_hit"]         = True
        pos["tp1_pnl"]         = pnl  # salviamo per il messaggio finale
        pos["qty_tp1_sold"]    = qty_to_sell  # qty venduta a TP1 per calcolo proporzione
        _exiting.discard(sym)
        if pos.get("realMode") and user_id:
            await persist_sessions()
        return  # posizione resta aperta per TP2

    # Chiusura totale
    # Usa size originale per il PnL finale (già parte è stata realizzata a TP1)
    state["currentCapital"] += pos["size_remaining"] + pnl
    state["tradeCount"] += 1

    # P&L totale = secondo leg + TP1 parziale già realizzato
    tp1_pnl   = pos.get("tp1_pnl", 0)
    total_pnl = pnl + tp1_pnl
    total_pct = total_pnl / pos["size"] * 100 if pos["size"] > 0 else pct

    if total_pnl > 0:
        state["wins"] += 1
        state["consecutiveLosses"] = 0
    else:
        state["consecutiveLosses"] = state.get("consecutiveLosses", 0) + 1

    cfg = state["config"]
    # SL secco (senza TP1): cooldown doppio per evitare re-entry immediato su trend avverso
    is_clean_stop = ("STOP" in reason) and not pos.get("tp1_hit", False)
    cooldown_h = cfg.get("cooldown", 1) * (2.0 if is_clean_stop else 1.0)
    state["cooldowns"][sym] = (datetime.now().timestamp() + cooldown_h * 3600) * 1000
    buy_fee_usd  = pos.get("buy_fee_usd", 0.0)
    sell_fee_usd = pos.get("sell_fee_usd", exit_fee)
    trade_record = {
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": total_pnl, "pct": total_pct, "time": datetime.utcnow().isoformat() + "Z",
        "entryTime": pos["entryTime"], "durationMin": round(dur, 1),
        "size": pos["size"], "realMode": pos.get("realMode", False),
        "tp1_hit": pos.get("tp1_hit", False),
        "buyFee": round(buy_fee_usd, 4), "sellFee": round(sell_fee_usd, 4),
        "sellType": pos.get("_sell_type", "Market"),
    }
    state["trades"].append(trade_record)
    if db_pool and user_id:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO trades_history
                    (user_id, symbol, entry_price, exit_price, size, pnl, pct,
                     reason, tp1_hit, duration_min, entry_time, exit_time, mode,
                     buy_fee, sell_fee, sell_type)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                """, user_id, sym,
                    float(pos["entryPrice"]), float(cur),
                    float(pos["size"]), float(total_pnl), float(total_pct),
                    reason, bool(pos.get("tp1_hit", False)), float(round(dur, 1)),
                    pos["entryTime"], datetime.utcnow().isoformat() + "Z",
                    "real" if pos.get("realMode") else "sim",
                    float(buy_fee_usd), float(sell_fee_usd),
                    pos.get("_sell_type", "Market")
                )
        except Exception as e:
            print(f"DB trade save error: {e}")
    state["positions"] = [p for p in state["positions"] if p is not pos]
    _exiting.discard(sym)
    if user_id:
        await persist_sessions()
    mode = "REALE" if pos.get("realMode") else "SIM"
    add_log(state, "sell", f"{reason} {mode}",
        f"{sym} @ {_fp(cur)} | {total_pnl:+.2f}$ ({total_pct:+.2f}%) | fee: ${exit_fee:.2f} | {dur:.0f} min")
    esito = "PROFITTO" if total_pnl >= 0 else "PERDITA"
    if pos.get("realMode"):
        curr = "$"
        if tp1_pnl:
            msg = ("VENDITA REALE - " + esito + "\n" + sym + " @ " + curr + f"{cur:.4f}" +
                   "\nP&L seconda metà: " + f"{pnl:+.2f}" + curr +
                   "\nP&L totale: " + f"{total_pnl:+.2f}" + curr)
        else:
            msg = ("VENDITA REALE - " + esito + "\n" + sym + " @ " + curr + f"{cur:.4f}" +
                   "\nP&L: " + f"{total_pnl:+.2f}" + curr)
        await notify(state, msg)
    else:
        if tp1_pnl:
            sim_msg = ("VENDITA SIM - " + esito + "\n" + sym + " @ $" + f"{cur:.4f}" +
                       "\nP&L seconda metà: " + f"{pnl:+.2f}$" +
                       "\nP&L totale: " + f"{total_pnl:+.2f}$")
        else:
            sim_msg = ("VENDITA SIM - " + esito + "\n" + sym + " @ $" + f"{cur:.4f}" +
                       "\nP&L: " + f"{total_pnl:+.2f}$")
        await notify(state, sim_msg)

    # Controllo stop automatico per perdite consecutive
    max_losses = cfg.get("maxConsecutiveLosses", 0)
    if max_losses > 0 and state.get("consecutiveLosses", 0) >= max_losses:
        if not state.get("_draining"):
            state["_draining"] = True
            add_log(state, "info", "STOP AUTO",
                f"{max_losses} perdite consecutive — nuovi ingressi bloccati, posizioni esistenti monitorate")
            await notify(state,
                f"⚠️ STOP AUTO: {max_losses} perdite consecutive\n"
                "Nessun nuovo ingresso. Le posizioni aperte restano monitorate fino alla chiusura.")

# ── main loop ─────────────────────────────────────────────────────────────────

async def scan_and_trade(state: dict, user_id: int = None):
    if not state["running"] or state.get("_stopping"):
        return

    cfg = state["config"]

    elapsed_ms = (datetime.now().timestamp() - (state["sessionStart"] or 0)) * 1000
    session_duration = state["sessionDuration"]
    if session_duration > 0 and elapsed_ms >= session_duration:
        if state["positions"]:
            if not state.get("_draining"):
                state["_draining"] = True
                add_log(state, "info", "FINE SESSIONE",
                    "Durata massima raggiunta — in attesa chiusura posizioni aperte.")
                await notify(state,
                    "⏰ Sessione scaduta\n"
                    "Nessun nuovo ingresso. Le posizioni aperte restano monitorate fino alla chiusura.")
        else:
            state["running"] = False
            add_log(state, "info", "FINE SESSIONE", "Durata massima raggiunta.")
            await persist_sessions()
            return

    # Controllo maxTrades
    max_trades = cfg.get("maxTrades", 0)
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        if state["positions"]:
            if not state.get("_draining"):
                state["_draining"] = True
                add_log(state, "info", "STOP AUTO",
                    f"Raggiunto limite di {max_trades} trade — nuovi ingressi bloccati, posizioni esistenti monitorate")
        else:
            state["running"] = False
            add_log(state, "info", "STOP AUTO", f"Raggiunto limite di {max_trades} trade — sessione fermata")
            return

    # Circuit breaker: perdita giornaliera massima
    today_utc = datetime.utcnow().strftime("%Y-%m-%d")
    if state.get("daily_date") != today_utc:
        state["daily_date"]          = today_utc
        state["daily_capital_start"] = state["currentCapital"]
    if cfg.get("circuitBreakerEnabled", False):
        daily_start = state.get("daily_capital_start", state["currentCapital"])
        if daily_start > 0:
            daily_loss_pct = (daily_start - state["currentCapital"]) / daily_start
            limit = cfg.get("dailyLossLimit", 0.03)
            if daily_loss_pct >= limit:
                state["running"] = False
                add_log(state, "info", "CIRCUIT BREAKER",
                    f"Perdita giornaliera {daily_loss_pct*100:.1f}% — soglia {limit*100:.0f}% raggiunta. Bot fermato per oggi.")
                await notify(state,
                    f"🚨 CIRCUIT BREAKER\n"
                    f"Perdita giornaliera: {daily_loss_pct*100:.1f}%\n"
                    f"Soglia: {limit*100:.0f}%\n"
                    f"Bot fermato fino a mezzanotte UTC.")
                await persist_sessions()
                return

    # Sync RevX: rileva posizioni agente chiuse esternamente (ogni 30s)
    use_revx     = state.get("use_revx", False)
    revx_key_id  = state.get("revx_key_id", "")
    revx_priv    = state.get("revx_private_key", "")
    revx_positions = [p for p in state["positions"] if p.get("exchange") == "revx" and p.get("realMode") and not p.get("manual")]
    if use_revx and revx_key_id and revx_priv and revx_positions:
        now_ts = time.time()
        if now_ts - state.get("_revx_agent_sync_last", 0) >= 30:
            state["_revx_agent_sync_last"] = now_ts
            try:
                result   = await revx_request("GET", "/api/1.0/balances", key_id=revx_key_id, private_key=revx_priv)
                bal_list = parse_revx_balances(result)
                bal_map  = {b["currency"]: float(b.get("available", 0) or 0) for b in bal_list if isinstance(b, dict)}
                for pos in list(revx_positions):
                    sym      = pos["symbol"]
                    qty      = pos.get("qty_purchased", 0.0)
                    coin_bal = bal_map.get(sym, 0.0)
                    if qty > 0 and coin_bal < qty * 0.05:
                        cur = market_data.get(sym, {}).get("price", pos["currentPrice"])
                        pos["currentPrice"]  = cur
                        pos["_already_sold"] = True
                        await exit_position(state, pos, "CHIUSO SU REVOLUT X", user_id=user_id)
            except Exception as e:
                print(f"[revx_agent_sync] user {user_id}: {e}")

    # Poll ordini GTC limit in attesa di fill
    for pos in list(state["positions"]):
        if pos.get("_sell_mode") == "retry_limit" and pos.get("realMode") and pos.get("exchange") == "revx":
            await _poll_revx_gtc_limit(state, pos, user_id)

    # Gestione posizioni aperte: hard stop + trailing profit stop
    for pos in list(state["positions"]):
        # Posizione in attesa di GTC limit fill: salta SL/TP
        if pos.get("_sell_mode") == "retry_limit":
            continue
        cur   = pos["currentPrice"]
        entry = pos["entryPrice"]

        max_hold_hours = cfg.get("maxHoldHours", 4)

        # Max hold time: chiude se la posizione è aperta da troppo
        if max_hold_hours > 0:
            dur_min = (datetime.utcnow() - datetime.fromisoformat(pos["entryTime"].replace("Z", ""))).total_seconds() / 60
            if dur_min >= max_hold_hours * 60:
                await exit_position(state, pos, "MAX TEMPO", user_id=user_id)
                continue

        # Aggiorna il picco di prezzo raggiunto dalla posizione
        if cur > pos.get("peak_price", entry):
            pos["peak_price"] = cur
        if cur > pos.get("highPrice", entry):
            pos["highPrice"] = cur

        # Hard stop fisso: protezione catastrofica, non si muove mai
        if cur <= pos["stopPrice"]:
            await exit_position(state, pos, "STOP LOSS", user_id=user_id)
            continue

        # Trailing profit stop: si attiva solo quando la posizione è in profitto netto
        # Profitto netto = profitto lordo - commissioni round-trip - slippage IOC sell
        fee_rt      = pos.get("fee_pct", 0.0009) * 2  # round-trip
        ioc_slip    = 0.001 if (state.get("use_revx") and pos.get("realMode")) else 0
        net_pnl_pct = (cur - entry) / entry - fee_rt - ioc_slip
        profit_activation = cfg.get("profitActivation", 0.003)
        if net_pnl_pct > profit_activation:
            pos["trailingActive"] = True
        if pos.get("trailingActive"):
            peak = pos.get("peak_price", cur)
            atr  = pos.get("atr_5m", 0.0)
            mult = cfg.get("trailAtrMultiplier", 2.0)
            if atr > 0:
                trail_price = peak - atr * mult
            else:
                trail_price = peak - (peak - entry) * cfg.get("profitTolerance", 0.20)
            if cur <= trail_price:
                await exit_position(state, pos, "TRAILING PROFIT", user_id=user_id)
                continue

    # Drenaggio attivo: nessun nuovo ingresso. Ferma la sessione appena tutte le posizioni sono chiuse.
    if state.get("_draining"):
        if not state["positions"]:
            state["running"] = False
            state.pop("_draining", None)
            add_log(state, "info", "STOP", "Tutte le posizioni chiuse — sessione terminata.")
            await notify(state, "✅ Zentra — sessione terminata\nTutte le posizioni aperte sono state chiuse.")
            await persist_sessions()
        else:
            _update_pnl(state)
        return

    alloc_pct   = min(cfg.get("allocPct", 0.20), 1.0)
    fixed_amt   = cfg.get("tradeAmountUsd", 0)
    capital_pct = cfg.get("capitalPct", 1.0)
    TRADING_FEE = 0.0009  # RevX taker fee 0.09%

    # Calcola il capitale tradabile dinamicamente
    if cfg.get("realMode", False) and state.get("use_revx", False):
        revx_key_id = state.get("revx_key_id", "")
        revx_priv   = state.get("revx_private_key", "")
        try:
            usd_balance = await get_revx_usd_balance(revx_key_id, revx_priv)
            tradable_capital = usd_balance * capital_pct
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Fetch saldo RevX fallito: {e}")
            _update_pnl(state)
            return
    else:
        # Coinbase real mode e SIM: usa currentCapital (aggiornato dopo ogni trade)
        tradable_capital = state["currentCapital"] * capital_pct

    # Ferma solo se il saldo reale non è sufficiente ad aprire nemmeno un trade minimo
    # Usa il saldo attuale (non il capitale dichiarato) per evitare stop falsi dopo perdite
    min_trade_size = tradable_capital * alloc_pct
    open_positions = state["positions"]
    if min_trade_size < 1.0 and cfg.get("realMode", False):
        if open_positions:
            _now = time.time()
            if _now - state.get("_last_monitor_log", 0) >= 60:
                state["_last_monitor_log"] = _now
                n = len(open_positions)
                pos_label = "posizioni aperte" if n > 1 else "posizione aperta"
                add_log(state, "info", "MONITOR",
                    f"{n} {pos_label} — saldo libero ${tradable_capital:.2f} | monitoring attivo")
            _update_pnl(state)
            return
        # Evita falso stop per settlement delay: se currentCapital è molto > saldo letto,
        # il saldo è probabilmente in transito (RevX non ha ancora accreditato la vendita)
        elif state.get("currentCapital", 0) > tradable_capital * 5:
            add_log(state, "info", "INFO",
                f"Saldo RevX in attesa settlement (${tradable_capital:.2f}) — attesa")
            _update_pnl(state)
            return
        else:
            state["running"] = False
            add_log(state, "info", "STOP AUTO",
                f"Saldo insufficiente per aprire nuovi trade (${tradable_capital:.2f}) — sessione fermata")
            await notify(state, f"STOP AUTO: saldo insufficiente ${tradable_capital:.2f}")
            return
    elif tradable_capital < 1.0 and not cfg.get("realMode", False):
        # Sim con capitale esaurito
        add_log(state, "info", "INFO", f"Capitale sim esaurito (${tradable_capital:.2f}) — attesa recupero da posizioni aperte")
        _update_pnl(state)
        return

    # Pausa manuale: SL/TP continuano, nessun nuovo ingresso
    if state.get("paused", False):
        _update_pnl(state)
        return

    # Numero massimo di posizioni aperte contemporaneamente
    is_free = state.get("plan", "free") == "free"
    max_pos   = FREE_MAX_POSITIONS if is_free else max(1, int(1 / alloc_pct))
    open_syms = {p["symbol"] for p in state["positions"]}
    slots     = max_pos - len(state["positions"])
    if is_free and slots <= 0:
        add_log(state, "info", "PIANO FREE", "Limite di 1 posizione contemporanea raggiunto. Passa a Pro per aprire più posizioni.")
        await notify(state, "⚠️ Piano Free: limite 1 posizione raggiunto.")
        _update_pnl(state)
        return

    # Sottrai le commissioni round-trip attese per tutte le posizioni apribili
    # fee_totale = size_per_trade * 1.2% * slot_disponibili
    size_per_trade = round(fixed_amt, 2) if fixed_amt and fixed_amt > 0 else tradable_capital * alloc_pct
    fee_reserve = size_per_trade * TRADING_FEE * 2 * slots  # entrata + uscita per ogni slot
    tradable_capital_net = tradable_capital - fee_reserve

    # Non aprire nuove posizioni se maxTrades raggiunto
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        _update_pnl(state)
        return

    if slots <= 0:
        _update_pnl(state)
        return
    if tradable_capital < state["capital"] * alloc_pct * capital_pct * 0.5:
        add_log(state, "info", "SCAN", "Capitale insufficiente per nuovi trade")
        _update_pnl(state)
        return

    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]

    # Filtro orario: niente operazioni 00:00-07:00 UTC (liquidità bassa)
    time_filter = cfg.get("timeFilter", True)
    if time_filter:
        utc_hour = datetime.utcnow().hour
        if 0 <= utc_hour < 7:
            add_log(state, "info", "PAUSA",
                f"Filtro orario — bassa liquidità (UTC {utc_hour:02d}:xx, pausa 00:00-07:00)")
            _update_pnl(state)
            return

    # Daily loss limit: pausa se perdita > 5% del capitale iniziale della sessione
    if state["pnlHistory"]:
        last_pnl = state["pnlHistory"][-1]["v"]
        if last_pnl < -state["capital"] * 0.05:
            add_log(state, "warning", "PAUSA",
                f"Loss sessione {abs(last_pnl/state['capital']*100):.1f}% > 5% — agente in pausa per il resto della sessione")
            _update_pnl(state)
            return

    # Filtro BTC: deve essere sopra EMA50 su 1h con tolleranza 0.3%
    # EMA50 1h è più stabile di EMA20 — meno falsi blocchi durante pullback normali
    btc_cd = candle_data.get("BTC", {})
    btc_ema20_1h = btc_cd.get("ema20_1h", 0)
    btc_ema50_1h = btc_cd.get("ema50_1h", 0)
    btc_price    = market_data.get("BTC", {}).get("price", 0)
    btc_filter   = cfg.get("btcEmaFilter", True)
    if btc_filter and btc_ema50_1h > 0 and btc_price > 0:
        tolerance = btc_ema50_1h * 0.003  # 0.3% sotto EMA50 è ancora accettabile
        if btc_price < btc_ema50_1h - tolerance:
            add_log(state, "info", "PAUSA",
                f"BTC sotto EMA50 1h (${btc_price:.0f} < ${btc_ema50_1h:.0f}) — agente in attesa")
            _update_pnl(state)
            return

    min_vol      = cfg.get("minVolume", 0)
    max_stop_pct   = cfg.get("maxStopPct", 0.02)
    vol_mult       = cfg.get("volMultiplier", 1.2)
    momentum_thr   = cfg.get("momentumPct", 0.01)

    use_revx_filter = state.get("use_revx", False)
    _now_ms = datetime.now().timestamp() * 1000
    universe = [
        {**d, "symbol": sym}
        for sym, d in market_data.items()
        if d["price"] > 0
        and sym in _dynamic_universe
        and (min_vol == 0 or d.get("volume24h", 0) >= min_vol)
        and sym not in open_syms
        and (not use_revx_filter or not _revx_pairs or sym in _revx_pairs)
        and sym in candle_data
        and (state["cooldowns"].get(sym, 0) < _now_ms)
    ]
    universe_sorted = sorted(universe, key=lambda d: d.get("volume24h", 0), reverse=True)

    candidates   = []
    skipped      = 0
    strategy = cfg.get("strategy", "momentum")
    if strategy == "breakout":
        block_count = {"consolidation": 0, "breakout": 0, "vol": 0, "fresh": 0}
    else:
        block_count = {"breakout": 0, "vol": 0, "rsi": 0,
                        "decomp": 0, "wick": 0, "keltner": 0, "tsi": 0, "macd": 0}

    for d in universe_sorted:
        sym = d["symbol"]
        if strategy == "breakout":
            signal = get_breakout_signal(
                sym, d["price"], max_stop_pct,
                chop_min=cfg.get("chopMin", 61.8),
                atr_ratio_max=cfg.get("atrRatioMax", 0.85),
                vol_multiplier=cfg.get("breakoutVolMultiplier", 1.5),
            )
            if not signal["signal"]:
                skipped += 1
                if   not signal.get("consolidation_ok"): block_count["consolidation"] += 1
                elif not signal.get("breakout_ok"):       block_count["breakout"]      += 1
                elif not signal.get("vol_ok"):            block_count["vol"]           += 1
                elif not signal.get("fresh_ok"):          block_count["fresh"]         += 1
                continue
        else:
            signal = get_momentum_signal(sym, d["price"], max_stop_pct, vol_mult, momentum_thr)
            if not signal["signal"]:
                skipped += 1
                if   not signal.get("breakout_ok"):  block_count["breakout"]  += 1
                elif not signal.get("vol_ok"):        block_count["vol"]       += 1
                elif not signal.get("rsi_ok"):        block_count["rsi"]       += 1
                elif not signal.get("decomp_ok"):     block_count["decomp"]    += 1
                elif not signal.get("wick_ok"):       block_count["wick"]      += 1
                elif not signal.get("keltner_ok"):    block_count["keltner"]   += 1
                elif not signal.get("tsi_ok"):        block_count["tsi"]       += 1
                elif not signal.get("macd_ok"):       block_count["macd"]      += 1
                continue
        d["ema_reason"] = signal["reason"]
        d["stop_price"] = signal["stop_price"]
        d["R_pct"]      = max_stop_pct
        candidates.append(d)
        if len(candidates) >= slots:
            break

    bc = block_count
    if strategy == "breakout":
        scan_detail = (
            f"CHOP:{bc.get('consolidation',0)} BRK:{bc.get('breakout',0)} "
            f"VOL:{bc.get('vol',0)} FRESH:{bc.get('fresh',0)}"
        )
    else:
        scan_detail = (
            f"MOM:{bc.get('breakout',0)} VOL:{bc.get('vol',0)} RSI:{bc.get('rsi',0)} "
            f"DCMP:{bc.get('decomp',0)} WICK:{bc.get('wick',0)} KELT:{bc.get('keltner',0)} "
            f"TSI:{bc.get('tsi',0)} MACD:{bc.get('macd',0)}"
        )
    add_log(state, "info", "SCAN",
        f"Universe: {len(universe_sorted)} | Candidati: {len(candidates)} | Saltati: {skipped} | "
        f"{scan_detail} | Candele:{len(candle_data)}"
    )

    for d in candidates:
        sym = d["symbol"]
        add_log(state, "info", "SEGNALE", f"{sym} | {d.get('ema_reason', '')}")
        await enter_position(state, d, tradable_capital_net)

    _update_pnl(state)

def _update_pnl(state: dict):
    if not state["sessionStart"]:
        return
    unr     = unrealized_pnl(state)
    # Usa size_remaining (non size) per evitare doppio conteggio dopo TP1 parziale
    pos_val = sum(p.get("size_remaining", p["size"]) for p in state["positions"])
    total   = state["currentCapital"] + pos_val + unr
    pnl_val = total - state["capital"]
    t       = (datetime.now().timestamp() - state["sessionStart"]) / 60
    state["pnlHistory"].append({"t": t, "v": pnl_val})
    if len(state["pnlHistory"]) > 500:
        state["pnlHistory"].pop(0)

# ── Telegram polling ──────────────────────────────────────────────────────────

_tg_last_update: int = 0
_tg_poll_lock = asyncio.Lock()
_tg_processed_ids: set = set()
_revx_wizard: dict[str, dict] = {}  # chat_id → {step, uid, os, api_key}

async def tg_send_keyboard(chat_id: str, text: str, buttons: list):
    """Invia messaggio Telegram con inline keyboard."""
    if not TELEGRAM_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                      "reply_markup": {"inline_keyboard": buttons}}
            )
    except Exception as e:
        print(f"TG keyboard error: {e}")

async def tg_answer_callback(callback_id: str):
    """Risponde al callback_query per togliere il loading dal bottone."""
    if not TELEGRAM_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/answerCallbackQuery",
                json={"callback_query_id": callback_id}
            )
    except Exception:
        pass

async def handle_revx_wizard(chat_id: str, uid: int, event: str, data: str):
    """
    Gestisce il wizard /configrevx step-by-step.
    event: 'start' | 'callback' | 'text'
    data:  callback_data oppure testo inviato dall'utente
    """
    wizard = _revx_wizard.get(chat_id, {})
    step   = wizard.get("step", "")

    # ── START ──────────────────────────────────────────────────────────────────
    if event == "start":
        _revx_wizard[chat_id] = {"step": "os", "uid": uid}
        await tg_send_keyboard(chat_id,
            "⚙️ <b>Configurazione Revolut X</b>\n\n"
            "Ti guido in 5 minuti.\n"
            "Dovrai eseguire 2 comandi nel terminale del tuo computer.\n\n"
            "Che sistema operativo usi?",
            [[{"text": "🍎  macOS / Linux", "callback_data": "revx_os_mac"},
              {"text": "🪟  Windows",        "callback_data": "revx_os_win"}]]
        )
        return

    # ── CALLBACK (bottoni) ─────────────────────────────────────────────────────
    if event == "callback":

        if data in ("revx_os_mac", "revx_os_win"):
            os_key = "mac" if data == "revx_os_mac" else "win"
            _revx_wizard[chat_id]["os"]   = os_key
            _revx_wizard[chat_id]["step"] = "terminal"
            if os_key == "mac":
                msg = ("📂 <b>Apri il Terminale</b>\n\n"
                       "Vai in <b>Applicazioni → Utility → Terminale</b>\n"
                       "oppure premi <b>Cmd+Spazio</b> e cerca <i>Terminale</i>.\n\n"
                       "Quando è aperto, devi installare OpenSSL. "
                       "Esegui questi comandi <b>uno alla volta</b> "
                       "(copia → incolla → Invio → aspetta che finisca → poi il prossimo):\n\n"
                       "① Installa Homebrew:\n"
                       "<code>/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"</code>\n\n"
                       "② Attiva Homebrew nella sessione corrente:\n"
                       "<code>eval \"$(/opt/homebrew/bin/brew shellenv zsh)\"</code>\n\n"
                       "③ Installa OpenSSL:\n"
                       "<code>brew install openssl</code>\n\n"
                       "⚠️ Se Homebrew era già installato, esegui solo ② e ③.")
            else:
                msg = ("📂 <b>Apri PowerShell</b>\n\n"
                       "Premi <b>Win+X</b> → <b>Windows PowerShell</b>\n"
                       "oppure cerca <i>PowerShell</i> nel menu Start.\n\n"
                       "⚠️ Verifica che OpenSSL sia installato:\n"
                       "<code>openssl version</code>")
            await tg_send_keyboard(chat_id, msg,
                [[{"text": "✅  Aperto, continua →", "callback_data": "revx_step_cmd1"}]])

        elif data == "revx_step_cmd1":
            _revx_wizard[chat_id]["step"] = "cmd1"
            os_key = wizard.get("os", "mac")
            if os_key == "mac":
                msg = ("1️⃣ <b>Genera la chiave privata</b>\n\n"
                       "Prima spostati sul Desktop (così trovi i file facilmente):\n"
                       "<code>cd ~/Desktop</code>\n\n"
                       "Poi esegui:\n"
                       "<code>$(brew --prefix openssl)/bin/openssl genpkey -algorithm ed25519 -out private.pem</code>")
            else:
                msg = ("1️⃣ <b>Genera la chiave privata</b>\n\n"
                       "Prima spostati sul Desktop:\n"
                       "<code>cd %USERPROFILE%\\Desktop</code>\n\n"
                       "Poi esegui:\n"
                       "<code>openssl genpkey -algorithm ed25519 -out private.pem</code>")
            await tg_send_keyboard(chat_id, msg,
                [[{"text": "✅  Fatto, continua →", "callback_data": "revx_step_cmd2"}]])

        elif data == "revx_step_cmd2":
            _revx_wizard[chat_id]["step"] = "cmd2"
            os_key = wizard.get("os", "mac")
            if os_key == "mac":
                cmd2 = "$(brew --prefix openssl)/bin/openssl pkey -in private.pem -pubout -out public.pem"
            else:
                cmd2 = "openssl pkey -in private.pem -pubout -out public.pem"
            await tg_send_keyboard(chat_id,
                f"2️⃣ <b>Genera la chiave pubblica</b>\n\n"
                f"Esegui questo comando:\n\n"
                f"<code>{cmd2}</code>\n\n"
                f"Trovi ora due file sul <b>Desktop</b>:\n"
                f"📄 <b>private.pem</b>  —  chiave privata (tienila al sicuro)\n"
                f"📄 <b>public.pem</b>   —  chiave pubblica",
                [[{"text": "✅  Fatto, continua →", "callback_data": "revx_step_register"}]])

        elif data == "revx_step_register":
            _revx_wizard[chat_id]["step"] = "register"
            os_key = wizard.get("os", "mac")
            if os_key == "mac":
                open_hint = ("Per leggere il contenuto di public.pem:\n"
                             "• Terminale: <code>cat ~/Desktop/public.pem</code>\n"
                             "• Oppure: tasto destro sul file → <b>Apri con → TextEdit</b>")
            else:
                open_hint = ("Per leggere il contenuto di public.pem:\n"
                             "• PowerShell: <code>type %USERPROFILE%\\Desktop\\public.pem</code>\n"
                             "• Oppure: tasto destro sul file → <b>Apri con → Blocco Note</b>")
            _revx_wizard.pop(chat_id, None)
            await send_telegram_to(chat_id,
                f"3️⃣ <b>Registra la chiave su Revolut X</b>\n\n"
                f"1. Vai su <b>exchange.revolut.com</b> → <b>Profile → API Keys</b> (da browser)\n"
                f"2. {open_hint}\n"
                f"3. Copia tutto il testo (incluse le righe BEGIN/END) e incollalo su Revolut X\n"
                f"4. Revolut genera una stringa di <b>64 caratteri</b> — è il tuo API Key\n\n"
                f"✅ <b>Ora torna su Zentra</b> → menu profilo → <b>Configura Revolut X</b> "
                f"e inserisci lì l'API Key e la chiave privata.")

async def poll_telegram():
    global _tg_last_update
    if not TELEGRAM_TOKEN:
        return
    if _tg_poll_lock.locked():
        return
    async with _tg_poll_lock:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                    params={"offset": _tg_last_update + 1, "timeout": 0}
                )
                data = r.json()
            results = data.get("result", [])
            if results:
                print(f"[TG] poll: {len(results)} update(s), ids={[u['update_id'] for u in results]}, last_known={_tg_last_update}")
            for update in results:
                uid_upd = update["update_id"]
                _tg_last_update = uid_upd
                msg_text = update.get("message", {}).get("text", "")
                print(f"[TG] update_id={uid_upd} cmd={msg_text!r}")
                if uid_upd in _tg_processed_ids:
                    print(f"[TG] skip {uid_upd}: in-memory dup")
                    continue
                # Deduplication DB: garantisce un solo processo per update anche con più istanze
                if db_pool:
                    try:
                        async with db_pool.acquire() as conn:
                            inserted = await conn.fetchval(
                                "INSERT INTO tg_updates (update_id) VALUES ($1) ON CONFLICT (update_id) DO NOTHING RETURNING update_id",
                                uid_upd
                            )
                        if inserted is None:
                            print(f"[TG] skip {uid_upd}: DB dup")
                            continue
                    except Exception as db_err:
                        print(f"[TG] DB check error: {db_err}")
                print(f"[TG] processing {uid_upd}: {msg_text!r}")
                _tg_processed_ids.add(uid_upd)
                if len(_tg_processed_ids) > 500:
                    _tg_processed_ids.discard(min(_tg_processed_ids))

                # ── callback_query (bottoni inline keyboard) ──────────────────
                cq = update.get("callback_query")
                if cq:
                    cq_id   = cq["id"]
                    cq_data = cq.get("data", "")
                    cq_from = str(cq.get("from", {}).get("id", ""))
                    await tg_answer_callback(cq_id)
                    if cq_data.startswith("revx_") and cq_from in _revx_wizard:
                        cq_uid = _revx_wizard[cq_from].get("uid")
                        if cq_uid:
                            await handle_revx_wizard(cq_from, cq_uid, "callback", cq_data)
                    continue

                # ── messaggi di testo normali ─────────────────────────────────
                msg = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                text = msg.get("text", "").strip()
                if not text or not chat_id:
                    continue

                cmd_parts = text.split()
                cmd = cmd_parts[0].upper()

                # /link <codice> — accessibile da qualsiasi chat, non richiede registrazione
                if cmd == "/LINK":
                    if len(cmd_parts) < 2:
                        await send_telegram_to(chat_id, "Usa: /link <codice>")
                        continue
                    code = cmd_parts[1].upper()
                    entry = _tg_link_codes.get(code)
                    if entry and entry[1] > time.time():
                        uid, _ = entry
                        del _tg_link_codes[code]
                        if db_pool:
                            async with db_pool.acquire() as conn:
                                await conn.execute(
                                    "UPDATE users SET telegram_chat_id = $1 WHERE id = $2", chat_id, uid
                                )
                        state = user_sessions.get(uid)
                        if state:
                            state["telegram_chat_id"] = chat_id
                        await send_telegram_to(chat_id,
                            "✅ Account collegato!\nOra puoi usare:\n/status — stato sessione\n/stop — ferma l'agente\n/close BTC — chiudi posizione\n/configrevx — configura Revolut X guidato")
                    else:
                        already_linked = False
                        if db_pool:
                            async with db_pool.acquire() as conn:
                                row_chk = await conn.fetchrow(
                                    "SELECT id FROM users WHERE telegram_chat_id = $1", chat_id
                                )
                            already_linked = bool(row_chk)
                        if not already_linked:
                            await send_telegram_to(chat_id, "❌ Codice non valido o scaduto. Genera un nuovo codice dall'app.")
                    continue

                # Per tutti gli altri comandi: trova l'utente dal chat_id registrato
                uid = None
                if db_pool:
                    async with db_pool.acquire() as conn:
                        user_row = await conn.fetchrow(
                            "SELECT id FROM users WHERE telegram_chat_id = $1", chat_id
                        )
                    if user_row:
                        uid = user_row["id"]

                # Fallback legacy: TELEGRAM_CHAT_ID globale per backward compat
                if uid is None and TELEGRAM_CHAT_ID and chat_id == str(TELEGRAM_CHAT_ID):
                    for s_uid, s in user_sessions.items():
                        if s.get("running"):
                            uid = s_uid
                            break

                if uid is None:
                    continue  # chat_id non riconosciuto

                state = user_sessions.get(uid)

                # Se wizard attivo e l'utente manda testo (non comando), gestisci come input wizard
                is_command = text.startswith("/")
                if chat_id in _revx_wizard:
                    if not is_command:
                        await handle_revx_wizard(chat_id, uid, "text", text)
                        continue
                    elif cmd != "/CONFIGREVX":
                        # Qualsiasi altro comando cancella il wizard
                        _revx_wizard.pop(chat_id, None)

                if cmd == "/CONFIGREVX":
                    await handle_revx_wizard(chat_id, uid, "start", "")
                elif cmd == "/STATUS":
                    if state and (state.get("running") or state.get("positions")):
                        pos_list = ", ".join([p["symbol"] for p in state["positions"]]) or "nessuna"
                        pnl = unrealized_pnl(state)
                        status_label = "Sessione attiva" if state.get("running") else "Monitoraggio posizioni"
                        paused_note = "\nStato: pausa, nessun nuovo ingresso" if state.get("paused") else ""
                        await send_telegram_to(chat_id, f"{status_label}{paused_note}\nPosizioni: {pos_list}\nP&L: ${pnl:.2f}")
                    else:
                        await send_telegram_to(chat_id, "Nessuna sessione attiva")

                elif cmd == "/STOP":
                    if state and state.get("running"):
                        closed = [p["symbol"] for p in list(state["positions"]) if not p.get("manual")]
                        state["_stopping"] = True
                        for p in list(state["positions"]):
                            if not p.get("manual"):
                                await exit_position(state, p, "STOP MANUALE", user_id=uid)
                        remaining_agent = [p for p in state.get("positions", []) if not p.get("manual")]
                        if remaining_agent:
                            state.pop("_stopping", None)
                            syms = ", ".join(p["symbol"] for p in remaining_agent)
                            add_log(state, "info", "ERRORE", f"Stop Telegram annullato: vendita fallita per {syms} — riprova")
                            await send_telegram_to(chat_id, f"⚠️ Stop annullato: vendita fallita per {syms}. Sessione ancora attiva.")
                            continue
                        state["running"] = False
                        state.pop("_stopping", None)
                        pnl = state["currentCapital"] - state["capital"]
                        add_log(state, "info", "STOP", f"P&L finale: {pnl:+.2f}$")
                        await persist_sessions()
                        msg = "✅ Agente fermato"
                        if closed:
                            msg += f"\nPosizioni chiuse: {', '.join(closed)}"
                        msg += f"\nP&L sessione: {pnl:+.2f}$"
                        await send_telegram_to(chat_id, msg)
                    else:
                        await send_telegram_to(chat_id, "Nessuna sessione attiva")

                elif cmd == "/CLOSE":
                    if len(cmd_parts) >= 2:
                        sym = cmd_parts[1].upper()
                        if state:
                            pos = next((p for p in state["positions"] if p["symbol"] == sym), None)
                            if pos:
                                await exit_position(state, pos, "TELEGRAM", user_id=uid)
                                if pos in state.get("positions", []):
                                    await send_telegram_to(chat_id, f"⚠️ Chiusura {sym} non confermata. Posizione ancora aperta, verifica su Zentra/Revolut X.")
                                else:
                                    await send_telegram_to(chat_id, f"✅ Posizione {sym} chiusa")
                            else:
                                await send_telegram_to(chat_id, f"Nessuna posizione aperta su {sym}")
                        else:
                            await send_telegram_to(chat_id, "Nessuna sessione attiva")
                    else:
                        await send_telegram_to(chat_id, "Uso: /close <SYM>")
        except Exception as e:
            print(f"Telegram poll error: {e}")

async def monitor_manual_positions(state: dict, user_id: int):
    """Monitora SL/TP e sync RevX per tutte le posizioni aperte quando l'agente è fermo."""
    revx_key_id  = state.get("revx_key_id", "")
    revx_priv    = state.get("revx_private_key", "")
    use_revx     = state.get("use_revx", False)

    # Sync RevX: rimuovi posizioni chiuse esternamente controllando i saldi
    if use_revx and revx_key_id and revx_priv:
        try:
            result = await revx_request("GET", "/api/1.0/balances", key_id=revx_key_id, private_key=revx_priv)
            balances = parse_revx_balances(result)
            bal_map = {b["currency"]: float(b.get("available", 0) or 0) for b in balances if isinstance(b, dict)}
            for pos in list(state["positions"]):
                if pos.get("exchange") != "revx":
                    continue
                sym = pos["symbol"]
                coin_bal = bal_map.get(sym, 0.0)
                qty = pos.get("qty_purchased", 0.0)
                if qty > 0 and coin_bal < qty * 0.05:
                    cur = market_data.get(sym, {}).get("price", pos["entryPrice"])
                    pos["currentPrice"] = cur
                    add_log(state, "sell", "CHIUSO ESTERNAMENTE",
                            f"{sym} — posizione non trovata su Revolut X (saldo {coin_bal:.6f})")
                    await notify(state, f"⚠️ {sym} chiuso esternamente su Revolut X")
                    state["positions"].remove(pos)
                    state["currentCapital"] += pos.get("size_remaining", pos["size"])
        except Exception as e:
            print(f"[revx_sync] user {user_id}: {e}")

    # SL / TP per tutte le posizioni (manuali e agente)
    for pos in list(state["positions"]):
        sym = pos["symbol"]
        if pos.get("exchange") == "coinbase" and pos.get("realMode"):
            try:
                api_key, api_secret = await load_coinbase_keys_for_user(user_id)
                cur = await get_coinbase_product_price(pos.get("symbol_pair", f"{sym}-USDC"), api_key, api_secret)
            except Exception as e:
                add_log(state, "info", "WARN", f"{sym}: prezzo Coinbase non disponibile — monitor SL/TP saltato: {public_error(e, max_len=100)}")
                continue
        else:
            cur = market_data.get(sym, {}).get("price", 0.0)
        if cur <= 0:
            continue
        pos["currentPrice"] = cur
        if cur > pos.get("peak_price", pos["entryPrice"]):
            pos["peak_price"] = cur

        if cur <= pos["stopPrice"]:
            await exit_position(state, pos, "STOP LOSS", user_id=user_id)
            continue

        tp = pos.get("tp1Price", 0.0)
        if tp > 0 and cur >= tp:
            await exit_position(state, pos, "TAKE PROFIT", user_id=user_id)
            continue

    _update_pnl(state)

# ── binance websocket stream ──────────────────────────────────────────────────

async def binance_ws_loop():
    global _ws_connected, _ws_last_msg_ts
    urls = [
        "wss://stream.binance.com:9443/ws/!miniTicker@arr",
        "wss://stream.binance.us:9443/ws/!miniTicker@arr",
    ]
    backoff = 5
    url_idx = 0
    while True:
        url = urls[url_idx % len(urls)]
        try:
            print(f"[WS] Connessione a {url} ...")
            async with websockets.connect(url, ping_interval=20, ping_timeout=30) as ws:
                _ws_connected = True
                backoff = 5
                print("[WS] ✅ Connesso — stream prezzi attivo")
                async for raw in ws:
                    _ws_last_msg_ts = time.time()
                    try:
                        tickers = json.loads(raw)
                        if not isinstance(tickers, list):
                            continue
                        for t in tickers:
                            pair = t.get("s", "")
                            if not pair.endswith("USDT"):
                                continue
                            sym = pair[:-4]
                            if not sym.isascii() or not sym.isalpha() or sym in STABLES:
                                continue
                            try:
                                price    = float(t["c"])
                                open_24h = float(t["o"])
                                vol_usd  = float(t["q"])
                            except (KeyError, ValueError, TypeError):
                                continue
                            if price <= 0:
                                continue
                            change24h = (price - open_24h) / open_24h * 100 if open_24h > 0 else 0.0
                            if sym not in market_data:
                                market_data[sym] = {"price": 0.0, "change1h": 0.0, "change24h": 0.0, "volume24h": 0.0, "icon": sym[0]}
                            cd = candle_data.get(sym)
                            change1h = ((price - cd["close_1h_ago"]) / cd["close_1h_ago"] * 100
                                        if cd and cd.get("close_1h_ago", 0) > 0
                                        else market_data[sym].get("change1h", 0.0))
                            market_data[sym]["price"]     = price
                            market_data[sym]["change1h"]  = change1h
                            market_data[sym]["change24h"] = change24h
                            market_data[sym]["volume24h"] = vol_usd
                            for state in list(user_sessions.values()):
                                for pos in list(state["positions"]):
                                    if pos["symbol"] == sym:
                                        pos["currentPrice"] = price
                                        if price > pos["highPrice"]:
                                            pos["highPrice"] = price
                    except Exception as parse_err:
                        print(f"[WS] Errore parsing: {parse_err}")
        except Exception as e:
            _ws_connected = False
            url_idx += 1
            print(f"[WS] ❌ Disconnesso: {e} — provo {urls[url_idx % len(urls)]} in {backoff}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

# ── background loop ───────────────────────────────────────────────────────────

async def background_loop():
    global _rest_price_last_fetch, _ws_last_msg_ts
    consecutive_errors = 0
    last_persist = 0.0
    while True:
        try:
            # Fetch REST prezzi: ogni 5s se WS silente, ogni 30s se WS attivo
            ws_live = _ws_connected and _ws_last_msg_ts > 0 and (time.time() - _ws_last_msg_ts < 10)
            rest_interval = 30 if ws_live else 5
            if time.time() - _rest_price_last_fetch >= rest_interval:
                _rest_price_last_fetch = time.time()
                await fetch_prices()

            if time.time() - _universe_last_update >= UNIVERSE_UPDATE_INTERVAL:
                await fetch_dynamic_universe()

            if time.time() - _candles_last_update >= CANDLE_UPDATE_INTERVAL:
                await fetch_all_candles()

            if time.time() - _scanner_candles_ts.get("1h", 0) >= CANDLE_UPDATE_INTERVAL:
                await fetch_all_scanner_candles("1h")

            sessions_snapshot = list(user_sessions.items())
            for uid, state in sessions_snapshot:
                if state["running"]:
                    try:
                        await scan_and_trade(state, user_id=uid)
                    except Exception as user_err:
                        import traceback as _tb
                        print(f"[scan_and_trade] user {uid}: {user_err}\n{_tb.format_exc()}")
                elif state.get("positions"):
                    try:
                        await monitor_manual_positions(state, user_id=uid)
                    except Exception as user_err:
                        print(f"[manual_monitor] user {uid}: {user_err}")

            # Persisti sessioni ogni 30 secondi
            if time.time() - last_persist >= 30:
                await persist_sessions()
                last_persist = time.time()

            consecutive_errors = 0
            await asyncio.sleep(3)
        except Exception as e:
            import traceback
            consecutive_errors += 1
            wait = min(8 * (2 ** (consecutive_errors - 1)), 120)
            print(f"Loop error ({consecutive_errors}), retry in {wait}s: {e}\n{traceback.format_exc()}")
            await asyncio.sleep(wait)

async def persist_sessions():
    """Salva lo stato delle sessioni attive nel DB per sopravvivere ai riavvii."""
    if not db_pool:
        return
    _SENSITIVE_KEYS = {
        "revx_key_id", "revx_private_key",
        "binance_api_key", "binance_api_secret",
        "coinbase_api_key", "coinbase_api_secret",
        "coinbase_api_key_agent", "coinbase_api_secret_agent",
    }
    sessions_snapshot = list(user_sessions.items())
    for uid, state in sessions_snapshot:
        try:
            state_to_save = {k: v for k, v in state.items() if k not in _SENSITIVE_KEYS and k not in ("log", "_exiting", "_stopping")}
            state_json = json.dumps(state_to_save, default=str)
            has_open_positions = bool(state.get("positions"))
            async with db_pool.acquire() as conn:
                if state.get("running") or has_open_positions:
                    await conn.execute("""
                        INSERT INTO active_sessions (user_id, state_json, updated_at)
                        VALUES ($1, $2, NOW())
                        ON CONFLICT (user_id) DO UPDATE
                        SET state_json = $2, updated_at = NOW()
                    """, uid, state_json)
                else:
                    await conn.execute("DELETE FROM active_sessions WHERE user_id = $1", uid)
        except Exception as e:
            print(f"Errore persist sessione user {uid}: {e}")

async def telegram_loop():
    """Loop separato per Telegram. Attende 20s all'avvio per dare tempo al vecchio container Railway di spegnersi (rolling deploy)."""
    await asyncio.sleep(20)
    while True:
        try:
            await poll_telegram()
        except Exception as e:
            print(f"Telegram loop error: {e}")
        await asyncio.sleep(10)

# ── startup ───────────────────────────────────────────────────────────────────

async def _skip_old_telegram_updates():
    """Drena e conferma tutti gli update Telegram pendenti per evitare che vecchi comandi vengano rieseguiti dopo un deploy."""
    global _tg_last_update
    if not TELEGRAM_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Recupera tutti gli update pendenti (fino a 100)
            r = await client.get(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                params={"limit": 100, "timeout": 0}
            )
            results = r.json().get("result", [])
            if results:
                last_id = results[-1]["update_id"]
                # Conferma esplicita: Telegram non ritornerà più questi update
                await client.get(
                    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                    params={"offset": last_id + 1, "timeout": 0}
                )
                _tg_last_update = last_id
                print(f"Telegram: scartati {len(results)} update pendenti (ultimo id: {last_id})")
    except Exception as e:
        print(f"Telegram skip-updates error: {e}")

@app.on_event("startup")
async def startup():
    global db_pool
    if DATABASE_URL:
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        telegram_chat_id TEXT DEFAULT '',
                        avatar_b64 TEXT DEFAULT '',
                        sim_mode BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS sim_mode BOOLEAN DEFAULT TRUE;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_b64 TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS revx_key_id TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS revx_private_key TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS binance_api_key TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS binance_api_secret TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS coinbase_api_key TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS coinbase_api_secret TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT DEFAULT '';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMP;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_session_date DATE;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_today INT DEFAULT 0;
                    CREATE TABLE IF NOT EXISTS trades_history (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        symbol TEXT NOT NULL,
                        entry_price FLOAT NOT NULL,
                        exit_price FLOAT NOT NULL,
                        size FLOAT NOT NULL,
                        pnl FLOAT NOT NULL,
                        pct FLOAT NOT NULL,
                        reason TEXT NOT NULL,
                        tp1_hit BOOLEAN DEFAULT FALSE,
                        duration_min FLOAT DEFAULT 0,
                        entry_time TEXT NOT NULL,
                        exit_time TEXT NOT NULL,
                        mode TEXT DEFAULT 'sim',
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS watchlist (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        symbol TEXT NOT NULL,
                        UNIQUE(user_id, symbol)
                    );
                    CREATE TABLE IF NOT EXISTS active_sessions (
                        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                        state_json TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS tg_updates (
                        update_id BIGINT PRIMARY KEY,
                        processed_at TIMESTAMP DEFAULT NOW()
                    );
                    DELETE FROM tg_updates WHERE processed_at < NOW() - INTERVAL '7 days'
                """)
                # Migrazione colonne fee (idempotente)
                await conn.execute("""
                    ALTER TABLE trades_history ADD COLUMN IF NOT EXISTS buy_fee FLOAT DEFAULT 0;
                    ALTER TABLE trades_history ADD COLUMN IF NOT EXISTS sell_fee FLOAT DEFAULT 0;
                    ALTER TABLE trades_history ADD COLUMN IF NOT EXISTS sell_type TEXT DEFAULT 'Market';
                """)
            print("Database connesso e schema creato")

            # Ripristina sessioni attive dopo riavvio
            await restore_sessions_from_db(db_pool)

        except Exception as e:
            print(f"Database error: {e}")
    def _on_task_done(t: asyncio.Task):
        if not t.cancelled() and t.exception():
            print(f"[TASK CRASH] {t.get_name()}: {t.exception()}", file=sys.stderr)

    for _name, _coro in [
        ("background_loop",      background_loop()),
        ("binance_ws_loop",      binance_ws_loop()),
        ("load_global_revx_keys", load_global_revx_keys()),
        ("load_telegram_bot_info", load_telegram_bot_info()),
        ("fetch_coingecko_logos", fetch_coingecko_logos()),
        ("cleanup_rate_buckets",  _cleanup_rate_buckets()),
    ]:
        _t = asyncio.create_task(_coro, name=_name)
        _t.add_done_callback(_on_task_done)
    await _skip_old_telegram_updates()
    _t = asyncio.create_task(telegram_loop(), name="telegram_loop")
    _t.add_done_callback(_on_task_done)

async def load_global_revx_keys():
    """Carica le chiavi RevX e le coppie USD disponibili all'avvio."""
    global _global_revx_key_id, _global_revx_private_key, _revx_pairs, _universe_last_update
    if not db_pool:
        return
    try:
        await asyncio.sleep(3)  # Aspetta che il DB sia pronto
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT revx_key_id, revx_private_key FROM users WHERE revx_key_id != '' AND sim_mode = FALSE ORDER BY id LIMIT 1"
            )
        if row and row["revx_key_id"]:
            _global_revx_key_id = decrypt_key(row["revx_key_id"])
            _global_revx_private_key = decrypt_key(row["revx_private_key"])
            print(f"[REVX] Chiavi globali caricate per market data")
            # Carica coppie EUR disponibili su Revolut X
            try:
                data = await revx_request("GET", "/api/1.0/tickers",
                                          key_id=_global_revx_key_id,
                                          private_key=_global_revx_private_key)
                tickers = data.get("data", []) if isinstance(data, dict) else data
                pairs = set()
                for t in (tickers if isinstance(tickers, list) else []):
                    symbol = t.get("symbol", "")
                    if symbol.endswith("/USD"):
                        pairs.add(symbol[:-4])  # "BTC/USD" -> "BTC"
                if pairs:
                    _revx_pairs = pairs
                    _universe_last_update = 0  # forza re-fetch universo con coppie RevX
                    print(f"[REVX] {len(pairs)} coppie USD caricate: {sorted(pairs)[:8]}...")
                else:
                    print(f"[REVX] Nessuna coppia USD trovata nel ticker")
            except Exception as e2:
                print(f"[REVX] Errore caricamento coppie: {e2}")
    except Exception as e:
        print(f"[REVX] Errore caricamento chiavi globali: {e}")

async def load_telegram_bot_info():
    """Recupera lo username del bot Telegram via getMe e lo salva in cache."""
    global _tg_bot_username
    if not TELEGRAM_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getMe")
        data = r.json()
        if data.get("ok"):
            _tg_bot_username = data["result"].get("username", "")
            print(f"[TG] Bot username: @{_tg_bot_username}")
    except Exception as e:
        print(f"[TG] Errore getMe: {e}")

async def fetch_coingecko_logos():
    """Fetcha i loghi di ~500 coin da CoinGecko markets API e li cacha in _cg_logos."""
    global _cg_logos
    try:
        logos = {}
        async with httpx.AsyncClient(timeout=15) as client:
            for page in (1, 2):
                r = await client.get(
                    "https://api.coingecko.com/api/v3/coins/markets",
                    params={"vs_currency": "usd", "order": "market_cap_desc",
                            "per_page": 250, "page": page}
                )
                if r.status_code != 200:
                    break
                for coin in r.json():
                    sym = coin.get("symbol", "").upper()
                    img = (coin.get("image") or "").replace("/large/", "/small/")
                    if sym and img:
                        logos[sym] = img
                await asyncio.sleep(1.5)  # rispetta rate limit CoinGecko free
        _cg_logos = logos
        print(f"[CG] Loghi caricati per {len(logos)} coin")
    except Exception as e:
        print(f"[CG] Errore fetch loghi: {e}")

async def restore_sessions_from_db(pool):
    """Ripristina sessioni dal DB dopo un riavvio.
    Sessioni con posizioni aperte sopravvivono al deploy con SL/TP attivi:
    - running=True  → rimane True, paused=True  (scan_and_trade monitora, no nuovi ingressi)
    - running=False → rimane False               (monitor_all_positions monitora SL/TP)
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT s.user_id, s.state_json, s.updated_at,
                       u.revx_key_id, u.revx_private_key
                FROM active_sessions s JOIN users u ON u.id = s.user_id
            """)
        for row in rows:
            uid = row["user_id"]
            try:
                state = make_session()
                state.update(json.loads(row["state_json"]))
                positions = state.get("positions", [])

                if not positions:
                    async with pool.acquire() as conn:
                        await conn.execute("DELETE FROM active_sessions WHERE user_id = $1", uid)
                    restore_debug_log(f"[RESTORE] User {uid}: nessuna posizione, rimossa dal DB")
                    continue

                state["revx_key_id"]      = decrypt_key(row["revx_key_id"] or "")
                state["revx_private_key"] = decrypt_key(row["revx_private_key"] or "")
                state.pop("_auto_stop_on_restore", None)
                state.pop("_stopping", None)

                was_running = state.get("running", False)
                if was_running:
                    state["paused"] = True

                user_sessions[uid] = state

                n    = len(positions)
                syms = ", ".join(p.get("symbol", "?") for p in positions)
                mode = "paused" if was_running else "monitor"
                restore_debug_log(f"[RESTORE] User {uid}: RIPRISTINATO {n} posizioni ({syms}) — modalità {mode}")

                tg_chat = state.get("telegram_chat_id", "")
                pausa_note = ("L'agente è in <b>PAUSA</b> — riavvialo dall'app quando sei pronto."
                              if was_running else
                              "Monitoraggio SL/TP attivo.")
                msg = (
                    f"🔄 <b>Zentra — server riavviato</b>\n"
                    f"Trovate <b>{n}</b> posizioni aperte: {syms}\n"
                    f"Le posizioni sono attive e monitorate (SL/TP operativi).\n"
                    f"{pausa_note}"
                )
                if tg_chat:
                    await send_telegram_to(tg_chat, msg)
                else:
                    await send_telegram(msg)
            except Exception as e:
                import traceback as _tb
                print(f"[RESTORE] Errore user {uid}: {e}\n{_tb.format_exc()}")
    except Exception as e:
        import traceback as _tb
        print(f"[RESTORE] Errore fatale: {e}\n{_tb.format_exc()}")

# ── RATE LIMITING ─────────────────────────────────────────────────────────────
from collections import defaultdict
_rate_buckets: dict = defaultdict(list)  # key -> [timestamps]

async def _cleanup_rate_buckets():
    while True:
        await asyncio.sleep(300)
        now = time.time()
        stale = [k for k, ts in list(_rate_buckets.items()) if not any(now - t < 600 for t in ts)]
        for k in stale:
            _rate_buckets.pop(k, None)

def _get_client_ip(request: Request) -> str:
    """Estrae l'IP reale del client, gestendo il reverse proxy di Railway.
    Prende l'ULTIMO IP dalla catena X-Forwarded-For: è quello aggiunto dal proxy
    di Railway (trusted), non quello eventualmente iniettato dal client."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        if ips:
            return ips[-1]  # ultimo = aggiunto dal proxy Railway, non dal client
    return request.client.host or "unknown"

def check_rate_limit(request_or_ip, max_attempts: int = 10, window: int = 300, key_suffix: str = ""):
    """Rate limit per IP reale (gestisce reverse proxy). Accetta Request o stringa IP."""
    ip = _get_client_ip(request_or_ip) if isinstance(request_or_ip, Request) else request_or_ip
    key = f"{ip}:{key_suffix}" if key_suffix else ip
    now = time.time()
    attempts = [t for t in _rate_buckets[key] if now - t < window]
    if attempts:
        _rate_buckets[key] = attempts
    else:
        del _rate_buckets[key]  # rimuove chiavi inattive per evitare memory leak
    if len(attempts) >= max_attempts:
        raise HTTPException(status_code=429, detail="Troppi tentativi — riprova tra qualche minuto")
    _rate_buckets[key].append(now)

# Alias usato da auth endpoints
_login_attempts = _rate_buckets

# ── AUTH ENDPOINTS ─────────────────────────────────────────────────────────────

@app.post("/auth/register")
async def register(req: RegisterRequest, request: Request):
    check_rate_limit(request, max_attempts=10, window=300, key_suffix="register")
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username troppo corto (min 3 caratteri)")
    if len(req.username) > 30:
        raise HTTPException(status_code=400, detail="Username troppo lungo (max 30 caratteri)")
    if not req.username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise HTTPException(status_code=400, detail="Username può contenere solo lettere, numeri, _, -, .")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password troppo corta (min 8 caratteri)")
    if len(req.password) > 128:
        raise HTTPException(status_code=400, detail="Password troppo lunga (max 128 caratteri)")
    pw_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO users (username, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id",
                req.username.lower(), pw_hash, req.username
            )
        token = create_token(row["id"])
        return {"token": token, "username": req.username, "has_revx_keys": False}
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=400, detail="Username già in uso")
    except Exception:
        raise HTTPException(status_code=500, detail="Errore durante la registrazione")

@app.post("/auth/logout")
async def logout_user(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        _revoked_tokens.add(auth[7:])
    return {"ok": True}

@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    check_rate_limit(request, max_attempts=10, window=300, key_suffix="login")
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash, revx_key_id, display_name FROM users WHERE username = $1",
            req.username.lower()
        )
    if not row:
        raise HTTPException(status_code=401, detail="Username o password errati")
    if not bcrypt.checkpw(req.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Username o password errati")
    token = create_token(row["id"])
    has_keys = bool(row.get("revx_key_id"))
    dname = row["display_name"] or req.username
    return {"token": token, "username": dname, "has_revx_keys": has_keys}


# ── WATCHLIST ─────────────────────────────────────────────────────────────────

@app.get("/watchlist")
async def get_watchlist(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="watchlist_get")
    if not db_pool:
        return {"symbols": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT symbol FROM watchlist WHERE user_id = $1", user_id)
    return {"symbols": [r["symbol"] for r in rows]}

@app.post("/watchlist/{symbol}")
async def add_watchlist(symbol: str, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="watchlist")
    sym = symbol.upper()
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO watchlist (user_id, symbol) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                user_id, sym
            )
        except Exception:
            pass
    return {"ok": True}

@app.delete("/watchlist/{symbol}")
async def remove_watchlist(symbol: str, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="watchlist")
    sym = symbol.upper()
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM watchlist WHERE user_id = $1 AND symbol = $2",
            user_id, sym
        )
    return {"ok": True}

# ── AVATAR ─────────────────────────────────────────────────────────────────────

class AvatarRequest(BaseModel):
    avatar_b64: str

@app.post("/auth/avatar")
async def save_avatar(req: AvatarRequest, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="avatar")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    if len(req.avatar_b64) > 700000:
        raise HTTPException(status_code=400, detail="Immagine troppo grande (max 500KB)")
    # Accetta solo prefissi base64 di immagini (JPEG, PNG, GIF, WebP)
    allowed_prefixes = ("data:image/jpeg;base64,", "data:image/png;base64,",
                        "data:image/gif;base64,", "data:image/webp;base64,")
    if not any(req.avatar_b64.startswith(p) for p in allowed_prefixes):
        raise HTTPException(status_code=400, detail="Formato immagine non supportato (usa JPEG, PNG, GIF o WebP)")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET avatar_b64 = $1 WHERE id = $2",
            req.avatar_b64, user_id
        )
    return {"ok": True}

@app.get("/auth/me")
async def get_me(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="me")
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, display_name, avatar_b64, sim_mode, revx_key_id, "
            "binance_api_key, coinbase_api_key, telegram_chat_id, "
            "plan, subscription_expires_at, last_session_date, sessions_today FROM users WHERE id = $1", user_id
        )
    has_keys = bool(row.get("revx_key_id"))
    has_binance_keys = bool(row.get("binance_api_key"))
    has_coinbase_keys = bool(row.get("coinbase_api_key"))
    sim = row["sim_mode"] if row["sim_mode"] is not None else True
    if not has_keys:
        sim = True
    dname = row["display_name"] or row["username"]
    # Calcola piano effettivo (pro scade se subscription_expires_at è nel passato)
    raw_plan = row["plan"] or "free"
    exp = row["subscription_expires_at"]
    if raw_plan == "pro" and exp and exp < datetime.utcnow():
        raw_plan = "free"
    # Sessioni usate oggi
    today = datetime.utcnow().date()
    last_date = row["last_session_date"]
    sessions_today = (row["sessions_today"] or 0) if (last_date and last_date == today) else 0
    return {
        "username": dname,
        "has_revx_keys": has_keys,
        "has_binance_keys": has_binance_keys,
        "has_coinbase_keys": has_coinbase_keys,
        "avatar_b64": row["avatar_b64"] or "",
        "sim_mode": sim,
        "telegram_linked": bool(row["telegram_chat_id"] or ""),
        "plan": raw_plan,
        "sessions_today": sessions_today,
        "sessions_per_day": FREE_SESSIONS_PER_DAY,
        "subscription_expires_at": exp.isoformat() if exp else None,
    }

class SimModeRequest(BaseModel):
    sim_mode: bool

@app.post("/auth/sim_mode")
async def set_sim_mode(req: SimModeRequest, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="sim_mode")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT revx_key_id FROM users WHERE id = $1", user_id)
        if not row["revx_key_id"] and not req.sim_mode:
            raise HTTPException(status_code=400, detail="API keys richieste per modalità reale")
        await conn.execute(
            "UPDATE users SET sim_mode = $1 WHERE id = $2",
            req.sim_mode, user_id
        )
    # Reset session state so stale data from the previous mode doesn't show up
    state = user_sessions.get(user_id)
    if state and not state.get("running"):
        user_sessions[user_id] = make_session()
    return {"ok": True, "sim_mode": req.sim_mode}

# ── TRADES HISTORY ─────────────────────────────────────────────────────────────

@app.get("/trades_history")
async def get_trades_history(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="trades_history")
    if not db_pool:
        return {"trades": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM trades_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 500",
            user_id
        )
    return {"trades": [dict(r) for r in rows]}

# ── TRADING ENDPOINTS ──────────────────────────────────────────────────────────

@app.get("/status")
async def get_status(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=120, window=60, key_suffix="status")
    state = get_session(user_id)
    if not state.get("telegram_chat_id") and db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT telegram_chat_id FROM users WHERE id = $1", user_id)
            if row and row["telegram_chat_id"]:
                state["telegram_chat_id"] = row["telegram_chat_id"]
        except Exception:
            pass
    unr     = unrealized_pnl(state)
    pos_val = sum(p.get("size_remaining", p["size"]) for p in state["positions"])
    total   = state["currentCapital"] + pos_val + unr
    pnl     = total - state["capital"]
    pct     = pnl / state["capital"] * 100 if state["capital"] > 0 else 0
    wr      = state["wins"] / state["tradeCount"] * 100 if state["tradeCount"] > 0 else 0
    remaining = 0
    if state["running"] and state["sessionStart"]:
        elapsed   = (datetime.now().timestamp() - state["sessionStart"]) * 1000
        remaining = max(0, state["sessionDuration"] - elapsed)
    return {
        "running": state["running"],
        "capital": state["capital"],
        "currentCapital": state["currentCapital"],
        "pnl": pnl, "pct": pct,
        "tradeCount": state["tradeCount"],
        "winRate": wr,
        "positions": state["positions"],
        "remainingMs": remaining,
        "pnlHistory": state["pnlHistory"][-100:],
        "log": state.get("log", [])[:40],
        "paused": state.get("paused", False),
    }

@app.get("/market")
async def get_market(
    request: Request,
    user_id: int = Depends(get_current_user),
    timeframe: str = Query("1h"),
):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="market")

    if timeframe not in VALID_TF:
        timeframe = "1h"

    # Refresh scanner cache per il TF richiesto se assente o scaduta
    tf_age = time.time() - _scanner_candles_ts.get(timeframe, 0)
    if tf_age > SCANNER_CACHE_TTL or timeframe not in scanner_candle_data:
        await fetch_all_scanner_candles(timeframe)

    items = []
    user_state = user_sessions.get(user_id, {})
    active_cfg = user_state.get("config", {})

    max_stop_pct  = active_cfg.get("maxStopPct", 0.02)
    vol_mult      = active_cfg.get("volMultiplier", 1.2)
    momentum_thr  = active_cfg.get("momentumPct", 0.01)

    tf_cache = scanner_candle_data.get(timeframe, {})

    for s, d in market_data.items():
        if d["price"] <= 0:
            continue
        if s not in _dynamic_universe:
            continue
        item = {"symbol": s, **d}
        sig = get_momentum_signal(s, d["price"], max_stop_pct, vol_mult, momentum_thr)
        item["ema"] = {
            "breakout_ok":  sig.get("breakout_ok", False),
            "vol_ok":       sig.get("vol_ok", False),
            "freshness_ok": sig.get("freshness_ok", False),
            "rsi_ok":       sig.get("rsi_ok", False),
            "decomp_ok":    sig.get("decomp_ok", False),
            "wick_ok":      sig.get("wick_ok", False),
            "chop_ok":      sig.get("chop_ok", False),
            "keltner_ok":   sig.get("keltner_ok", False),
            "tsi_ok":       sig.get("tsi_ok", False),
            "macd_ok":      sig.get("macd_ok", False),
            "signal":       sig["signal"],
            "reason":       sig["reason"],
        }
        sc = tf_cache.get(s, {})
        item["sparkline"] = sc.get("sparkline", candle_data.get(s, {}).get("sparkline", []))
        item["scanner"] = {
            "rsi_14":         sc.get("rsi_14",         0.0),
            "macd_hist":      sc.get("macd_hist",       0.0),
            "golden_cross":   sc.get("golden_cross",    False),
            "death_cross":    sc.get("death_cross",     False),
            "rsi_oversold":   sc.get("rsi_oversold",    False),
            "rsi_overbought": sc.get("rsi_overbought",  False),
            "breakout":       sc.get("breakout",        False),
            "macd_bullish":   sc.get("macd_bullish",    False),
            "macd_bearish":   sc.get("macd_bearish",    False),
            "tsi_bullish":    sc.get("tsi_bullish",     False),
            "ema_stack":      sc.get("ema_stack",       False),
            "volume_spike":   sc.get("volume_spike",    False),
            "vol_ratio":      sc.get("vol_ratio",       0.0),
        }
        items.append(item)

    if _revx_pairs:
        items = [i for i in items if i["symbol"] in _revx_pairs]

    result = sorted(items, key=lambda x: x["change24h"], reverse=True)
    return {"market": result}

@app.get("/trades")
async def get_trades(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="trades")
    state = get_session(user_id)
    # Combina trades in memoria + storico DB (rimuovi duplicati per time+symbol)
    mem_trades = state["trades"]
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM trades_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 500",
                    user_id
                )
            db_trades = [{
                "symbol": r["symbol"],
                "entryPrice": r["entry_price"],
                "exitPrice": r["exit_price"],
                "pnl": r["pnl"],
                "pct": r["pct"],
                "reason": r["reason"],
                "tp1_hit": r["tp1_hit"],
                "durationMin": r["duration_min"],
                "entryTime": r["entry_time"],
                "time": r["exit_time"],
                "realMode": r["mode"] == "real",
                "size": r["size"],
                "buyFee": float(r["buy_fee"] or 0),
                "sellFee": float(r["sell_fee"] or 0),
                "sellType": r["sell_type"] or "Market",
            } for r in rows]
            # Merge: DB ha tutto, mem ha solo sessione corrente
            # Usa entryTime come chiave — è identico in memoria e nel DB
            db_keys = set((t["symbol"], t["entryTime"]) for t in db_trades)
            extra = [t for t in mem_trades if (t["symbol"], t["entryTime"]) not in db_keys]
            return {"trades": extra + db_trades}
        except Exception as e:
            print(f"DB trades fetch error: {e}")
    return {"trades": mem_trades}

@app.delete("/trades")
async def clear_trades(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="clear_trades")
    state = get_session(user_id)
    state["trades"] = []
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("DELETE FROM trades_history WHERE user_id = $1", user_id)
        except Exception as e:
            print(f"DB clear trades error: {e}")
    return {"ok": True}

@app.get("/telegram/bot_info")
async def telegram_bot_info(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="tg_bot_info")
    return {
        "username": _tg_bot_username,
        "url": f"https://t.me/{_tg_bot_username}" if _tg_bot_username else "",
        "configured": bool(TELEGRAM_TOKEN),
    }

@app.get("/telegram/link_code")
async def telegram_link_code(request: Request, user_id: int = Depends(get_current_user)):
    """Genera un codice temporaneo (5 min) da inviare al bot per collegare Telegram."""
    check_rate_limit(request, max_attempts=5, window=300, key_suffix="tg_link")
    import string
    if not TELEGRAM_TOKEN:
        raise HTTPException(status_code=400, detail="Telegram non configurato su questo server")
    # Pulizia codici scaduti
    now = time.time()
    expired = [k for k, (_, exp) in _tg_link_codes.items() if exp < now]
    for k in expired:
        del _tg_link_codes[k]
    alphabet = string.ascii_uppercase + string.digits
    code = ''.join(secrets.choice(alphabet) for _ in range(8))
    _tg_link_codes[code] = (user_id, now + 300)
    return {
        "code": code,
        "expires_in": 300,
        "bot_url": f"https://t.me/{_tg_bot_username}" if _tg_bot_username else "",
        "bot_username": _tg_bot_username,
    }

@app.delete("/telegram/unlink")
async def telegram_unlink(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=5, window=60, key_suffix="tg_unlink")
    """Rimuove il collegamento Telegram dell'utente."""
    if db_pool:
        async with db_pool.acquire() as conn:
            await conn.execute("UPDATE users SET telegram_chat_id = '' WHERE id = $1", user_id)
    state = user_sessions.get(user_id)
    if state:
        state["telegram_chat_id"] = ""
    return {"ok": True}

@app.post("/start")
async def start_agent(body: dict, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="start")
    state = get_session(user_id)
    if state["running"]:
        return {"error": "Already running"}
    if user_id in _sessions_starting:
        return {"error": "Already running"}
    cfg     = body.get("config", {})
    try:
        capital = float(cfg.get("capital", 1000))
    except (TypeError, ValueError):
        return {"error": "Capitale non valido (min $1, max $1,000,000)"}
    if capital <= 0 or capital > 1_000_000:
        return {"error": "Capitale non valido (min $1, max $1,000,000)"}
    try:
        alloc_val = float(cfg.get("allocPct", 0.20))
    except (TypeError, ValueError):
        return {"error": "Allocazione non valida (0-100%)"}
    if alloc_val <= 0 or alloc_val > 1:
        return {"error": "Allocazione non valida (0-100%)"}
    # Tutto OK — guard concorrenza DOPO validazione sincrona, prima del primo await
    _sessions_starting.add(user_id)
    # Validazione parametri config
    def _clamp(val, lo, hi, default):
        try: return max(lo, min(hi, float(val)))
        except (TypeError, ValueError): return default
    def _clamp_int(val, lo, hi, default):
        try: return max(lo, min(hi, int(val)))
        except (TypeError, ValueError): return default
    cfg["tp1R"]               = _clamp(cfg.get("tp1R", 2.0), 0.5, 10.0, 2.0)
    cfg["tp2R"]               = _clamp(cfg.get("tp2R", 4.0), 1.0, 20.0, 4.0)
    cfg["maxStopPct"]         = _clamp(cfg.get("maxStopPct", 0.05), 0.005, 0.20, 0.05)
    cfg["minR"]               = _clamp(cfg.get("minR", 0.01), 0.001, 0.10, 0.01)
    cfg["rsiMin"]             = _clamp(cfg.get("rsiMin", 35.0), 0.0, 100.0, 35.0)
    cfg["rsiMax"]             = _clamp(cfg.get("rsiMax", 65.0), 0.0, 100.0, 65.0)
    cfg["maxHoldHours"]       = _clamp(cfg.get("maxHoldHours", 4.0), 0.25, 72.0, 4.0)
    cfg["cooldown"]           = _clamp(cfg.get("cooldown", 1.0), 0.0, 24.0, 1.0)
    cfg["pullbackTolerance"]  = _clamp(cfg.get("pullbackTolerance", 0.02), 0.0, 0.10, 0.02)
    cfg["capitalPct"]         = _clamp(cfg.get("capitalPct", 1.0), 0.01, 1.0, 1.0)
    cfg["maxTrades"]          = _clamp_int(cfg.get("maxTrades", 0), 0, 100, 0)
    cfg["maxConsecutiveLosses"] = _clamp_int(cfg.get("maxConsecutiveLosses", 3), 1, 20, 3)
    cfg["sessionDuration"]    = _clamp_int(cfg.get("sessionDuration", 8), 0, 48, 8)

    real_mode = False
    revx_key_id, revx_private_key, use_revx = "", "", False
    user_plan = "free"
    free_session_counter_update = None
    row = None
    agent_exchange = cfg.get("agentExchange", "revx").lower()
    use_coinbase = False
    coinbase_api_key_agent, coinbase_api_secret_agent = "", ""
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT sim_mode, revx_key_id, revx_private_key, username, display_name, "
                    "telegram_chat_id, plan, subscription_expires_at, last_session_date, sessions_today, "
                    "coinbase_api_key, coinbase_api_secret "
                    "FROM users WHERE id = $1", user_id)
                if row:
                    revx_key_id      = decrypt_key(row["revx_key_id"] or "")
                    revx_private_key = decrypt_key(row["revx_private_key"] or "")
                    sim = row["sim_mode"] if row["sim_mode"] is not None else True
                    if agent_exchange == "coinbase" and not sim:
                        raw_cb_key = decrypt_key(row.get("coinbase_api_key") or "")
                        raw_cb_sec = decrypt_key(row.get("coinbase_api_secret") or "")
                        if raw_cb_key and raw_cb_sec:
                            use_coinbase = True
                            coinbase_api_key_agent = raw_cb_key
                            coinbase_api_secret_agent = raw_cb_sec
                            real_mode = True
                        use_revx = False
                    else:
                        use_revx = bool(revx_key_id) and not sim
                        real_mode = use_revx
                    # Piano effettivo
                    raw_plan = row["plan"] or "free"
                    exp = row["subscription_expires_at"]
                    if raw_plan == "pro" and exp and exp < datetime.utcnow():
                        raw_plan = "free"
                    user_plan = raw_plan
                    # Gate sessione giornaliera (solo free)
                    if user_plan == "free":
                        today = datetime.utcnow().date()
                        last_date = row["last_session_date"]
                        sessions_today = (row["sessions_today"] or 0) if (last_date and last_date == today) else 0
                        if sessions_today >= FREE_SESSIONS_PER_DAY:
                            _sessions_starting.discard(user_id)
                            return {
                                "error": "session_limit",
                                "message": f"Hai già usato la tua sessione gratuita di oggi. Torna domani o passa a Pro.",
                                "plan": "free",
                            }
                        free_session_counter_update = (today, sessions_today + 1)
        except Exception as e:
            print(f"DB key fetch error: {e}")

    # Override configurazione per utenti free
    if user_plan == "free":
        cfg["allocPct"]        = FREE_ALLOC_PCT
        free_duration = int(cfg.get("sessionDuration", FREE_MAX_SESSION_HOURS))
        cfg["sessionDuration"] = FREE_MAX_SESSION_HOURS if free_duration <= 0 else min(free_duration, FREE_MAX_SESSION_HOURS)
        cfg["rsiMin"]          = FREE_RSI_MIN
        cfg["rsiMax"]          = FREE_RSI_MAX
        cfg["trend1hFilter"]   = True
        cfg["btcEmaFilter"]    = True
        cfg["trailingStop"]    = True
        cfg["tp1R"]            = 2.0
        cfg["tp2R"]            = 4.0
        cfg["pullbackTolerance"] = 0.02
        cfg["cooldown"]        = 1.0
        cfg["maxTrades"]       = 0
        cfg["maxHoldHours"]    = 4.0
        cfg["minR"]            = 0.01

    existing_manual = [p for p in state.get("positions", []) if p.get("manual")]
    manual_invested  = sum(p.get("size", 0) for p in existing_manual)
    state.update({
        "running": True,
        "_exiting": set(),
        "capital": capital,
        "currentCapital": max(0.0, capital - manual_invested),
        "positions": existing_manual,
        "pnlHistory": [{"t": 0, "v": 0}],
        "sessionStart": datetime.now().timestamp(),
        "sessionDuration": int(cfg.get("sessionDuration", 8)) * 3600 * 1000,
        "config": {
            "allocPct":            float(cfg.get("allocPct", 0.20)),
            "tradeAmountUsd":      float(cfg.get("tradeAmountUsd", 0)),
            "capitalPct":          float(cfg.get("capitalPct", 1.0)),
            "stopLoss":            float(cfg.get("stopLoss", 0.01)),
            "cooldown":            float(cfg.get("cooldown", 1)),
            "minVolume":           float(cfg.get("minVolume", 0)),
            "sessionDuration":     int(cfg.get("sessionDuration", 8)),
            "realMode":            real_mode,
            "emaFilter":           bool(cfg.get("emaFilter", True)),
            "pullbackTolerance":   float(cfg.get("pullbackTolerance", 0.02)),
            "volMultiplier":       float(cfg.get("volMultiplier", 1.2)),
            "maxStopPct":          float(cfg.get("maxStopPct", 0.05)),
            "maxTrades":           int(cfg.get("maxTrades", 0)),
            "maxConsecutiveLosses": int(cfg.get("maxConsecutiveLosses", 3)),
            "trend1hFilter":       bool(cfg.get("trend1hFilter", True)),
            "btcEmaFilter":        bool(cfg.get("btcEmaFilter", True)),
            "rsiFilter":           bool(cfg.get("rsiFilter", True)),
            "rsiMin":              float(cfg.get("rsiMin", 35.0)),
            "rsiMax":              float(cfg.get("rsiMax", 65.0)),
            "minR":                float(cfg.get("minR", 0.01)),
            "tp1R":                float(cfg.get("tp1R", 2.0)),
            "tp2R":                float(cfg.get("tp2R", 4.0)),
            "trailingStop":        bool(cfg.get("trailingStop", True)),
            "maxHoldHours":        float(cfg.get("maxHoldHours", 4.0)),
            "timeFilter":          bool(cfg.get("timeFilter", True)),
            "momentumPct":         float(cfg.get("momentumPct", 0.01)),
            "profitTolerance":        float(cfg.get("profitTolerance", 0.20)),
            "profitActivation":       float(cfg.get("profitActivation", 0.003)),
            "trailAtrMultiplier":     float(cfg.get("trailAtrMultiplier", 2.0)),
            "circuitBreakerEnabled":  bool(cfg.get("circuitBreakerEnabled", False)),
            "dailyLossLimit":         float(cfg.get("dailyLossLimit", 0.03)),
            "strategy":               cfg.get("strategy", "momentum"),
            "chopMin":                float(cfg.get("chopMin", 61.8)),
            "atrRatioMax":            float(cfg.get("atrRatioMax", 0.85)),
            "breakoutVolMultiplier":  float(cfg.get("breakoutVolMultiplier", 1.5)),
            "agentExchange":          agent_exchange,
        },
        "daily_capital_start": capital,
        "daily_date":          datetime.utcnow().strftime("%Y-%m-%d"),
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "revx_key_id": revx_key_id, "revx_private_key": revx_private_key,
        "use_revx": use_revx,
        "use_coinbase": use_coinbase,
        "coinbase_api_key_agent": coinbase_api_key_agent,
        "coinbase_api_secret_agent": coinbase_api_secret_agent,
        "consecutiveLosses": 0,
        "username": (row["display_name"] or row["username"]) if (db_pool and row) else "",
        "telegram_chat_id": (row["telegram_chat_id"] or "") if (db_pool and row) else "",
        "plan": user_plan,
    })
    alloc  = float(cfg.get("allocPct", 0.20)) * 100
    capp   = float(cfg.get("capitalPct", 1.0)) * 100
    vol    = float(cfg.get("minVolume", 0)) / 1_000_000
    mode   = "REALE" if real_mode else "SIMULAZIONE"
    mt           = int(cfg.get("maxTrades", 0))
    mcl          = int(cfg.get("maxConsecutiveLosses", 3))
    mxh          = float(cfg.get("maxHoldHours", 4.0))
    max_stop_pct_s = float(cfg.get("maxStopPct", 0.02)) * 100
    btc_filt_s   = "ON" if cfg.get("btcEmaFilter", True) else "OFF"
    curr_sym     = "$"
    strategy_s   = cfg.get("strategy", "momentum")
    if use_coinbase:
        exchange_name = "Coinbase"
    elif use_revx:
        exchange_name = "Revolut X"
    else:
        exchange_name = "SIM"
    if strategy_s == "breakout":
        chop_s   = float(cfg.get("chopMin", 61.8))
        atr_s    = float(cfg.get("atrRatioMax", 0.85)) * 100
        bvol_s   = float(cfg.get("breakoutVolMultiplier", 1.5))
        strategy_params = f"CHOP≥{chop_s:.0f} | ATR<{atr_s:.0f}% | Vol≥{bvol_s:.1f}x"
    else:
        mom_thr_pct = float(cfg.get("momentumPct", 0.01)) * 100
        vol_mult_s  = float(cfg.get("volMultiplier", 1.2))
        strategy_params = f"Momentum: +{mom_thr_pct:.1f}% | Vol: {vol_mult_s}x"
    add_log(state, "info", "AVVIO",
        f"{curr_sym}{capital:.0f} | {mode} [{exchange_name}] | {strategy_s.upper()} | "
        f"Cap: {capp:.0f}% | Alloc: {alloc:.0f}% | {strategy_params} | "
        f"Stop: -{max_stop_pct_s:.1f}% | BTC: {btc_filt_s} | MaxHold: {mxh}h | MaxLoss: {mcl}"
    )
    if free_session_counter_update and db_pool:
        try:
            today, new_count = free_session_counter_update
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET last_session_date = $1, sessions_today = $2 WHERE id = $3",
                    today, new_count, user_id
                )
        except Exception as e:
            print(f"DB free session counter update error: {e}")
    _sessions_starting.discard(user_id)
    return {"ok": True}

@app.post("/stop")
async def stop_agent(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="stop")
    state = get_session(user_id)
    if not state["running"]:
        return {"error": "Not running"}
    state["_stopping"] = True  # blocca nuovi trade senza nascondere posizioni al poll
    for p in list(state["positions"]):
        if not p.get("manual"):
            await exit_position(state, p, "STOP MANUALE", user_id=user_id)
    # Considera fallimento solo per posizioni non-manuali rimaste
    remaining_agent = [p for p in state.get("positions", []) if not p.get("manual")]
    if remaining_agent:
        state.pop("_stopping", None)
        syms = ", ".join(p["symbol"] for p in remaining_agent)
        add_log(state, "info", "ERRORE", f"Stop annullato: vendita fallita per {syms} — riprova")
        return {"error": f"Vendita fallita per: {syms}. Sessione non fermata.", "remaining": [p["symbol"] for p in remaining_agent]}
    state["running"] = False
    state.pop("_stopping", None)
    pnl = state["currentCapital"] - state["capital"]
    add_log(state, "info", "STOP", f"P&L finale: {pnl:+.2f}$")
    await persist_sessions()  # rimuovi dal DB
    return {"ok": True, "pnl": pnl}

@app.patch("/config")
async def update_config_live(body: dict, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="config")
    state = get_session(user_id)
    if not state["running"]:
        return {"error": "Nessuna sessione attiva"}
    LOCKED = {"capital", "realMode", "capitalPct", "sessionDuration"}
    def _clamp_live(key: str, value):
        ranges = {
            "allocPct": (0.001, 1.0),
            "tradeAmountUsd": (0.0, 100_000.0),
            "momentumPct": (0.001, 0.10),
            "volMultiplier": (0.1, 10.0),
            "maxStopPct": (0.005, 0.20),
            "profitTolerance": (0.01, 0.80),
            "profitActivation": (0.0, 0.20),
            "trailAtrMultiplier": (0.1, 10.0),
            "dailyLossLimit": (0.001, 0.50),
            "minVolume": (0.0, 10_000_000_000.0),
            "cooldown": (0.0, 24.0),
            "maxHoldHours": (0.25, 72.0),
            "tp1R": (0.5, 10.0),
            "tp2R": (1.0, 20.0),
            "minR": (0.001, 0.10),
        }
        int_ranges = {
            "maxTrades": (0, 100),
            "maxConsecutiveLosses": (1, 20),
        }
        if key in ranges:
            lo, hi = ranges[key]
            return max(lo, min(hi, float(value)))
        if key in int_ranges:
            lo, hi = int_ranges[key]
            return max(lo, min(hi, int(value)))
        if key in {"btcEmaFilter", "timeFilter", "trailingStop", "circuitBreakerEnabled", "rsiFilter", "trend1hFilter"}:
            return bool(value)
        if key == "strategy":
            return value if value in ("momentum", "breakout") else "momentum"
        return value
    cfg = state["config"]
    changed = []
    for k, v in body.items():
        if k not in LOCKED and k in cfg:
            try:
                cfg[k] = _clamp_live(k, v)
                changed.append(k)
            except (TypeError, ValueError):
                continue
    if changed:
        add_log(state, "info", "CONFIG", f"Parametri aggiornati: {', '.join(changed)}")
        await persist_sessions()
    return {"ok": True}

@app.post("/pause")
async def pause_agent(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="pause")
    state = get_session(user_id)
    if not state["running"]:
        return {"error": "Not running"}
    state["paused"] = not state.get("paused", False)
    status = "paused" if state["paused"] else "resumed"
    add_log(state, "info", "PAUSA" if state["paused"] else "RIPRESA", "Nuovi ingressi bloccati." if state["paused"] else "Nuovi ingressi riattivati.")
    await persist_sessions()
    return {"ok": True, "paused": state["paused"], "status": status}

@app.post("/close_position/{symbol}")
async def close_symbol(symbol: str, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=20, window=60, key_suffix="close")
    sym = symbol.upper()
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    state = get_session(user_id)
    pos = next((p for p in state["positions"] if p["symbol"] == sym), None)
    if not pos:
        return {"error": f"No position on {symbol}"}
    await exit_position(state, pos, "CHIUSURA MANUALE", user_id=user_id)
    if pos in state.get("positions", []):
        return {
            "error": f"Chiusura non confermata per {sym}. Posizione ancora aperta.",
            "manual_action_required": bool(pos.get("_manual_action_required")),
        }
    return {"ok": True}

class ManualTradeReq(BaseModel):
    symbol:       str
    amount_usdt:  float
    sl_pct:       float
    tp_pct:       float
    exchange:     str = "revx"

class CoinbaseMicroBuyReq(BaseModel):
    symbol: str = "BTC"
    amount_usd: float = 1.0

class CoinbaseMicroSellReq(BaseModel):
    symbol: str = "BTC"
    base_size: float = 0.00001455

async def load_coinbase_keys_for_user(user_id: int) -> tuple[str, str]:
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT coinbase_api_key, coinbase_api_secret FROM users WHERE id = $1", user_id)
    if not row or not row["coinbase_api_key"]:
        raise HTTPException(status_code=400, detail="Chiavi Coinbase non configurate")
    return decrypt_key(row["coinbase_api_key"]), decrypt_key(row["coinbase_api_secret"])

async def get_coinbase_preflight_result(api_key: str, api_secret: str, sym: str, amount: float) -> dict:
    accounts = await fetch_coinbase_accounts(api_key, api_secret)
    product_errors = []
    preflight_candidates = []
    for product_id in (f"{sym}-USD", f"{sym}-USDC"):
        try:
            product = await coinbase_request(
                "GET", f"/api/v3/brokerage/products/{product_id}",
                api_key=api_key, api_secret=api_secret
            )
            candidate = build_coinbase_preflight(accounts, product, amount)
            preflight_candidates.append(candidate)
            if candidate["ok"]:
                return candidate
        except Exception as product_exc:
            product_errors.append(public_error(product_exc, api_key, api_secret, max_len=120))
    if preflight_candidates:
        best = sorted(
            preflight_candidates,
            key=lambda c: (len(c.get("blockers", [])), -float(c.get("available_quote") or 0))
        )[0]
        best["candidates"] = [
            {
                "product_id": c.get("product_id"),
                "quote_currency": c.get("quote_currency"),
                "available_quote": c.get("available_quote"),
                "blockers": c.get("blockers", []),
            }
            for c in preflight_candidates
        ]
        return best
    return {"ok": False, "symbol": sym, "blockers": ["product_unavailable"], "errors": product_errors[:2]}

@app.post("/trade/coinbase_micro_buy")
async def coinbase_micro_buy(req: CoinbaseMicroBuyReq, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=3, window=300, key_suffix="coinbase_micro_buy")
    sym = req.symbol.upper().replace("USDT", "").replace("USD", "")
    if sym != "BTC":
        raise HTTPException(status_code=400, detail="Micro-buy Coinbase abilitato solo su BTC")
    amount = round(float(req.amount_usd), 2)
    if amount < 1.0 or amount > 2.0:
        raise HTTPException(status_code=400, detail="Importo micro-buy consentito: 1.00-2.00")
    api_key, api_secret = await load_coinbase_keys_for_user(user_id)
    try:
        preflight = await get_coinbase_preflight_result(api_key, api_secret, sym, amount)
        if not preflight.get("ok"):
            return {"ok": False, "preflight": preflight, "error": "Preflight Coinbase non pronto"}
        import uuid as _uuid
        client_order_id = str(_uuid.uuid4())
        product_id = preflight["product_id"]
        order_body = {
            "client_order_id": client_order_id,
            "product_id": product_id,
            "side": "BUY",
            "order_configuration": {
                "market_market_ioc": {
                    "quote_size": f"{amount:.2f}",
                    "rfq_disabled": True,
                }
            },
        }
        result = await coinbase_request(
            "POST", "/api/v3/brokerage/orders",
            body=order_body, api_key=api_key, api_secret=api_secret
        )
        if result.get("success") is False:
            err = result.get("error_response") or result.get("failure_reason") or result
            return {"ok": False, "error": public_error(Exception(str(err)), api_key, api_secret)}
        order_id = extract_coinbase_order_id(result)
        if not order_id:
            return {"ok": False, "error": "Ordine Coinbase creato senza order_id", "raw": public_error(Exception(str(result)), api_key, api_secret)}
        await asyncio.sleep(1)
        details = await coinbase_request(
            "GET", f"/api/v3/brokerage/orders/historical/{order_id}",
            api_key=api_key, api_secret=api_secret
        )
        summary = summarize_coinbase_order(details)
        return {
            "ok": True,
            "product_id": product_id,
            "amount_usd": amount,
            "order_id": order_id,
            "order": summary,
        }
    except Exception as e:
        return {"ok": False, "error": public_error(e, api_key, api_secret)}

@app.post("/trade/coinbase_micro_sell")
async def coinbase_micro_sell(req: CoinbaseMicroSellReq, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=3, window=300, key_suffix="coinbase_micro_sell")
    sym = req.symbol.upper().replace("USDT", "").replace("USD", "")
    if sym != "BTC":
        raise HTTPException(status_code=400, detail="Micro-sell Coinbase abilitato solo su BTC")
    base_size = round(float(req.base_size), 8)
    if base_size <= 0 or base_size > 0.0001:
        raise HTTPException(status_code=400, detail="Quantità micro-sell consentita: 0-0.0001 BTC")
    api_key, api_secret = await load_coinbase_keys_for_user(user_id)
    try:
        accounts = await fetch_coinbase_accounts(api_key, api_secret)
        btc_available = sum(float(a.get("available") or 0) for a in accounts if a.get("currency") == "BTC")
        if btc_available < base_size:
            return {
                "ok": False,
                "error": "BTC insufficiente disponibile su Coinbase",
                "available_btc": btc_available,
                "required_btc": base_size,
            }
        product = None
        product_errors = []
        for product_id in ("BTC-USDC", "BTC-USD"):
            try:
                product = await coinbase_request(
                    "GET", f"/api/v3/brokerage/products/{product_id}",
                    api_key=api_key, api_secret=api_secret
                )
                if not (product.get("is_disabled") or product.get("trading_disabled") or product.get("cancel_only")):
                    break
            except Exception as product_exc:
                product_errors.append(public_error(product_exc, api_key, api_secret, max_len=120))
                product = None
        if not product:
            return {"ok": False, "error": "Prodotto BTC Coinbase non disponibile", "errors": product_errors[:2]}
        import uuid as _uuid
        client_order_id = str(_uuid.uuid4())
        product_id = product["product_id"]
        order_body = {
            "client_order_id": client_order_id,
            "product_id": product_id,
            "side": "SELL",
            "order_configuration": {
                "market_market_ioc": {
                    "base_size": f"{base_size:.8f}",
                    "rfq_disabled": True,
                }
            },
        }
        result = await coinbase_request(
            "POST", "/api/v3/brokerage/orders",
            body=order_body, api_key=api_key, api_secret=api_secret
        )
        if result.get("success") is False:
            err = result.get("error_response") or result.get("failure_reason") or result
            return {"ok": False, "error": public_error(Exception(str(err)), api_key, api_secret)}
        order_id = extract_coinbase_order_id(result)
        if not order_id:
            return {"ok": False, "error": "Ordine Coinbase creato senza order_id", "raw": public_error(Exception(str(result)), api_key, api_secret)}
        await asyncio.sleep(1)
        details = await coinbase_request(
            "GET", f"/api/v3/brokerage/orders/historical/{order_id}",
            api_key=api_key, api_secret=api_secret
        )
        summary = summarize_coinbase_order(details)
        return {
            "ok": True,
            "product_id": product_id,
            "base_size": base_size,
            "order_id": order_id,
            "order": summary,
        }
    except Exception as e:
        return {"ok": False, "error": public_error(e, api_key, api_secret)}

@app.post("/trade/manual")
async def manual_trade(req: ManualTradeReq, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="manual_trade")
    sym = req.symbol.upper().replace("USDT", "")
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    exchange = (req.exchange or "revx").lower()
    if exchange not in ("revx", "coinbase"):
        raise HTTPException(status_code=400, detail="Exchange non supportato per trade manuale")
    amount = round(req.amount_usdt, 2)
    if amount <= 0 or amount > 100_000:
        raise HTTPException(status_code=400, detail="Amount non valido")
    sl_pct = max(0.1, min(req.sl_pct, 50.0))
    tp_pct = max(0.1, min(req.tp_pct, 200.0))
    state = get_session(user_id)
    # Leggi chiavi RevX: prima dalla sessione in memoria, poi dal DB
    revx_key_id = state.get("revx_key_id", "")
    revx_priv   = state.get("revx_private_key", "")
    is_real     = state.get("use_revx", False)
    if (not is_real or not revx_key_id or not state.get("telegram_chat_id")) and db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT sim_mode, revx_key_id, revx_private_key, telegram_chat_id FROM users WHERE id = $1", user_id)
            if row:
                if not state.get("telegram_chat_id") and row["telegram_chat_id"]:
                    state["telegram_chat_id"] = row["telegram_chat_id"]
                if not row["sim_mode"] and row["revx_key_id"]:
                    revx_key_id = decrypt_key(row["revx_key_id"])
                    revx_priv   = decrypt_key(row["revx_private_key"])
                    is_real     = True
                    state["revx_key_id"]      = revx_key_id
                    state["revx_private_key"] = revx_priv
                    state["use_revx"]         = True
        except Exception as _e:
            print(f"[MANUAL TRADE] DB lookup: {_e}")
    price = market_data.get(sym, {}).get("price", 0.0)
    if not price:
        raise HTTPException(status_code=400, detail="Prezzo non disponibile per questa coin")
    R_pct      = sl_pct / 100
    stop_price = price * (1 - R_pct)
    tp_price   = price * (1 + tp_pct / 100)
    icon       = market_data.get(sym, {}).get("icon", "")
    if exchange == "coinbase":
        try:
            import uuid as _uuid
            api_key, api_secret = await load_coinbase_keys_for_user(user_id)
            preflight = await get_coinbase_preflight_result(api_key, api_secret, sym, amount)
            if not preflight.get("ok"):
                blockers = ", ".join(preflight.get("blockers", [])) or "preflight non pronto"
                raise HTTPException(status_code=400, detail=f"Coinbase non pronto per {sym}: {blockers}")
            product_id = preflight["product_id"]
            order_body = {
                "client_order_id": str(_uuid.uuid4()),
                "product_id": product_id,
                "side": "BUY",
                "order_configuration": {
                    "market_market_ioc": {
                        "quote_size": f"{amount:.2f}",
                        "rfq_disabled": True,
                    }
                },
            }
            result = await coinbase_request(
                "POST", "/api/v3/brokerage/orders",
                body=order_body, api_key=api_key, api_secret=api_secret
            )
            if result.get("success") is False:
                err = result.get("error_response") or result.get("failure_reason") or result
                raise HTTPException(status_code=400, detail=f"Ordine Coinbase fallito: {public_error(Exception(str(err)), api_key, api_secret, max_len=160)}")
            order_id = extract_coinbase_order_id(result)
            if not order_id:
                raise HTTPException(status_code=400, detail="Ordine Coinbase creato senza order_id")
            od = await wait_coinbase_order_fill(order_id, api_key, api_secret)
            try:
                actual_price = float(od.get("average_filled_price") or 0)
                qty = float(od.get("filled_size") or 0)
                buy_fee_usd = float(od.get("total_fees") or 0)
            except Exception:
                actual_price = 0.0
                qty = 0.0
                buy_fee_usd = 0.0
            if actual_price <= 0 or qty <= 0:
                state_txt = od.get("status") or "sconosciuto"
                raise HTTPException(status_code=400, detail=f"Ordine Coinbase non fillato (state={state_txt}). Verifica su Coinbase.")
            stop_price = actual_price * (1 - R_pct)
            tp_price = actual_price * (1 + tp_pct / 100)
            add_log(state, "buy", "ACQUISTO MANUALE (Coinbase)",
                    f"{sym} @ ${actual_price:.4f} | Size: ${amount:.0f} | SL: ${stop_price:.4f}")
            await notify(state, f"ACQUISTO MANUALE Coinbase\n{sym} @ ${actual_price:.4f}\nSize: ${amount:.2f}")
            state["currentCapital"] -= amount
            pos = {
                "symbol": sym, "icon": icon,
                "entryPrice": actual_price, "currentPrice": actual_price,
                "highPrice": actual_price, "peak_price": actual_price,
                "size": amount, "size_remaining": amount, "tp1_hit": False,
                "entryTime": datetime.utcnow().isoformat() + "Z",
                "stopPrice": stop_price, "tp1Price": tp_price, "tp2Price": tp_price,
                "R_pct": R_pct, "atr_5m": candle_data.get(sym, {}).get("atr_5m", 0.0),
                "realMode": True, "fee_pct": 0.0012,
                "qty_purchased": qty, "exchange": "coinbase", "symbol_pair": product_id,
                "entry_usd": amount, "buy_fee_usd": round(buy_fee_usd, 4), "manual": True,
            }
            state["positions"].append(pos)
            await persist_sessions()
            return {"ok": True, "price": actual_price, "qty": qty, "exchange": "coinbase"}
        except HTTPException:
            raise
        except Exception as e:
            err = public_error(e)
            add_log(state, "info", "ERRORE", f"Manual Coinbase trade error: {err}")
            raise HTTPException(status_code=500, detail=err)

    if is_real and exchange == "revx":
        if not revx_key_id or not revx_priv:
            raise HTTPException(status_code=400, detail="Chiavi RevX non configurate")
        try:
            import uuid as _uuid
            symbol_revx = f"{sym}-USD"
            order_body = {
                "client_order_id": str(_uuid.uuid4()),
                "symbol": symbol_revx,
                "side": "BUY",
                "order_configuration": {"market": {"quote_size": str(amount)}}
            }
            result = None
            for attempt in range(2):
                try:
                    result = await revx_request(
                        "POST", "/api/1.0/orders", order_body,
                        key_id=revx_key_id, private_key=revx_priv
                    )
                    break
                except Exception:
                    if attempt == 0:
                        await asyncio.sleep(2)
                    else:
                        raise
            data     = result.get("data") or result
            order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
            if not order_id:
                err_msg = result.get("message") or result.get("error") or str(result)
                raise HTTPException(status_code=400, detail=f"Ordine RevX fallito: {err_msg[:120]}")
            od            = await wait_revx_order_fill(order_id, revx_key_id, revx_priv)
            actual_price  = od.get("average_fill_price", 0.0)
            qty           = od.get("filled_quantity", 0.0)
            if actual_price <= 0 or qty <= 0:
                state_txt = od.get("state") or "sconosciuto"
                add_log(state, "info", "ERRORE", f"Manual trade {sym} non fillato (state={state_txt}) — verifica su RevX")
                raise HTTPException(status_code=400, detail=f"Ordine RevX non fillato (state={state_txt}). Verifica su RevX.")
            buy_fee       = od.get("total_fee", 0.0)
            fee_usd       = buy_fee * actual_price if od.get("fee_currency", "USD") != "USD" else buy_fee
            stop_price    = actual_price * (1 - R_pct)
            tp_price      = actual_price * (1 + tp_pct / 100)
            add_log(state, "buy", "ACQUISTO MANUALE (RevX)",
                    f"{sym} @ ${actual_price:.4f} | Size: ${amount:.0f} | SL: ${stop_price:.4f}")
            await notify(state, f"ACQUISTO MANUALE RevX\n{sym} @ ${actual_price:.4f}\nSize: ${amount:.2f}")
            state["currentCapital"] -= amount
            pos = {
                "symbol": sym, "icon": icon,
                "entryPrice": actual_price, "currentPrice": actual_price,
                "highPrice": actual_price, "peak_price": actual_price,
                "size": amount, "size_remaining": amount, "tp1_hit": False,
                "entryTime": datetime.utcnow().isoformat() + "Z",
                "stopPrice": stop_price, "tp1Price": tp_price, "tp2Price": tp_price,
                "R_pct": R_pct, "atr_5m": candle_data.get(sym, {}).get("atr_5m", 0.0),
                "realMode": True, "fee_pct": 0.0009,
                "qty_purchased": qty, "exchange": "revx", "symbol_pair": symbol_revx,
                "entry_usd": amount, "buy_fee_usd": round(fee_usd, 4), "manual": True,
            }
            state["positions"].append(pos)
            await persist_sessions()
            return {"ok": True, "price": actual_price, "qty": qty}
        except HTTPException:
            raise
        except Exception as e:
            err = public_error(e, revx_key_id, revx_priv)
            add_log(state, "info", "ERRORE", f"Manual trade error: {err}")
            raise HTTPException(status_code=500, detail=err)
    else:
        qty       = amount / price if price else 0.0
        entry_fee = amount * 0.001
        add_log(state, "buy", "ACQUISTO MANUALE SIM",
                f"{sym} @ ${price:.4f} | Size: ${amount:.0f} | SL: ${stop_price:.4f}")
        await notify(state, f"ACQUISTO MANUALE SIM\n{sym} @ ${price:.4f}\nSize: ${amount:.2f}")
        state["currentCapital"] -= amount + entry_fee
        pos = {
            "symbol": sym, "icon": icon,
            "entryPrice": price, "currentPrice": price,
            "highPrice": price, "peak_price": price,
            "size": amount, "size_remaining": amount, "tp1_hit": False,
            "entryTime": datetime.utcnow().isoformat() + "Z",
            "stopPrice": stop_price, "tp1Price": tp_price, "tp2Price": tp_price,
            "R_pct": R_pct, "atr_5m": candle_data.get(sym, {}).get("atr_5m", 0.0),
            "realMode": False, "fee_pct": 0.001, "qty_purchased": 0.0, "manual": True,
        }
        state["positions"].append(pos)
        await persist_sessions()
        return {"ok": True, "price": price, "qty": qty}

@app.post("/chat")
async def chat(body: dict, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=20, window=60)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "API key non configurata"}
    messages = body.get("messages", [])
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Formato messaggi non valido")
    if len(messages) > 20:
        raise HTTPException(status_code=400, detail="Troppi messaggi nella richiesta")
    # Valida ogni messaggio: solo role e content stringa, max 2000 char ciascuno
    for m in messages:
        if not isinstance(m, dict):
            raise HTTPException(status_code=400, detail="Messaggio non valido")
        if m.get("role") not in ("user", "assistant"):
            raise HTTPException(status_code=400, detail="Role non valido")
        if not isinstance(m.get("content"), str) or len(m["content"]) > 2000:
            raise HTTPException(status_code=400, detail="Contenuto messaggio non valido o troppo lungo")
    state = get_session(user_id)
    positions = state["positions"]
    pnl = state["currentCapital"] - state["capital"]
    if positions:
        pos_desc = ", ".join([f"{p['symbol']} @ ${p['entryPrice']:.4f}" for p in positions])
    else:
        pos_desc = "nessuna posizione aperta"
    system = (
        f"Sei un agente di trading crypto. "
        f"Stato: {pos_desc}. P&L sessione: ${pnl:.2f}. "
        f"Rispondi in italiano, conciso e professionale."
    )
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 500, "system": system, "messages": messages}
        )
        data = res.json()
        if "content" in data:
            return {"reply": data["content"][0]["text"]}
        return {"error": public_error(Exception(str(data.get("error", data))), api_key)}

# ── DEBUG / UTILITY ENDPOINTS ──────────────────────────────────────────────────

@app.get("/health")
def health(request: Request):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="health")
    return {
        "status": "ok",
        "market_data": any(d["price"] > 0 for d in market_data.values()),
        "candles": len(candle_data),
        "candles_age_min": round((time.time() - _candles_last_update) / 60, 1) if _candles_last_update else None,
    }

@app.get("/logs")
async def get_logs(request: Request, n: int = 50):
    check_rate_limit(request, max_attempts=20, window=60, key_suffix="logs")
    n = min(n, 500)
    """Restituisce gli ultimi N log — protetto da Authorization: Bearer <SECRET_KEY>"""
    auth = request.headers.get("Authorization", "")
    provided = auth.removeprefix("Bearer ").strip()
    if not provided or provided != SECRET_KEY:
        return PlainTextResponse("Non autorizzato.", status_code=401)
    # Aggrega log di tutte le sessioni attive
    lines = []
    for uid, state in user_sessions.items():
        for l in state.get("log", [])[-n:]:
            ts = ""
            if l.get("ts"):
                import datetime as _dt
                ts = _dt.datetime.fromtimestamp(l["ts"]/1000).strftime("%H:%M:%S") + " "
            lines.append(f"{ts}[{l.get('label','?')}] {l.get('desc','')}")
    return PlainTextResponse("\n".join(lines) if lines else "Nessun log disponibile.")

@app.get("/candles_status")
async def candles_status(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=20, window=60, key_suffix="candles_status")
    """Mostra stato aggiornamento candele e un esempio di segnale EMA."""
    sample = {}
    for sym in list(candle_data.keys())[:5]:
        price = market_data.get(sym, {}).get("price", 0)
        sample[sym] = get_momentum_signal(sym, price)
    now = time.time()
    ws_ago = round(now - _ws_last_msg_ts, 1) if _ws_last_msg_ts else None
    sample_prices = {sym: market_data.get(sym, {}).get("price", 0) for sym in list(_dynamic_universe)[:5]}
    return {
        "candles_count": len(candle_data),
        "last_update": datetime.fromtimestamp(_candles_last_update).isoformat() if _candles_last_update else None,
        "next_update_in_sec": max(0, CANDLE_UPDATE_INTERVAL - (now - _candles_last_update)) if _candles_last_update else 0,
        "ws_connected": _ws_connected,
        "ws_last_msg_ago_sec": ws_ago,
        "universe_size": len(_dynamic_universe),
        "sample_prices": sample_prices,
        "sample_signals": sample,
    }

class RevxKeysRequest(BaseModel):
    key_id: str
    private_key: str

class ExchangeKeysRequest(BaseModel):
    api_key: str
    api_secret: str

SUPPORTED_EXTERNAL_EXCHANGES = {
    "binance": {
        "name": "Binance",
        "key_column": "binance_api_key",
        "secret_column": "binance_api_secret",
    },
    "coinbase": {
        "name": "Coinbase",
        "key_column": "coinbase_api_key",
        "secret_column": "coinbase_api_secret",
    },
}

def validate_external_exchange_keys(exchange: str, api_key: str, api_secret: str) -> tuple[str, str, dict]:
    cfg = SUPPORTED_EXTERNAL_EXCHANGES.get((exchange or "").lower())
    if not cfg:
        raise HTTPException(status_code=404, detail="Exchange non supportato")
    api_key = (api_key or "").strip()
    api_secret = (api_secret or "").strip()
    if len(api_key) < 8 or len(api_key) > 512:
        raise HTTPException(status_code=400, detail="API key non valida")
    if len(api_secret) < 8 or len(api_secret) > 4096:
        raise HTTPException(status_code=400, detail="API secret non valida")
    if (exchange or "").lower() == "coinbase":
        api_secret = normalize_coinbase_api_secret(api_secret)
    return api_key, api_secret, cfg

@app.post("/auth/save_revx_keys")
async def save_revx_keys(req: RevxKeysRequest, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=300, key_suffix="save_revx")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    # API Key RevX: stringa alfanumerica di 64 caratteri
    if not req.key_id or not req.key_id.isalnum() or len(req.key_id) != 64:
        raise HTTPException(status_code=400, detail="API Key non valida (deve essere 64 caratteri alfanumerici)")
    # Private key: deve iniziare con il header PEM corretto
    if not req.private_key.strip().startswith("-----BEGIN"):
        raise HTTPException(status_code=400, detail="Chiave privata non valida (formato PEM richiesto)")
    if len(req.private_key) > 4096:
        raise HTTPException(status_code=400, detail="Chiave privata troppo lunga")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET revx_key_id = $1, revx_private_key = $2 WHERE id = $3",
            encrypt_key(req.key_id), encrypt_key(req.private_key), user_id
        )
    return {"ok": True}

@app.delete("/auth/revx_keys")
async def delete_revx_keys(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=5, window=60, key_suffix="revx_delete")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET revx_key_id = '', revx_private_key = '' WHERE id = $1", user_id
        )
    state = user_sessions.get(user_id)
    if state:
        state["revx_key_id"] = ""
        state["revx_private_key"] = ""
    return {"ok": True}

@app.post("/auth/exchange_keys/{exchange}")
async def save_external_exchange_keys(exchange: str, req: ExchangeKeysRequest, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=300, key_suffix=f"save_{exchange}_keys")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    api_key, api_secret, cfg = validate_external_exchange_keys(exchange, req.api_key, req.api_secret)
    async with db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE users SET {cfg['key_column']} = $1, {cfg['secret_column']} = $2 WHERE id = $3",
            encrypt_key(api_key), encrypt_key(api_secret), user_id
        )
    return {"ok": True, "exchange": exchange.lower()}

@app.delete("/auth/exchange_keys/{exchange}")
async def delete_external_exchange_keys(exchange: str, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=5, window=60, key_suffix=f"delete_{exchange}_keys")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    cfg = SUPPORTED_EXTERNAL_EXCHANGES.get((exchange or "").lower())
    if not cfg:
        raise HTTPException(status_code=404, detail="Exchange non supportato")
    async with db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE users SET {cfg['key_column']} = '', {cfg['secret_column']} = '' WHERE id = $1",
            user_id
        )
    return {"ok": True, "exchange": exchange.lower()}

@app.get("/test_revx")
async def test_revx(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=15, window=60, key_suffix="test_revx")
    if not db_pool:
        return {"ok": False, "error": "DB non disponibile"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
    if not row or not row["revx_key_id"]:
        return {"ok": False, "error": "Chiavi Revolut X non configurate"}
    key_id = decrypt_key(row["revx_key_id"])
    private_key = decrypt_key(row["revx_private_key"])
    try:
        result = await revx_request("GET", "/api/1.0/balances", key_id=key_id, private_key=private_key)
        balances_raw = parse_revx_balances(result)
        balances = [
            {"currency": b.get("currency", ""), "available": b.get("available", "0")}
            for b in balances_raw
            if float(b.get("available", 0) or 0) > 0
        ]
        return {"ok": True, "balances": balances}
    except Exception as e:
        return {"ok": False, "error": public_error(e, key_id, private_key)}

@app.get("/test_coinbase")
async def test_coinbase(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="test_coinbase")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT coinbase_api_key, coinbase_api_secret FROM users WHERE id = $1", user_id)
    if not row or not row["coinbase_api_key"]:
        raise HTTPException(status_code=400, detail="Chiavi Coinbase non configurate")
    api_key = decrypt_key(row["coinbase_api_key"])
    api_secret = decrypt_key(row["coinbase_api_secret"])
    try:
        accounts = await fetch_coinbase_accounts(api_key, api_secret)
        nonzero = [a for a in accounts if a["available"] > 0]
        quote_balances = {
            a.get("currency"): float(a.get("available") or 0)
            for a in accounts
            if a.get("currency") in ("USD", "USDC", "EUR")
        }
        return {
            "ok": True,
            "accounts_count": len(accounts),
            "quote_balances": quote_balances,
            "balances": nonzero[:12],
        }
    except Exception as e:
        return {"ok": False, "error": public_error(e, api_key, api_secret)}

@app.get("/preflight_coinbase")
async def preflight_coinbase(request: Request, symbol: str = "BTC", amount_usd: float = 1.0,
                             user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=10, window=60, key_suffix="preflight_coinbase")
    sym = symbol.upper().replace("USDT", "").replace("USD", "")
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    amount = round(float(amount_usd), 2)
    if amount <= 0 or amount > 100_000:
        raise HTTPException(status_code=400, detail="Amount non valido")
    api_key, api_secret = await load_coinbase_keys_for_user(user_id)
    try:
        return await get_coinbase_preflight_result(api_key, api_secret, sym, amount)
    except Exception as e:
        return {"ok": False, "error": public_error(e, api_key, api_secret)}

@app.get("/exchange_price/{exchange}/{symbol}")
async def exchange_price(exchange: str, symbol: str, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="exchange_price")
    sym = symbol.upper().replace("USDT", "").replace("USD", "")
    if not sym.isalnum() or len(sym) > 20:
        raise HTTPException(status_code=400, detail="Simbolo non valido")
    exchange = exchange.lower()
    if exchange == "revx":
        # Prova a prendere il prezzo live da RevX, fallback a Binance
        state = get_session(user_id)
        key_id = state.get("revx_key_id", "")
        priv   = state.get("revx_private_key", "")
        if not key_id and db_pool:
            try:
                async with db_pool.acquire() as conn:
                    row = await conn.fetchrow("SELECT revx_key_id, revx_private_key, sim_mode FROM users WHERE id=$1", user_id)
                if row and not row["sim_mode"] and row["revx_key_id"]:
                    key_id = decrypt_key(row["revx_key_id"])
                    priv   = decrypt_key(row["revx_private_key"])
            except Exception:
                pass
        if key_id and priv:
            try:
                data = await revx_request("GET", "/api/1.0/tickers", key_id=key_id, private_key=priv, params={})
                tickers = data.get("data", []) if isinstance(data, dict) else data
                for t in (tickers if isinstance(tickers, list) else []):
                    if t.get("symbol", "") == f"{sym}/USD":
                        price = float(t.get("last_price") or t.get("mid") or t.get("ask") or 0)
                        if price > 0:
                            return {"price": price, "exchange": "revx", "symbol": sym}
            except Exception:
                pass
        # Fallback Binance
        price = market_data.get(sym, {}).get("price", 0.0)
        if not price:
            raise HTTPException(status_code=404, detail=f"Prezzo non disponibile per {sym} su RevX")
        return {"price": price, "exchange": "revx", "symbol": sym, "source": "binance_fallback"}
    elif exchange == "coinbase":
        api_key, api_secret = await load_coinbase_keys_for_user(user_id)
        last_exc = None
        for product_id in (f"{sym}-USDC", f"{sym}-USD"):
            try:
                price = await get_coinbase_product_price(product_id, api_key, api_secret)
                if price > 0:
                    return {"price": price, "exchange": "coinbase", "symbol": sym, "product_id": product_id}
            except Exception as e:
                last_exc = e
        raise HTTPException(status_code=404, detail=public_error(last_exc or Exception("Prezzo non disponibile"), api_key, api_secret))
    raise HTTPException(status_code=400, detail="Exchange non supportato")

@app.get("/debug/revx_orders")
async def debug_revx_orders(request: Request, user_id: int = Depends(get_current_user)):
    if not ENABLE_DEBUG_REVX:
        raise HTTPException(status_code=404, detail="Not found")
    check_rate_limit(request, max_attempts=15, window=60, key_suffix="debug_revx_orders")
    if not db_pool:
        return {"ok": False, "error": "DB non disponibile"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
    if not row or not row["revx_key_id"]:
        return {"ok": False, "error": "Chiavi Revolut X non configurate"}
    key_id = decrypt_key(row["revx_key_id"])
    private_key = decrypt_key(row["revx_private_key"])
    try:
        result = await revx_request("GET", "/api/1.0/orders?state=open", key_id=key_id, private_key=private_key)
        return {"ok": True, "raw": result}
    except Exception as e:
        return {"ok": False, "error": public_error(e, key_id, private_key)}

@app.get("/debug/revx_order")
async def debug_revx_order(request: Request, order_id: str, user_id: int = Depends(get_current_user)):
    if not ENABLE_DEBUG_REVX:
        raise HTTPException(status_code=404, detail="Not found")
    check_rate_limit(request, max_attempts=15, window=60, key_suffix="debug_revx_order")
    if not db_pool:
        return {"ok": False, "error": "DB non disponibile"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
    if not row or not row["revx_key_id"]:
        return {"ok": False, "error": "Chiavi Revolut X non configurate"}
    key_id = decrypt_key(row["revx_key_id"])
    private_key = decrypt_key(row["revx_private_key"])
    try:
        result = await revx_request("GET", f"/api/1.0/orders/{order_id}", key_id=key_id, private_key=private_key)
        return {"ok": True, "raw": result}
    except Exception as e:
        return {"ok": False, "error": public_error(e, key_id, private_key)}

@app.delete("/debug/revx_cancel_order")
async def debug_revx_cancel_order(request: Request, order_id: str, user_id: int = Depends(get_current_user)):
    if not ENABLE_DEBUG_REVX:
        raise HTTPException(status_code=404, detail="Not found")
    check_rate_limit(request, max_attempts=15, window=60, key_suffix="debug_revx_cancel")
    if not db_pool:
        return {"ok": False, "error": "DB non disponibile"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
    if not row or not row["revx_key_id"]:
        return {"ok": False, "error": "Chiavi Revolut X non configurate"}
    key_id = decrypt_key(row["revx_key_id"])
    private_key = decrypt_key(row["revx_private_key"])
    try:
        result = await revx_request("DELETE", f"/api/1.0/orders/{order_id}", key_id=key_id, private_key=private_key)
        return {"ok": True, "raw": result}
    except Exception as e:
        return {"ok": False, "error": public_error(e, key_id, private_key)}

@app.get("/logos")
async def get_logos(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="logos")
    # Loghi di qualità per le coin principali (CoinGecko CDN)
    KNOWN = {
        "BTC":"https://assets.coingecko.com/coins/images/1/small/bitcoin.png",
        "ETH":"https://assets.coingecko.com/coins/images/279/small/ethereum.png",
        "SOL":"https://assets.coingecko.com/coins/images/4128/small/solana.png",
        "BNB":"https://assets.coingecko.com/coins/images/825/small/bnb-icon2_2x.png",
        "XRP":"https://assets.coingecko.com/coins/images/44/small/xrp-symbol-white-128.png",
        "ADA":"https://assets.coingecko.com/coins/images/975/small/cardano.png",
        "AVAX":"https://assets.coingecko.com/coins/images/12559/small/Avalanche_Circle_RedWhite_Trans.png",
        "DOT":"https://assets.coingecko.com/coins/images/12171/small/polkadot.png",
        "LINK":"https://assets.coingecko.com/coins/images/877/small/chainlink-new-logo.png",
        "MATIC":"https://assets.coingecko.com/coins/images/4713/small/matic-token-icon.png",
        "UNI":"https://assets.coingecko.com/coins/images/12504/small/uniswap-uni.png",
        "NEAR":"https://assets.coingecko.com/coins/images/10365/small/near_icon.png",
        "INJ":"https://assets.coingecko.com/coins/images/12882/small/Secondary_Symbol.png",
        "APT":"https://assets.coingecko.com/coins/images/26455/small/aptos_round.png",
        "ARB":"https://assets.coingecko.com/coins/images/16547/small/photo_2023-03-29_21.47.00.jpeg",
        "OP":"https://assets.coingecko.com/coins/images/25244/small/Optimism.png",
        "ATOM":"https://assets.coingecko.com/coins/images/1481/small/cosmos_hub.png",
        "DOGE":"https://assets.coingecko.com/coins/images/5/small/dogecoin.png",
        "SHIB":"https://assets.coingecko.com/coins/images/11939/small/shiba.png",
        "LTC":"https://assets.coingecko.com/coins/images/2/small/litecoin.png",
        "TON":"https://assets.coingecko.com/coins/images/17980/small/ton_symbol.png",
        "TRX":"https://assets.coingecko.com/coins/images/1094/small/tron-logo.png",
        "HBAR":"https://assets.coingecko.com/coins/images/3688/small/hbar.png",
        "AAVE":"https://assets.coingecko.com/coins/images/12645/small/AAVE.png",
        "GRT":"https://assets.coingecko.com/coins/images/13397/small/Graph_Token.png",
        "PEPE":"https://assets.coingecko.com/coins/images/29850/small/pepe-token.jpeg",
        "SUI":"https://assets.coingecko.com/coins/images/26375/small/sui_asset.jpeg",
        "WLD":"https://assets.coingecko.com/coins/images/31069/small/worldcoin.jpeg",
        "ICP":"https://assets.coingecko.com/coins/images/14495/small/Internet_Computer_logo.png",
        "RENDER":"https://assets.coingecko.com/coins/images/11636/small/rndr.png",
    }
    # Per tutte le coin in market_data: hardcoded > CoinGecko cache (no fallback — il frontend usa TradingView CDN)
    result = {
        sym: KNOWN.get(sym) or _cg_logos.get(sym) or None
        for sym in market_data
    }
    return {sym: url for sym, url in result.items() if url}

# ── BILLING ───────────────────────────────────────────────────────────────────

@app.get("/billing/status")
async def billing_status(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=30, window=60, key_suffix="billing_status")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT plan, subscription_expires_at, last_session_date, sessions_today FROM users WHERE id = $1", user_id)
    raw_plan = row["plan"] or "free"
    exp = row["subscription_expires_at"]
    if raw_plan == "pro" and exp and exp < datetime.utcnow():
        raw_plan = "free"
    today = datetime.utcnow().date()
    last_date = row["last_session_date"]
    sessions_today = (row["sessions_today"] or 0) if (last_date and last_date == today) else 0
    return {
        "plan": raw_plan,
        "sessions_today": sessions_today,
        "sessions_per_day": FREE_SESSIONS_PER_DAY,
        "sessions_remaining": max(0, FREE_SESSIONS_PER_DAY - sessions_today) if raw_plan == "free" else 999,
        "subscription_expires_at": exp.isoformat() if exp else None,
        "stripe_enabled": bool(STRIPE_SECRET_KEY),
    }

@app.post("/billing/checkout")
async def billing_checkout(body: dict, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=5, window=60, key_suffix="billing_checkout")
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        raise HTTPException(status_code=503, detail="Pagamenti non configurati")
    success_url = body.get("success_url", "")
    cancel_url  = body.get("cancel_url", "")
    if not success_url or not cancel_url:
        raise HTTPException(status_code=400, detail="success_url e cancel_url obbligatori")
    if not is_allowed_redirect_url(success_url):
        raise HTTPException(status_code=400, detail="success_url non autorizzata")
    if not is_allowed_redirect_url(cancel_url):
        raise HTTPException(status_code=400, detail="cancel_url non autorizzata")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT username, display_name, stripe_customer_id FROM users WHERE id = $1", user_id)
    customer_id = row["stripe_customer_id"] or ""
    try:
        # Crea o recupera customer Stripe
        if not customer_id:
            customer = stripe.Customer.create(
                name=row["display_name"] or row["username"],
                metadata={"user_id": str(user_id)},
            )
            customer_id = customer["id"]
            async with db_pool.acquire() as conn:
                await conn.execute("UPDATE users SET stripe_customer_id = $1 WHERE id = $2", customer_id, user_id)
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=with_query_param(success_url, "upgraded", "1"),
            cancel_url=cancel_url,
        )
        return {"url": session["url"]}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e.user_message or e))

@app.post("/billing/portal")
async def billing_portal(body: dict, request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=5, window=60, key_suffix="billing_portal")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Pagamenti non configurati")
    return_url = body.get("return_url", "")
    if not return_url:
        raise HTTPException(status_code=400, detail="return_url obbligatorio")
    if not is_allowed_redirect_url(return_url):
        raise HTTPException(status_code=400, detail="return_url non autorizzata")
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT stripe_customer_id FROM users WHERE id = $1", user_id)
    customer_id = row["stripe_customer_id"] or ""
    if not customer_id:
        raise HTTPException(status_code=400, detail="Nessun abbonamento attivo")
    try:
        portal = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return {"url": portal["url"]}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e.user_message or e))

@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook non configurato")
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Firma webhook non valida")
    etype = event["type"]
    data  = event["data"]["object"]
    if etype == "checkout.session.completed":
        customer_id = data.get("customer", "")
        sub_id      = data.get("subscription", "")
        if customer_id and db_pool:
            # Recupera subscription per data scadenza
            try:
                sub = stripe.Subscription.retrieve(sub_id)
                expires_at = datetime.utcfromtimestamp(sub["current_period_end"])
            except Exception:
                expires_at = None
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET plan = 'pro', subscription_expires_at = $1 WHERE stripe_customer_id = $2",
                    expires_at, customer_id
                )
            print(f"[BILLING] upgrade a pro: customer={customer_id}, scade={expires_at}")
    elif etype == "invoice.payment_succeeded":
        customer_id = data.get("customer", "")
        sub_id      = data.get("subscription", "")
        if customer_id and sub_id and db_pool:
            try:
                sub = stripe.Subscription.retrieve(sub_id)
                expires_at = datetime.utcfromtimestamp(sub["current_period_end"])
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE users SET plan = 'pro', subscription_expires_at = $1 WHERE stripe_customer_id = $2",
                        expires_at, customer_id
                    )
                print(f"[BILLING] rinnovo pro: customer={customer_id}, scade={expires_at}")
            except Exception as e:
                print(f"[BILLING] errore rinnovo: {e}")
    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        customer_id = data.get("customer", "")
        if customer_id and db_pool:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET plan = 'free', subscription_expires_at = NULL WHERE stripe_customer_id = $1",
                    customer_id
                )
            print(f"[BILLING] downgrade a free: customer={customer_id}")
    return {"ok": True}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
