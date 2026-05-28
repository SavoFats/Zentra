import asyncio
import os
import time
import hashlib
import json
import secrets
import stripe
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import httpx
import uvicorn
import asyncpg
import bcrypt
from cryptography.fernet import Fernet

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

_CORS_METHODS = "GET, POST, DELETE, OPTIONS"
_CORS_HEADERS = "Authorization, Content-Type"

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
    except (HTTPException, ValueError, IndexError, AttributeError):
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

BINANCE_BASE = "https://api.binance.com"

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
    """Esegue una richiesta autenticata a Revolut X."""
    body_str = json.dumps(body, separators=(',', ':')) if body else ""
    # Costruisci query string per la firma (deve essere nell'ordine corretto)
    query_str = ""
    if params:
        query_str = "&".join(f"{k}={v}" for k, v in params.items())
    headers = make_revx_signature(key_id, private_key, method, path, query_str, body_str)
    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            r = await client.get(f"{REVX_BASE}{path}", headers=headers, params=params or {})
        else:
            r = await client.post(f"{REVX_BASE}{path}", headers=headers, content=body_str)
    return r.json()


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
CANDLE_UPDATE_INTERVAL = 120   # secondi (2 minuti)
CANDLE_UNIVERSE_SIZE   = 50    # top N coin per volume (dinamico)
COIN_WHITELIST = {"BTC","ETH","SOL","BNB","XRP","DOGE","ADA","AVAX","SUI","TON","LINK","DOT"}  # fallback iniziale

_dynamic_universe: set = set(COIN_WHITELIST)  # aggiornato ogni 30 min
_universe_last_update: float = 0
UNIVERSE_UPDATE_INTERVAL = 1800  # 30 minuti

def calc_ema(prices: list, period: int) -> float:
    """Calcola EMA su una lista di prezzi (close). Restituisce l'ultimo valore."""
    if len(prices) < period:
        return 0.0
    k = 2 / (period + 1)
    ema = sum(prices[:period]) / period  # SMA iniziale
    for price in prices[period:]:
        ema = price * k + ema * (1 - k)
    return ema

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
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
        if r.status_code != 200:
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
            if vol < 10_000_000:
                continue
            candidates.append((sym, vol))
        candidates.sort(key=lambda x: x[1], reverse=True)
        new_universe = {sym for sym, _ in candidates[:CANDLE_UNIVERSE_SIZE]}
        if new_universe:
            _dynamic_universe = new_universe
            _universe_last_update = time.time()
            print(f"Universo dinamico: {len(_dynamic_universe)} coin")
    except Exception as e:
        print(f"Errore fetch universo dinamico: {e}")

async def fetch_candles_for_symbol(sym: str, client: httpx.AsyncClient) -> dict | None:
    """Scarica candele 5min, 15min e 1h da Binance. Calcola EMA20/50, RSI14, ATR."""
    pair = f"{sym}USDT"
    try:
        r5, r15, r1h = await asyncio.gather(
            client.get(f"{BINANCE_BASE}/api/v3/klines", params={"symbol": pair, "interval": "5m",  "limit": 150}),
            client.get(f"{BINANCE_BASE}/api/v3/klines", params={"symbol": pair, "interval": "15m", "limit": 150}),
            client.get(f"{BINANCE_BASE}/api/v3/klines", params={"symbol": pair, "interval": "1h",  "limit": 60}),
        )
        if r5.status_code != 200 or r15.status_code != 200 or r1h.status_code != 200:
            return None

        klines5  = r5.json()
        klines15 = r15.json()
        klines1h = r1h.json()

        if not isinstance(klines5, list) or not isinstance(klines15, list) or not isinstance(klines1h, list):
            return None
        if len(klines5) < 100 or len(klines15) < 100 or len(klines1h) < 50:
            return None

        closes5  = [float(k[4]) for k in klines5]
        closes15 = [float(k[4]) for k in klines15]
        closes1h = [float(k[4]) for k in klines1h]
        volumes5 = [float(k[5]) for k in klines5]
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

        return {
            "ema20_5m":          ema20_5m_cur,
            "ema50_5m":          calc_ema(closes5[:-1], 50),
            "ema20_15m":         calc_ema(closes15[:-1], 20),
            "ema50_15m":         calc_ema(closes15[:-1], 50),
            "ema20_15m_prev3":   ema20_15m_prev3,
            "ema50_15m_prev3":   ema50_15m_prev3,
            "ema20_1h":          ema20_1h_cur,
            "ema50_1h":          calc_ema(closes1h[:-1], 50),
            "ema20_1h_prev3":    ema20_1h_prev3,
            "last_close_5m":    closes5[-2],   # ultimo close CONFERMATO (candela chiusa)
            "close_1h_ago":     closes1h[-2] if len(closes1h) >= 2 else 0.0,
            "atr_5m":           atr_5m,
            "pullback_low_5m":  pullback_low_5m,
            "vol_avg_20":       vol_avg_20,
            "vol_last":         vol_last,
            "rsi_14":           rsi_14,
            "candle_body":      candle_body,
            "body_ratio":       body_ratio,
            "ema20_5m_prev3":   ema20_5m_prev3,
            "atr_15m_long":     atr_15m_long,
            "atr_15m_short":    atr_15m_short,
            "close_10_ago":     close_10_ago,
            "updated_at":       time.time(),
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
    )[:CANDLE_UNIVERSE_SIZE]

    if not universe:
        return

    syms = [sym for sym, _ in universe]
    print(f"Aggiornamento candele per {len(syms)} coin...")

    # Fetch parallelo con un unico client (rispetta rate limit Binance)
    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [fetch_candles_for_symbol(sym, client) for sym in syms]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    updated = 0
    for sym, result in zip(syms, results):
        if result and not isinstance(result, Exception):
            candle_data[sym] = result
            updated += 1

    _candles_last_update = time.time()
    print(f"Candele aggiornate: {updated}/{len(syms)}")

def get_ema_signal(sym: str, current_price: float, pullback_tolerance: float = 0.02,
                   max_stop_pct: float = 0.05,
                   trend1h_filter: bool = True, rsi_filter: bool = True,
                   rsi_min: float = 35.0, rsi_max: float = 65.0,
                   min_r: float = 0.01) -> dict:
    """
    Analizza il segnale di pullback per una coin.
    Condizioni: trend 1h + 15m, prezzo vicino a EMA20 15m (pullback), RSI, candela bullish, volume, stop valido.
    """
    cd = candle_data.get(sym)
    if not cd:
        return {"signal": False, "reason": "no candle data", "stop_price": 0.0, "R": 0.0,
                "trend_ok": False, "pullback_ok": False,
                "stop_ok": False, "rsi_ok": True, "trend1h_ok": True, "atr_5m": 0.0}

    ema20_15m        = cd["ema20_15m"]
    ema50_15m        = cd["ema50_15m"]
    ema20_15m_prev3  = cd.get("ema20_15m_prev3", ema20_15m)
    ema50_15m_prev3  = cd.get("ema50_15m_prev3", ema50_15m)
    ema20_5m         = cd["ema20_5m"]
    ema20_1h         = cd.get("ema20_1h", 0)
    ema50_1h         = cd.get("ema50_1h", 0)
    atr_5m           = cd["atr_5m"]
    pullback_low_5m  = cd["pullback_low_5m"]
    rsi_14           = cd.get("rsi_14", 50.0)
    candle_body      = cd.get("candle_body", 0.0)
    body_ratio       = cd.get("body_ratio", 0.0)
    last_close_5m    = cd.get("last_close_5m", current_price)
    vol_avg_20       = cd.get("vol_avg_20", 0.0)
    vol_last         = cd.get("vol_last", 0.0)
    ema20_5m_prev3   = cd.get("ema20_5m_prev3", ema20_5m)
    ema20_1h_prev3   = cd.get("ema20_1h_prev3", ema20_1h)
    atr_15m_long     = cd.get("atr_15m_long", 0.0)
    atr_15m_short    = cd.get("atr_15m_short", 0.0)

    # 1. Trend rialzista su 1h (macro): EMA20 > EMA50
    trend1h_ok = (ema20_1h > ema50_1h) if (trend1h_filter and ema20_1h > 0 and ema50_1h > 0) else True

    # 2. Trend rialzista su 15m: EMA20 > EMA50 (uptrend attivo sulla timeframe operativa)
    trend_ok = ema20_15m > ema50_15m

    # 3. Pullback: prezzo vicino all'EMA20 su 15m (entro pullback_tolerance)
    #    Compra la correzione verso la media, non il breakout già partito
    dist_from_ema20 = (current_price - ema20_15m) / ema20_15m if ema20_15m > 0 else 1.0
    pullback_ok = abs(dist_from_ema20) <= pullback_tolerance

    # 4. EMA20 1h in pendenza positiva (trend macro in salita)
    slope_ok = ema20_1h > ema20_1h_prev3

    # 5. Prezzo live vicino al close confermato (drift < 1%)
    price_drift = abs(current_price - last_close_5m) / last_close_5m if last_close_5m > 0 else 0
    fresh_ok = price_drift <= 0.01

    # 6. RSI in zona (non ipercomprato, c'è spazio per salire)
    rsi_ok = (rsi_min <= rsi_14 <= rsi_max) if rsi_filter else True

    # 7. Ultima candela 5m chiusa bullish con corpo solido (rimbalzo confermato)
    body_ok = candle_body > 0 and body_ratio >= 0.30

    # 8. Volume sopra la media (il rimbalzo ha partecipazione reale)
    vol_ok = (vol_last >= vol_avg_20) if vol_avg_20 > 0 else True

    # SL: minimo delle ultime candele chiuse oppure 1.5× ATR sotto il prezzo
    stop_from_low = pullback_low_5m
    stop_from_atr = current_price - atr_5m * 1.5 if atr_5m > 0 else 0.0
    stop_price    = min(stop_from_low, stop_from_atr) if stop_from_atr > 0 else stop_from_low

    R = (current_price - stop_price) / current_price if stop_price > 0 else 0.0
    stop_ok = min_r <= R <= max_stop_pct

    signal = trend1h_ok and trend_ok and pullback_ok and fresh_ok and rsi_ok and body_ok and vol_ok and stop_ok

    if not trend1h_ok:
        reason = f"no trend 1h (EMA20 {ema20_1h:.4f} < EMA50 {ema50_1h:.4f})"
    elif not trend_ok:
        reason = f"no trend 15m (EMA20 {ema20_15m:.4f} < EMA50 {ema50_15m:.4f})"
    elif not pullback_ok:
        direction = "sopra" if dist_from_ema20 > 0 else "sotto"
        reason = f"prezzo {abs(dist_from_ema20)*100:.2f}% {direction} EMA20 15m — fuori zona pullback ({pullback_tolerance*100:.1f}%)"
    elif not fresh_ok:
        direction = "salito" if current_price > last_close_5m else "sceso"
        reason = f"prezzo {direction} del {price_drift*100:.1f}% dal last close — segnale stantio"
    elif not rsi_ok:
        reason = f"RSI fuori zona ({rsi_14:.1f}, zona {rsi_min:.0f}-{rsi_max:.0f})"
    elif not body_ok:
        reason = f"candela ribassista o doji ({body_ratio*100:.0f}% del range)" if candle_body <= 0 else f"corpo troppo piccolo ({body_ratio*100:.0f}% < 30%)"
    elif not vol_ok:
        reason = f"volume basso ({vol_last/vol_avg_20:.2f}x media) — rimbalzo senza partecipazione"
    elif not stop_ok:
        if R > 0 and R < min_r:
            reason = f"R troppo piccolo ({R*100:.2f}% < {min_r*100:.1f}% min)"
        elif R > max_stop_pct:
            reason = f"stop troppo largo ({R*100:.1f}% > {max_stop_pct*100:.1f}%)"
        else:
            reason = "stop non calcolabile"
    else:
        reason = (f"OK | EMA20/50 1h: {ema20_1h:.4f}/{ema50_1h:.4f} | "
                  f"EMA20/50 15m: {ema20_15m:.4f}/{ema50_15m:.4f} | "
                  f"pullback: {dist_from_ema20*100:.2f}% | "
                  f"RSI: {rsi_14:.1f} | corpo: {body_ratio*100:.0f}% | "
                  f"vol: {vol_last/vol_avg_20:.2f}x | R: {R*100:.2f}%")

    return {
        "signal":       signal,
        "reason":       reason,
        "stop_price":   round(stop_price, 8),
        "R":            round(R, 6),
        "atr_5m":       atr_5m,
        "trend_ok":     trend_ok,
        "pullback_ok":  pullback_ok,
        "trend1h_ok":   trend1h_ok,
        "slope_ok":     slope_ok,
        "fresh_ok":     fresh_ok,
        "rsi_ok":       rsi_ok,
        "body_ok":      body_ok,
        "vol_ok":       vol_ok,
        "stop_ok":      stop_ok,
        "rsi":          rsi_14,
    }

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
                "breakout_ok": False, "vol_ok": False}

    close_10_ago = cd.get("close_10_ago", 0.0)
    last_close   = cd.get("last_close_5m", 0.0)
    vol_avg_20   = cd.get("vol_avg_20", 0.0)
    vol_last     = cd.get("vol_last", 0.0)

    momentum_pct = (last_close - close_10_ago) / close_10_ago if close_10_ago > 0 else 0.0
    breakout_ok  = momentum_pct >= momentum_threshold
    vol_ok       = (vol_last >= vol_avg_20 * vol_multiplier) if vol_avg_20 > 0 else False

    stop_price = current_price * (1 - max_stop_pct)

    signal = breakout_ok and vol_ok

    if not breakout_ok:
        reason = f"momentum debole | +{momentum_pct*100:.2f}% in 50min (soglia +{momentum_threshold*100:.0f}%)"
    elif not vol_ok:
        ratio = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        reason = f"volume basso ({ratio:.2f}x < {vol_multiplier}x richiesto)"
    else:
        ratio = vol_last / vol_avg_20
        reason = f"MOMENTUM +{momentum_pct*100:.2f}% in 50min | vol {ratio:.1f}x | SL -{max_stop_pct*100:.1f}%"

    return {
        "signal":      signal,
        "reason":      reason,
        "stop_price":  round(stop_price, 8),
        "breakout_ok": breakout_ok,
        "vol_ok":      vol_ok,
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

async def fetch_prices():
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
        if r.status_code != 200:
            print(f"[BINANCE] fetch_prices HTTP {r.status_code}: {r.text[:200]}")
            return
        tickers = r.json()
        if not isinstance(tickers, list):
            print(f"[BINANCE] fetch_prices risposta non-lista: {str(tickers)[:200]}")
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

async def get_revx_usd_balance(key_id: str, private_key: str) -> float:
    """Legge il saldo USD disponibile su Revolut X."""
    try:
        result = await revx_request("GET", "/api/1.0/balances", key_id=key_id, private_key=private_key)
        balances = result if isinstance(result, list) else result.get("balances", [])
        for b in balances:
            if b.get("currency") == "USD":
                return float(b.get("available", 0) or 0)
    except Exception as e:
        print(f"[REVX BALANCE] error: {e}")
    return 0.0


async def enter_position(state: dict, sym_data: dict, tradable_capital: float):
    cfg      = state["config"]
    price    = sym_data["price"]
    sym      = sym_data["symbol"]
    is_real  = cfg.get("realMode", False)

    alloc_pct  = cfg.get("allocPct", 0.20)
    use_revx   = state.get("use_revx", False)
    TRADING_FEE = 0.0009  # RevX taker fee 0.09%
    size = tradable_capital * alloc_pct
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
                # Retry su errori di rete — max 2 tentativi
                result = None
                for attempt in range(2):
                    try:
                        result = await revx_request("POST", "/api/1.0/orders", order_body, key_id=revx_key_id, private_key=revx_priv)
                        break
                    except Exception as net_err:
                        if attempt == 0:
                            print(f"[REVX ORDER] tentativo 1 fallito: {net_err}, riprovo...")
                            await asyncio.sleep(2)
                            order_body["client_order_id"] = str(_uuid.uuid4())  # nuovo ID per il retry
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
                # Tutto in USD: qty = size_usd / price_usd (Binance)
                # Coerente con currentPrice, stopPrice, tp1Price che sono tutti USD
                actual_price = price  # prezzo Binance USD al momento dell'ordine
                qty_purchased = size / actual_price if actual_price > 0 else 0.0
                print(f"[REVX BUY] qty={qty_purchased:.6f} @ ${actual_price:.4f} USD size=${size:.2f}")
                stop_price  = actual_price * (1 - R_pct)
                tp1_price   = actual_price * (1 + R_pct * tp1_multiplier)
                tp2_price   = actual_price * (1 + R_pct * tp2_multiplier)
                add_log(state, "buy", "ACQUISTO REALE (RevX)",
                    f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | Qty: {qty_purchased:.6f} | "
                    f"SL: ${stop_price:.4f} | TP1: ${tp1_price:.4f} | TP2: ${tp2_price:.4f} | R: {R_pct*100:.2f}%")
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
                "entry_usd": round(size, 2),  # USD effettivamente spesi su RevX
            }
            state["positions"].append(pos)
            return
    else:
        actual_price = price
        add_log(state, "buy", "ACQUISTO SIM",
            f"{sym} @ {fmt_price(actual_price)} | Size: ${size:.0f} | Fee: ${entry_fee:.2f} | "
            f"SL: {fmt_price(stop_price)} | TP1: {fmt_price(tp1_price)} | TP2: {fmt_price(tp2_price)} | R: {R_pct*100:.2f}%")
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
        if pos.get("exchange") == "revx":
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
                # Leggi saldo reale da RevX per evitare "Insufficient balance"
                try:
                    balances = await revx_request("GET", "/api/1.0/balances",
                                                  key_id=revx_key_id, private_key=revx_priv)
                    bal_list = balances if isinstance(balances, list) else balances.get("balances", [])
                    for b in bal_list:
                        if b.get("currency") == sym:
                            real_qty = float(b.get("available", 0) or 0)
                            if real_qty > 0:
                                # Usa la qty reale su RevX — ignora quella tracciata in USD
                                qty_to_sell_real = round(real_qty * (0.5 if partial else 1.0), 8)
                                print(f"[REVX SELL] {sym} qty_tracciata={qty_to_sell:.6f} qty_reale={real_qty:.6f} -> vendo {qty_to_sell_real:.6f}")
                                qty_to_sell = qty_to_sell_real
                                pos["qty_purchased"] = real_qty
                            else:
                                add_log(state, "info", "WARN", f"{sym}: saldo RevX = 0, posizione rimossa")
                                if pos in state["positions"]:
                                    state["positions"].remove(pos)
                                return
                            break
                except Exception as be:
                    print(f"[REVX SELL] errore lettura saldo: {be}")
                # Limit order IOC con slippage progressivo — evita slippage protection RevX
                # Tre tentativi: -0.5%, -1.5%, -3% sotto prezzo corrente
                SELL_SLIP_BUFFERS = [0.001, 0.005, 0.015]
                result = None
                for slip_attempt, slip_buf in enumerate(SELL_SLIP_BUFFERS):
                    limit_price = round(cur * (1 - slip_buf), 8)
                    order_body = {
                        "client_order_id": str(_uuid.uuid4()),
                        "symbol": symbol_pair,
                        "side": "SELL",
                        "order_configuration": {
                            "limit": {
                                "base_size": str(qty_to_sell),
                                "price": str(limit_price),
                                "time_in_force": "IOC"
                            }
                        }
                    }
                    print(f"[REVX SELL] {sym} limit @ ${limit_price:.6f} (-{slip_buf*100:.1f}%) attempt {slip_attempt+1}/{len(SELL_SLIP_BUFFERS)}")
                    try:
                        result = await revx_request("POST", "/api/1.0/orders", order_body, key_id=revx_key_id, private_key=revx_priv)
                        _d = result.get("data") or result
                        _state = _d.get("state", "")
                        if _state in ("filled", "partially_filled"):
                            break  # successo
                        if _state == "new":
                            # IOC returned 'new' — RevX still processing; poll for final state
                            _oid = _d.get("venue_order_id") or _d.get("order_id")
                            if _oid:
                                for _pi in range(5):
                                    await asyncio.sleep(1)
                                    try:
                                        _pr = await revx_request("GET", f"/api/1.0/orders/{_oid}", None, key_id=revx_key_id, private_key=revx_priv)
                                        _pd = _pr.get("data") or _pr
                                        _ps = _pd.get("state", "")
                                        print(f"[REVX SELL] {sym} poll {_pi+1}/5 order {_oid[:8]}: state={_ps}")
                                        if _ps in ("filled", "partially_filled"):
                                            result = _pr; _state = _ps; break
                                        if _ps in ("cancelled", "expired", "rejected"):
                                            _state = _ps; break
                                    except Exception as _pe:
                                        print(f"[REVX SELL] {sym} poll error: {_pe}"); break
                            if _state in ("filled", "partially_filled"):
                                break
                            # Still unresolved — treat as cancelled for retry
                            _state = "cancelled"
                        if _state == "cancelled" and slip_attempt < len(SELL_SLIP_BUFFERS) - 1:
                            print(f"[REVX SELL] limit -{slip_buf*100:.1f}% cancelled, riprovo con spread più largo...")
                            await asyncio.sleep(1)
                        else:
                            break  # errore API o ultimo tentativo
                    except Exception as net_err:
                        if slip_attempt < len(SELL_SLIP_BUFFERS) - 1:
                            print(f"[REVX SELL] tentativo {slip_attempt+1} errore: {net_err}, riprovo...")
                            await asyncio.sleep(2)
                        else:
                            raise
                print(f"[REVX SELL RESULT] {sym}: {result}")
                data = result.get("data") or result
                order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
                order_state = data.get("state", "")
                sell_failed = not order_id or order_state == "cancelled"
                if sell_failed:
                    err_msg = f"ordine {order_state}" if order_state == "cancelled" else (result.get("message") or result.get("error") or result.get("detail") or str(result))
                    # Conta tentativi falliti consecutivi
                    pos["_sell_failures"] = pos.get("_sell_failures", 0) + 1
                    add_log(state, "info", "ERRORE", f"Vendita RevX {sym} fallita ({pos['_sell_failures']}x): {err_msg}")
                    await notify(state, f"ERRORE VENDITA RevX {sym}: {err_msg[:100]}")
                    # Dopo 3 fallimenti: rimuovi posizione dalla memoria (l'ordine non esiste su RevX)
                    if pos.get("_sell_failures", 0) >= 3:
                        add_log(state, "info", "WARN", f"{sym} rimosso dalla memoria dopo 3 vendite fallite — verifica su RevX")
                        await notify(state, f"WARN: {sym} rimosso da memoria dopo 3 errori. Verifica saldo su Revolut X.")
                        # Non fare return — lascia che il codice dopo rimuova la posizione
                    else:
                        _exiting.discard(sym); return
                filled_price = float(data.get("average_price") or data.get("price") or limit_price)
                if filled_price > 0:
                    cur = filled_price
                add_log(state, "info", "VENDUTO RevX", f"{sym} qty: {qty_to_sell:.6f} @ ${cur:.4f}")
                if partial:
                    pos["qty_purchased"] = qty_purchased - qty_to_sell
            except Exception as e:
                add_log(state, "info", "ERRORE", f"RevX exit error: {e}")
                _exiting.discard(sym); return

    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * close_size
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    fee_pct = pos.get("fee_pct", 0.0009)
    exit_fee = close_size * fee_pct
    pnl -= exit_fee
    if pos.get("realMode", False):
        # In reale la fee d'entrata è già stata detratta dal saldo RevX: corretta nel PnL display
        pnl -= close_size * fee_pct

    if partial:
        # TP1: restituisce metà capitale, aggiorna size_remaining
        # Il nuovo stop viene gestito dal trailing in scan_and_trade
        state["currentCapital"] += close_size + pnl
        pos["size_remaining"] -= close_size
        pos["stopPrice"]       = pos["entryPrice"]  # breakeven minimo
        pos["tp1_hit"]         = True
        pos["tp1_pnl"]         = pnl  # salviamo per il messaggio finale
        pos["qty_tp1_sold"]    = qty_to_sell  # qty venduta a TP1 per calcolo proporzione
        mode = "REALE" if pos.get("realMode") else "SIM"
        add_log(state, "sell", f"TP1 {mode}",
            f"{sym} 50% @ ${cur:.4f} | +{pnl:.2f}$ ({pct:+.2f}%) | trailing stop attivo")
        if pos.get("realMode"):
            await notify(state,
                "TP1 REALE\n" + sym + " 50% @ $" + f"{cur:.4f}" +
                "\nP&L parziale: +$" + f"{pnl:.2f}" + "\nStop spostato a breakeven"
            )
        else:
            await notify(state,
                "TP1 SIM\n" + sym + " 50% @ $" + f"{cur:.4f}" +
                "\nP&L parziale: +$" + f"{pnl:.2f}" + "\nStop spostato a breakeven"
            )
        _exiting.discard(sym)
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
    # Dopo uno stop loss secco (senza TP1), cooldown più lungo per proteggere da re-entry su trend avverso
    is_clean_stop = ("STOP" in reason) and not pos.get("tp1_hit", False)
    cooldown_h = cfg.get("cooldown", 1)
    state["cooldowns"][sym] = (datetime.now().timestamp() + cooldown_h * 3600) * 1000
    trade_record = {
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": total_pnl, "pct": total_pct, "time": datetime.utcnow().isoformat() + "Z",
        "entryTime": pos["entryTime"], "durationMin": round(dur, 1),
        "size": pos["size"], "realMode": pos.get("realMode", False),
        "tp1_hit": pos.get("tp1_hit", False),
    }
    state["trades"].append(trade_record)
    if db_pool and user_id:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO trades_history
                    (user_id, symbol, entry_price, exit_price, size, pnl, pct,
                     reason, tp1_hit, duration_min, entry_time, exit_time, mode)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                """, user_id, sym,
                    float(pos["entryPrice"]), float(cur),
                    float(pos["size"]), float(total_pnl), float(total_pct),
                    reason, bool(pos.get("tp1_hit", False)), float(round(dur, 1)),
                    pos["entryTime"], datetime.utcnow().isoformat() + "Z",
                    "real" if pos.get("realMode") else "sim"
                )
        except Exception as e:
            print(f"DB trade save error: {e}")
    state["positions"] = [p for p in state["positions"] if p is not pos]
    _exiting.discard(sym)
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
        state["running"] = False
        add_log(state, "info", "STOP AUTO",
            f"{max_losses} perdite consecutive — sessione fermata automaticamente")
        await notify(state, f"STOP AUTO: {max_losses} perdite consecutive")

# ── main loop ─────────────────────────────────────────────────────────────────

async def scan_and_trade(state: dict, user_id: int = None):
    if not state["running"] or state.get("_stopping"):
        return
    cfg = state["config"]

    elapsed_ms = (datetime.now().timestamp() - state["sessionStart"]) * 1000
    session_duration = state["sessionDuration"]
    if session_duration > 0 and elapsed_ms >= session_duration:
        state["running"] = False
        for p in list(state["positions"]):
            await exit_position(state, p, "SESSIONE SCADUTA", user_id=user_id)
        add_log(state, "info", "FINE SESSIONE", "Durata massima raggiunta.")
        return

    # Controllo maxTrades
    max_trades = cfg.get("maxTrades", 0)
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        if state["positions"]:
            pass  # aspetta che le posizioni aperte si chiudano
        else:
            state["running"] = False
            add_log(state, "info", "STOP AUTO", f"Raggiunto limite di {max_trades} trade — sessione fermata")
            return

    # Gestione posizioni aperte: hard stop + trailing profit stop
    for pos in list(state["positions"]):
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
            peak         = pos.get("peak_price", cur)
            profit_move  = peak - entry
            tolerance    = cfg.get("profitTolerance", 0.20)
            trail_price  = peak - profit_move * tolerance
            if cur <= trail_price:
                await exit_position(state, pos, "TRAILING PROFIT", user_id=user_id)
                continue

    alloc_pct   = cfg.get("allocPct", 0.20)
    capital_pct = cfg.get("capitalPct", 1.0)
    TRADING_FEE = 0.0009  # RevX taker fee 0.09%

    # Calcola il capitale tradabile dinamicamente
    if cfg.get("realMode", False):
        use_revx = state.get("use_revx", False)
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
        # Sim: usa currentCapital (già aggiornato dopo ogni trade)
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
    size_per_trade = tradable_capital * alloc_pct
    fee_reserve = size_per_trade * TRADING_FEE * 2 * slots  # entrata + uscita per ogni slot
    tradable_capital_net = tradable_capital - fee_reserve

    # Non aprire nuove posizioni se maxTrades raggiunto
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        _update_pnl(state)
        return

    if slots <= 0 or tradable_capital < state["capital"] * alloc_pct * capital_pct * 0.5:
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
    universe = [
        {**d, "symbol": sym}
        for sym, d in market_data.items()
        if d["price"] > 0
        and sym in _dynamic_universe
        and d.get("volume24h", 0) >= min_vol
        and sym not in open_syms
        and (not use_revx_filter or not _revx_pairs or sym in _revx_pairs)
        and sym in candle_data
        and (state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
    ]
    universe_sorted = sorted(universe, key=lambda d: d.get("volume24h", 0), reverse=True)

    candidates   = []
    skipped      = 0
    block_count  = {"breakout": 0, "vol": 0}

    for d in universe_sorted:
        sym    = d["symbol"]
        signal = get_momentum_signal(sym, d["price"], max_stop_pct, vol_mult, momentum_thr)
        if not signal["signal"]:
            skipped += 1
            if not signal.get("breakout_ok"): block_count["breakout"] += 1
            elif not signal.get("vol_ok"):    block_count["vol"] += 1
            continue
        d["ema_reason"] = signal["reason"]
        d["stop_price"] = signal["stop_price"]
        d["R_pct"]      = max_stop_pct
        candidates.append(d)
        if len(candidates) >= slots:
            break

    add_log(state, "info", "SCAN",
        f"Universe: {len(universe_sorted)} | Candidati: {len(candidates)} | "
        f"Saltati: {skipped} | no-breakout: {block_count['breakout']} | low-vol: {block_count['vol']} | "
        f"Candele: {len(candle_data)}"
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
                    if state and state.get("running"):
                        pos_list = ", ".join([p["symbol"] for p in state["positions"]]) or "nessuna"
                        pnl = unrealized_pnl(state)
                        await send_telegram_to(chat_id, f"Sessione attiva\nPosizioni: {pos_list}\nP&L: ${pnl:.2f}")
                    else:
                        await send_telegram_to(chat_id, "Nessuna sessione attiva")

                elif cmd == "/STOP":
                    if state and state.get("running"):
                        state["running"] = False
                        closed = [p["symbol"] for p in list(state["positions"])]
                        for p in list(state["positions"]):
                            await exit_position(state, p, "STOP MANUALE", user_id=uid)
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
                                await exit_position(state, pos, "TELEGRAM")
                                await send_telegram_to(chat_id, f"✅ Posizione {sym} chiusa")
                            else:
                                await send_telegram_to(chat_id, f"Nessuna posizione aperta su {sym}")
                        else:
                            await send_telegram_to(chat_id, "Nessuna sessione attiva")
                    else:
                        await send_telegram_to(chat_id, "Uso: /close <SYM>")
        except Exception as e:
            print(f"Telegram poll error: {e}")

# ── background loop ───────────────────────────────────────────────────────────

async def background_loop():
    consecutive_errors = 0
    last_persist = 0.0
    while True:
        try:
            await fetch_prices()

            if time.time() - _universe_last_update >= UNIVERSE_UPDATE_INTERVAL:
                await fetch_dynamic_universe()

            if time.time() - _candles_last_update >= CANDLE_UPDATE_INTERVAL:
                await fetch_all_candles()

            sessions_snapshot = list(user_sessions.items())
            for uid, state in sessions_snapshot:
                if state["running"]:
                    try:
                        await scan_and_trade(state, user_id=uid)
                    except Exception as user_err:
                        import traceback as _tb
                        print(f"[scan_and_trade] user {uid}: {user_err}\n{_tb.format_exc()}")

            # Persisti sessioni ogni 30 secondi
            if time.time() - last_persist >= 30:
                await persist_sessions()
                last_persist = time.time()

            consecutive_errors = 0
            await asyncio.sleep(8)
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
    _SENSITIVE_KEYS = {"revx_key_id", "revx_private_key"}
    sessions_snapshot = list(user_sessions.items())
    for uid, state in sessions_snapshot:
        try:
            state_to_save = {k: v for k, v in state.items() if k not in _SENSITIVE_KEYS and k not in ("log", "_exiting", "_stopping")}
            state_json = json.dumps(state_to_save, default=str)
            async with db_pool.acquire() as conn:
                if state.get("running"):
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
    global _global_revx_key_id, _global_revx_private_key, _revx_pairs
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
    """Ripristina sessioni attive salvate nel DB dopo un riavvio."""
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT s.user_id, s.state_json, u.revx_key_id, u.revx_private_key
                FROM active_sessions s JOIN users u ON u.id = s.user_id
            """)
        for row in rows:
            uid = row["user_id"]
            try:
                state = json.loads(row["state_json"])
                if not state.get("running"):
                    continue
                session_start = state.get("sessionStart", 0)
                session_dur   = state.get("sessionDuration", 0)
                if session_dur > 0:
                    elapsed = (datetime.now().timestamp() - session_start) * 1000
                    if elapsed >= session_dur:
                        continue
                state["revx_key_id"]     = decrypt_key(row["revx_key_id"] or "")
                state["revx_private_key"] = decrypt_key(row["revx_private_key"] or "")
                user_sessions[uid] = state
                print(f"Sessione ripristinata per user {uid} con {len(state.get('positions',[]))} posizioni")
            except Exception as e:
                print(f"Errore ripristino sessione user {uid}: {e}")
    except Exception as e:
        print(f"Errore restore sessioni: {e}")

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
            "SELECT username, display_name, avatar_b64, sim_mode, revx_key_id, telegram_chat_id, "
            "plan, subscription_expires_at, last_session_date, sessions_today FROM users WHERE id = $1", user_id
        )
    has_keys = bool(row.get("revx_key_id"))
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
        "avatar_b64": row["avatar_b64"] or "",
        "sim_mode": sim,
        "has_revx_keys": bool(row.get("revx_key_id") or ""),
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
    }

@app.get("/market")
async def get_market(request: Request, user_id: int = Depends(get_current_user)):
    check_rate_limit(request, max_attempts=60, window=60, key_suffix="market")
    items = []
    # Usa la configurazione della sessione dell'utente richiedente, altrimenti default
    user_state = user_sessions.get(user_id, {})
    active_cfg = user_state.get("config", {})

    max_stop_pct  = active_cfg.get("maxStopPct", 0.02)
    vol_mult      = active_cfg.get("volMultiplier", 1.2)
    momentum_thr  = active_cfg.get("momentumPct", 0.01)

    for s, d in market_data.items():
        if d["price"] <= 0:
            continue
        if s not in _dynamic_universe:
            continue
        item = {"symbol": s, **d}
        sig = get_momentum_signal(s, d["price"], max_stop_pct, vol_mult, momentum_thr)
        item["ema"] = {
            "breakout_ok": sig.get("breakout_ok", False),
            "vol_ok":      sig.get("vol_ok", False),
            "signal":      sig["signal"],
            "reason":      sig["reason"],
        }
        items.append(item)

    # Filtra sempre alle coin RevX se disponibili — sim e reale mostrano le stesse coin
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
    cfg["sessionDuration"]    = _clamp_int(cfg.get("sessionDuration", 8), 1, 48, 8)

    real_mode = False
    revx_key_id, revx_private_key, use_revx = "", "", False
    user_plan = "free"
    row = None
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT sim_mode, revx_key_id, revx_private_key, username, display_name, "
                    "telegram_chat_id, plan, subscription_expires_at, last_session_date, sessions_today "
                    "FROM users WHERE id = $1", user_id)
                if row:
                    revx_key_id      = decrypt_key(row["revx_key_id"] or "")
                    revx_private_key = decrypt_key(row["revx_private_key"] or "")
                    sim = row["sim_mode"] if row["sim_mode"] is not None else True
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
                        # Aggiorna contatore
                        new_count = sessions_today + 1
                        await conn.execute(
                            "UPDATE users SET last_session_date = $1, sessions_today = $2 WHERE id = $3",
                            today, new_count, user_id
                        )
        except Exception as e:
            print(f"DB key fetch error: {e}")

    # Override configurazione per utenti free
    if user_plan == "free":
        cfg["allocPct"]        = FREE_ALLOC_PCT
        cfg["sessionDuration"] = min(int(cfg.get("sessionDuration", FREE_MAX_SESSION_HOURS)), FREE_MAX_SESSION_HOURS)
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

    state.update({
        "running": True,
        "_exiting": set(),
        "capital": capital,
        "currentCapital": capital,
        "positions": [],
        "pnlHistory": [{"t": 0, "v": 0}],
        "sessionStart": datetime.now().timestamp(),
        "sessionDuration": int(cfg.get("sessionDuration", 8)) * 3600 * 1000,
        "config": {
            "allocPct":            float(cfg.get("allocPct", 0.20)),
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
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "revx_key_id": revx_key_id, "revx_private_key": revx_private_key,
        "use_revx": use_revx,
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
    mom_thr_pct  = float(cfg.get("momentumPct", 0.01)) * 100
    vol_mult_s   = float(cfg.get("volMultiplier", 1.2))
    max_stop_pct_s = float(cfg.get("maxStopPct", 0.02)) * 100
    btc_filt_s   = "ON" if cfg.get("btcEmaFilter", True) else "OFF"
    curr_sym     = "$"
    exchange_name = "Revolut X" if real_mode else "SIM"
    add_log(state, "info", "AVVIO",
        f"{curr_sym}{capital:.0f} | {mode} [{exchange_name}] | Cap: {capp:.0f}% | Alloc: {alloc:.0f}% | "
        f"Momentum: +{mom_thr_pct:.1f}% | Vol: {vol_mult_s}x | Stop: -{max_stop_pct_s:.1f}% | "
        f"BTC: {btc_filt_s} | MaxHold: {mxh}h | MaxLoss: {mcl}"
    )
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
        await exit_position(state, p, "STOP MANUALE", user_id=user_id)
    # Se alcune posizioni non sono state vendute, non chiudere la sessione
    remaining = state.get("positions", [])
    if remaining:
        state.pop("_stopping", None)
        syms = ", ".join(p["symbol"] for p in remaining)
        add_log(state, "info", "ERRORE", f"Stop annullato: vendita fallita per {syms} — riprova")
        return {"error": f"Vendita fallita per: {syms}. Sessione non fermata.", "remaining": [p["symbol"] for p in remaining]}
    state["running"] = False
    state.pop("_stopping", None)
    pnl = state["currentCapital"] - state["capital"]
    add_log(state, "info", "STOP", f"P&L finale: {pnl:+.2f}$")
    await persist_sessions()  # rimuovi dal DB
    return {"ok": True, "pnl": pnl}

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
    return {"ok": True}

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
        return {"error": str(data.get("error", data))}

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
    return {
        "candles_count": len(candle_data),
        "last_update": datetime.fromtimestamp(_candles_last_update).isoformat() if _candles_last_update else None,
        "next_update_in_sec": max(0, CANDLE_UPDATE_INTERVAL - (time.time() - _candles_last_update)) if _candles_last_update else 0,
        "sample_signals": sample,
    }

class RevxKeysRequest(BaseModel):
    key_id: str
    private_key: str

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
        # Revolut X può restituire lista diretta o dict con "balances"
        if isinstance(result, list):
            balances_raw = result
        else:
            balances_raw = result.get("balances", [])
        balances = [
            {"currency": b.get("currency", ""), "available": b.get("available", "0")}
            for b in balances_raw
            if float(b.get("available", 0) or 0) > 0
        ]
        return {"ok": True, "balances": balances}
    except Exception as e:
        return {"ok": False, "error": str(e)}

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
    # Per tutte le coin in market_data: hardcoded > CoinGecko cache > Binance CDN
    result = {
        sym: KNOWN.get(sym)
             or _cg_logos.get(sym)
             or f"https://bin.bnbstatic.com/image/crypto/square/{sym}.png"
        for sym in market_data
    }
    return result

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
    _allowed = tuple(o for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip().startswith("https://"))
    if _allowed:
        if not any(success_url.startswith(o.strip()) for o in _allowed):
            raise HTTPException(status_code=400, detail="success_url non autorizzata")
        if not any(cancel_url.startswith(o.strip()) for o in _allowed):
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
            success_url=success_url + "?upgraded=1",
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
