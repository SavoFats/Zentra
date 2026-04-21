import asyncio
import os
import time
import jwt
import hashlib
import json
import secrets
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx
import uvicorn
import asyncpg
import bcrypt
from cryptography.fernet import Fernet

app = FastAPI()
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET","POST","DELETE"], allow_headers=["Authorization","Content-Type"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable non impostata — il server non può partire in modo sicuro")

# ── ENCRYPTION (chiavi Coinbase) ──────────────────────────────────────────────
def _get_fernet() -> Fernet:
    import base64, hashlib
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_key(text: str) -> str:
    """Cifra una stringa sensibile prima di salvarla nel DB."""
    if not text:
        return ""
    try:
        return _get_fernet().encrypt(text.encode()).decode()
    except Exception:
        return text  # fallback: salva plaintext se qualcosa va storto

def decrypt_key(text: str) -> str:
    """Decifra una stringa recuperata dal DB."""
    if not text:
        return ""
    try:
        return _get_fernet().decrypt(text.encode()).decode()
    except Exception:
        return text  # fallback: restituisce così com'è (retrocompatibilità con valori plaintext esistenti)

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

security = HTTPBearer()

def create_token(user_id: int) -> str:
    import base64
    payload = f"{user_id}:{int(time.time()) + 86400 * 30}"
    sig = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:32]
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(token: str) -> int:
    import base64
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split(":")
        user_id, expires, sig = int(parts[0]), int(parts[1]), parts[2]
        if int(time.time()) > expires:
            raise HTTPException(status_code=401, detail="Token scaduto")
        payload = f"{user_id}:{expires}"
        expected = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:32]
        if sig != expected:
            raise HTTPException(status_code=401, detail="Token non valido")
        return user_id
    except (HTTPException, ValueError, IndexError, AttributeError):
        raise HTTPException(status_code=401, detail="Token non valido")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return verify_token(credentials.credentials)

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ApiKeyRequest(BaseModel):
    cb_key: str
    cb_secret: str

BINANCE_BASE = "https://api.binance.com"
COINBASE_BASE = "https://api.coinbase.com"

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

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

_ENV_CB_KEY    = os.environ.get("CB_KEY", "")
_ENV_CB_SECRET = os.environ.get("CB_SECRET", "")

def make_coinbase_jwt(method: str, path: str, cb_key: str, cb_secret: str) -> str:
    key = cb_secret
    if '\\n' in key:
        key = key.replace('\\n', '\n')
    elif '\n' not in key and 'BEGIN' in key:
        key = key.replace('-----BEGIN EC PRIVATE KEY----- ', '-----BEGIN EC PRIVATE KEY-----\n')
        key = key.replace(' -----END EC PRIVATE KEY-----', '\n-----END EC PRIVATE KEY-----')
    payload = {
        "sub": cb_key,
        "iss": "cdp",
        "nbf": int(time.time()),
        "exp": int(time.time()) + 120,
        "uri": f"{method} api.coinbase.com{path}",
    }
    token = jwt.encode(payload, key, algorithm="ES256",
                       headers={"kid": cb_key, "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:16]})
    return token

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

async def coinbase_request(method: str, path: str, body: dict = None,
                           cb_key: str = None, cb_secret: str = None) -> dict:
    api_key    = cb_key    or _ENV_CB_KEY
    api_secret = cb_secret or _ENV_CB_SECRET
    jwt_path = path.split("?")[0]
    token = make_coinbase_jwt(method, jwt_path, api_key, api_secret)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            r = await client.get(f"{COINBASE_BASE}{path}", headers=headers)
        else:
            r = await client.post(f"{COINBASE_BASE}{path}", headers=headers, json=body)
    return r.json()

# ── market data ───────────────────────────────────────────────────────────────

market_data = {}  # sym -> {price, change1h, change24h, volume24h, icon}
user_sessions: dict = {}
_market_data_lock = asyncio.Lock()
_sessions_lock = asyncio.Lock()

# ── CANDLE DATA (nuovo) ───────────────────────────────────────────────────────
# sym -> {
#   "ema20_5m": float, "ema50_5m": float,
#   "ema20_15m": float, "ema50_15m": float,
#   "last_close_5m": float,
#   "updated_at": float (timestamp)
# }
candle_data: dict = {}
_candles_last_update: float = 0
CANDLE_UPDATE_INTERVAL = 300  # secondi (5 minuti)
CANDLE_UNIVERSE_SIZE   = 40   # top N coin per volume

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

        # Minimo delle ultime 3 candele 5m (per stop contestuale)
        pullback_low_5m = min(lows5[-3:]) if len(lows5) >= 3 else lows5[-1]

        # Volume medio ultime 20 candele 5m
        vol_avg_20 = sum(volumes5[-20:]) / 20 if len(volumes5) >= 20 else 0.0
        vol_last   = volumes5[-1]

        # RSI(14) su 5m
        rsi_14 = calc_rsi(closes5, 14)

        # Corpo ultima candela 5m: close - open
        last_candle  = klines5[-1]
        last_open    = float(last_candle[1])
        last_close_c = float(last_candle[4])
        last_high    = float(last_candle[2])
        last_low_c   = float(last_candle[3])
        candle_range = last_high - last_low_c
        candle_body  = last_close_c - last_open  # positivo = verde
        body_ratio   = abs(candle_body) / candle_range if candle_range > 0 else 0.0

        return {
            "ema20_5m":         calc_ema(closes5,  20),
            "ema50_5m":         calc_ema(closes5,  50),
            "ema20_15m":        calc_ema(closes15, 20),
            "ema50_15m":        calc_ema(closes15, 50),
            "ema20_1h":         calc_ema(closes1h, 20),
            "ema50_1h":         calc_ema(closes1h, 50),
            "last_close_5m":    closes5[-1],
            "close_1h_ago":     closes1h[-2] if len(closes1h) >= 2 else 0.0,
            "atr_5m":           atr_5m,
            "pullback_low_5m":  pullback_low_5m,
            "vol_avg_20":       vol_avg_20,
            "vol_last":         vol_last,
            "rsi_14":           rsi_14,
            "candle_body":      candle_body,
            "body_ratio":       body_ratio,
            "updated_at":       time.time(),
        }
    except Exception as e:
        print(f"Candle error {sym}: {e}")
        return None

async def fetch_all_candles():
    """Aggiorna candle_data per le top CANDLE_UNIVERSE_SIZE coin per volume."""
    global _candles_last_update

    # Seleziona top coin per volume tra quelle con prezzo noto
    universe = sorted(
        [(sym, d) for sym, d in market_data.items() if d["price"] > 0],
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

def get_ema_signal(sym: str, current_price: float, pullback_tolerance: float = 0.015,
                   vol_multiplier: float = 1.2, max_stop_pct: float = 0.025,
                   trend1h_filter: bool = True, rsi_filter: bool = True,
                   rsi_min: float = 35.0, rsi_max: float = 70.0,
                   min_r: float = 0.01) -> dict:
    """
    Analizza il segnale EMA + RSI + volume per una coin.
    Restituisce segnale, stop price contestuale e R (rischio per unità).
    """
    cd = candle_data.get(sym)
    if not cd:
        return {"signal": False, "reason": "no candle data", "stop_price": 0.0, "R": 0.0,
                "trend_ok": False, "pullback_ok": False, "bounce_ok": False,
                "vol_ok": False, "stop_ok": False, "rsi_ok": True, "trend1h_ok": True}

    ema20_15m       = cd["ema20_15m"]
    ema50_15m       = cd["ema50_15m"]
    ema20_5m        = cd["ema20_5m"]
    ema20_1h        = cd.get("ema20_1h", 0)
    ema50_1h        = cd.get("ema50_1h", 0)
    last_close_5m   = cd["last_close_5m"]
    atr_5m          = cd["atr_5m"]
    pullback_low_5m = cd["pullback_low_5m"]
    vol_avg_20      = cd["vol_avg_20"]
    vol_last        = cd["vol_last"]
    rsi_14          = cd.get("rsi_14", 50.0)
    body_ratio      = cd.get("body_ratio", 0.0)
    candle_body     = cd.get("candle_body", 0.0)

    # 1. Trend rialzista su 15min
    trend_ok = ema20_15m > ema50_15m

    # 2. Trend rialzista su 1h (filtro superiore)
    trend1h_ok = (ema20_1h > ema50_1h) if (trend1h_filter and ema20_1h > 0 and ema50_1h > 0) else True

    # 3. Prezzo vicino a EMA20 su 5min (pullback)
    dist_from_ema20 = abs(current_price - ema20_5m) / ema20_5m
    pullback_ok = dist_from_ema20 <= pullback_tolerance

    # 4. Ultima candela 5min chiusa sopra EMA20 (rimbalzo)
    bounce_ok = last_close_5m > ema20_5m

    # 5. Volume candela corrente >= media * coefficiente
    vol_ok = (vol_avg_20 > 0) and (vol_last >= vol_avg_20 * vol_multiplier)

    # 6. RSI in zona neutrale (né ipercomprato né ipervenduto)
    rsi_ok = (rsi_min <= rsi_14 <= rsi_max) if rsi_filter else True

    # 7. Corpo candela verde e almeno 30% del range (rimbalzo convinto, no doji)
    body_ok = candle_body > 0 and body_ratio >= 0.30

    # Stop contestuale
    stop_from_low = pullback_low_5m
    stop_from_atr = current_price - atr_5m if atr_5m > 0 else 0.0
    stop_price    = min(stop_from_low, stop_from_atr) if stop_from_atr > 0 else stop_from_low

    R = (current_price - stop_price) / current_price if stop_price > 0 else 0.0
    stop_ok = min_r <= R <= max_stop_pct

    signal = trend_ok and trend1h_ok and pullback_ok and bounce_ok and vol_ok and rsi_ok and body_ok and stop_ok

    if not trend1h_ok:
        reason = f"no trend 1h (EMA20 {ema20_1h:.4f} < EMA50 {ema50_1h:.4f})"
    elif not trend_ok:
        reason = f"no trend 15m (EMA20 {ema20_15m:.4f} < EMA50 {ema50_15m:.4f})"
    elif not pullback_ok:
        reason = f"no pullback (dist EMA20: {dist_from_ema20*100:.1f}% > {pullback_tolerance*100:.1f}%)"
    elif not bounce_ok:
        reason = f"no rimbalzo (close 5m {last_close_5m:.4f} < EMA20 {ema20_5m:.4f})"
    elif not vol_ok:
        ratio = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        reason = f"volume basso ({ratio:.1f}x media, richiesto {vol_multiplier}x)"
    elif not rsi_ok:
        reason = f"RSI fuori range ({rsi_14:.1f}, range {rsi_min:.0f}-{rsi_max:.0f})"
    elif not body_ok:
        reason = f"candela debole (corpo {body_ratio*100:.0f}% del range, min 30%)" if candle_body > 0 else "candela ribassista — no entrata"
    elif not stop_ok:
        if R > 0 and R < min_r:
            reason = f"R troppo piccolo ({R*100:.2f}% < {min_r*100:.1f}% min) — fee mangerebbero il profitto"
        elif R > max_stop_pct:
            reason = f"stop troppo largo ({R*100:.1f}% > {max_stop_pct*100:.1f}%)"
        else:
            reason = "stop non calcolabile"
    else:
        reason = (f"OK | EMA20/50 1h: {ema20_1h:.4f}/{ema50_1h:.4f} | "
                  f"EMA20/50 15m: {ema20_15m:.4f}/{ema50_15m:.4f} | "
                  f"dist EMA20: {dist_from_ema20*100:.2f}% | "
                  f"RSI: {rsi_14:.1f} | corpo: {body_ratio*100:.0f}% | vol: {vol_last/vol_avg_20:.1f}x | R: {R*100:.2f}%")

    return {
        "signal":      signal,
        "reason":      reason,
        "stop_price":  round(stop_price, 8),
        "R":           round(R, 6),
        "trend_ok":    trend_ok,
        "trend1h_ok":  trend1h_ok,
        "pullback_ok": pullback_ok,
        "bounce_ok":   bounce_ok,
        "vol_ok":      vol_ok,
        "rsi_ok":      rsi_ok,
        "body_ok":     body_ok,
        "stop_ok":     stop_ok,
        "rsi":         rsi_14,
    }

# ── rest of market data ───────────────────────────────────────────────────────

STABLES = {'USDT','USDC','BUSD','DAI','FDUSD','TUSD','USDP','GUSD','FRAX',
           'LUSD','SUSD','EUR','GBP','USD','USDD','USTC','PAX','CBBTC','WBTC'}

_coinbase_products: dict = {}
_products_last_update: float = 0

REVX_BASE_PUB = "https://revx.revolut.com"

async def fetch_revx_market_data() -> dict:
    """
    Scarica ticker e variazioni da Revolut X (endpoint pubblico).
    Restituisce dict sym -> {price_eur, change24h, volume24h}
    """
    result = {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Tickers pubblici - no auth (endpoint aperto)
            r = await client.get(f"{REVX_BASE_PUB}/api/1.0/market/tickers")
            if r.status_code != 200:
                print(f"[REVX TICKER] status {r.status_code}")
                return result
            data = r.json()
            tickers = data if isinstance(data, list) else data.get("data", [])
            for t in tickers:
                symbol = t.get("symbol", "")  # es. "BTC-EUR"
                if not symbol.endswith("-EUR"):
                    continue
                sym = symbol[:-4]  # "BTC"
                if not sym or sym in STABLES:
                    continue
                price = float(t.get("last_price") or t.get("close") or t.get("mid_price") or 0)
                change24h = float(t.get("price_change_24h_pct") or t.get("change_24h") or 0)
                volume24h = float(t.get("volume_24h") or t.get("volume") or 0)
                if price > 0:
                    result[sym] = {
                        "price_eur": price,
                        "change24h": change24h,
                        "volume24h_eur": volume24h,
                        "symbol_pair": symbol,
                    }
    except Exception as e:
        print(f"[REVX TICKER] error: {e}")
    return result

async def fetch_prices():
    global _products_last_update
    try:
        # Usa Advanced Trade API per i prodotti — più aggiornata di Exchange API
        # Prodotti pubblici, nessuna auth richiesta
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://api.coinbase.com/api/v3/brokerage/market/products",
                params={"product_type": "SPOT", "limit": 500}
            )
            all_products_adv = r.json().get("products", [])

        usd_syms = {}
        usdc_syms = {}
        for p in all_products_adv:
            if not isinstance(p, dict): continue
            if p.get("status", "") not in ("online", ""): continue
            if p.get("is_disabled", False): continue
            product_id = p.get("product_id", "")
            if not product_id or "-" not in product_id: continue
            parts = product_id.split("-")
            if len(parts) != 2: continue
            sym, quote = parts[0], parts[1]
            if not sym.isascii() or not sym.isalpha(): continue
            if sym in STABLES: continue
            if quote == "USD":
                usd_syms[product_id] = sym
            elif quote == "USDC":
                usdc_syms[sym] = product_id

        async with httpx.AsyncClient(timeout=15) as client:
            r2 = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            tickers = r2.json()

        binance_map = {}
        for t in tickers:
            pair = t.get("symbol","")
            if pair.endswith("USDT"):
                s = pair[:-4]
                if s in usd_syms.values():
                    binance_map[s] = t

        for product_id, sym in usd_syms.items():
            t = binance_map.get(sym)
            if t:
                try:
                    price = float(t["lastPrice"])
                    change24h = float(t["priceChangePercent"])
                    vol_usd = float(t["quoteVolume"])
                except:
                    continue
            else:
                continue
            if price <= 0: continue

            # Preferisci USDC se disponibile, altrimenti USD
            product_id_trading = usdc_syms.get(sym, product_id)
            _coinbase_products[sym] = {
                "price": price, "change24h": change24h,
                "volume24h": vol_usd, "logo_url": "",
                "product_id": product_id_trading
            }

            if sym not in market_data:
                market_data[sym] = {
                    "price": 0.0, "change1h": 0.0, "change24h": 0.0,
                    "volume24h": 0.0, "icon": sym[0]
                }

            # change1h: usa il close della candela 1h precedente da candle_data
            # candle_data viene aggiornato ogni 5 minuti con dati reali Binance
            cd = candle_data.get(sym)
            if cd and cd.get("close_1h_ago", 0) > 0:
                change1h = (price - cd["close_1h_ago"]) / cd["close_1h_ago"] * 100
            else:
                change1h = market_data[sym].get("change1h", 0.0)

            market_data[sym]["price"]     = price
            market_data[sym]["change1h"]  = change1h
            market_data[sym]["change24h"] = change24h
            market_data[sym]["volume24h"] = vol_usd

            for state in user_sessions.values():
                for pos in state["positions"]:
                    if pos["symbol"] == sym:
                        pos["currentPrice"] = price
                        if price > pos["highPrice"]:
                            pos["highPrice"] = price

        # Overlay con dati Revolut X in EUR se disponibili
        try:
            revx_data = await fetch_revx_market_data()
            for sym, rd in revx_data.items():
                if sym in market_data and rd["price_eur"] > 0:
                    market_data[sym]["price_eur"]    = rd["price_eur"]
                    market_data[sym]["change24h_eur"] = rd["change24h"]
                    market_data[sym]["symbol_revx"]  = rd["symbol_pair"]
                elif rd["price_eur"] > 0:
                    # Coin disponibile su Revolut X ma non su Coinbase
                    market_data[sym] = {
                        "price": 0.0, "price_eur": rd["price_eur"],
                        "change1h": 0.0, "change24h": rd["change24h"],
                        "change24h_eur": rd["change24h"],
                        "volume24h": rd["volume24h_eur"],
                        "icon": sym[0], "symbol_revx": rd["symbol_pair"]
                    }
            # Aggiorna prezzi posizioni aperte con EUR se use_revx
            for state in user_sessions.values():
                if not state.get("use_revx"):
                    continue
                for pos in state["positions"]:
                    sym = pos["symbol"]
                    rd = revx_data.get(sym)
                    if rd and rd["price_eur"] > 0:
                        pos["currentPrice"] = rd["price_eur"]
                        if rd["price_eur"] > pos["highPrice"]:
                            pos["highPrice"] = rd["price_eur"]
        except Exception as e:
            print(f"[REVX OVERLAY] error: {e}")

    except Exception as e:
        print(f"Fetch error: {e}")

# ── session ───────────────────────────────────────────────────────────────────

def make_session() -> dict:
    return {
        "running": False, "capital": 0.0, "currentCapital": 0.0,
        "positions": [], "pnlHistory": [], "sessionStart": None,
        "sessionDuration": 0, "config": {}, "cooldowns": {},
        "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "cb_key": "", "cb_secret": "",
        "consecutiveLosses": 0,
    }

def get_session(user_id: int) -> dict:
    if user_id not in user_sessions:
        user_sessions[user_id] = make_session()
    return user_sessions[user_id]

def add_log(state: dict, type_: str, label: str, desc: str):
    state["log"].insert(0, {
        "type": type_, "label": label, "desc": desc,
        "ts": int(time.time() * 1000)
    })
    if len(state["log"]) > 200:
        state["log"].pop()

def unrealized_pnl(state: dict) -> float:
    total = 0.0
    for p in state["positions"]:
        size = p.get("size_remaining", p["size"])
        gross = (p["currentPrice"] - p["entryPrice"]) / p["entryPrice"] * size
        exit_fee = size * p.get("fee_pct", 0.006)  # fee di uscita stimata
        total += gross - exit_fee
    return total

# ── trading ───────────────────────────────────────────────────────────────────

async def get_revx_eur_balance(key_id: str, private_key: str) -> float:
    """Legge il saldo EUR disponibile su Revolut X."""
    try:
        result = await revx_request("GET", "/api/1.0/balances", key_id=key_id, private_key=private_key)
        balances = result if isinstance(result, list) else result.get("balances", [])
        for b in balances:
            if b.get("currency") == "EUR":
                return float(b.get("available", 0) or 0)
    except Exception as e:
        print(f"[REVX BALANCE] error: {e}")
    return 0.0

async def get_revx_eur_balance(key_id: str, private_key: str) -> float:
    """Legge il saldo EUR disponibile su Revolut X."""
    try:
        result = await revx_request("GET", "/api/1.0/balances", key_id=key_id, private_key=private_key)
        balances = result if isinstance(result, list) else result.get("balances", [])
        for b in balances:
            if b.get("currency") == "EUR":
                return float(b.get("available", 0) or 0)
    except Exception as e:
        print(f"[REVX BALANCE] error: {e}")
    return 0.0

async def get_coinbase_usdc_balance(cb_key: str, cb_secret: str) -> float:
    """
    Legge il saldo USDC/USD disponibile su Coinbase Advanced Trade.
    Usa /portfolios/{uuid} che restituisce available_to_trade_fiat per ogni asset.
    """
    try:
        # Trova il portfolio DEFAULT
        port_res = await coinbase_request("GET", "/api/v3/brokerage/portfolios", cb_key=cb_key, cb_secret=cb_secret)
        portfolios = port_res.get("portfolios", [])
        default = next((p for p in portfolios if p.get("type") == "DEFAULT"), None)
        if not default and portfolios:
            default = portfolios[0]
        if not default:
            print("[BALANCE] nessun portfolio trovato")
            return 0.0

        uuid = default.get("uuid", "")
        detail = await coinbase_request("GET", f"/api/v3/brokerage/portfolios/{uuid}", cb_key=cb_key, cb_secret=cb_secret)
        spot_positions = detail.get("breakdown", {}).get("spot_positions", [])

        total = 0.0
        for pos in spot_positions:
            if pos.get("asset") in ("USDC", "USD") and pos.get("is_cash"):
                val = float(pos.get("available_to_trade_fiat", 0) or 0)
                total += val
                print(f"[BALANCE] {pos['asset']}: ${val:.2f} disponibile per trading")

        if total > 0:
            return total

        # Fallback: total_cash_equivalent_balance dal portfolio
        cash = detail.get("breakdown", {}).get("portfolio_balances", {}).get("total_cash_equivalent_balance", {})
        total_cash = float(cash.get("value", 0) or 0)
        if total_cash > 0:
            print(f"[BALANCE] cash_equivalent fallback: ${total_cash:.2f}")
            return total_cash

    except Exception as e:
        print(f"[BALANCE] portfolios error: {e}")

    return 0.0

async def enter_position(state: dict, sym_data: dict, tradable_capital: float):
    cfg      = state["config"]
    price    = sym_data["price"]
    sym      = sym_data["symbol"]
    is_real  = cfg.get("realMode", False)

    alloc_pct = cfg.get("allocPct", 0.20)
    COINBASE_FEE = 0.006  # 0.60% per lato
    # Size = quota del capitale tradabile netto per questo trade
    size = tradable_capital * alloc_pct
    if size < 1:
        return

    # Fee di entrata (sempre applicata, in reale la detrae Coinbase, in sim la contabilizziamo noi)
    entry_fee = size * COINBASE_FEE

    # Funzione per formattare prezzi con abbastanza decimali (gestisce coin micro come PEPE)
    def fmt_price(p: float) -> str:
        if p >= 1: return f"${p:.4f}"
        if p >= 0.0001: return f"${p:.6f}"
        return f"${p:.8f}"

    # Stop price: dalla funzione EMA signal (contestuale ATR/low)
    # Fallback: stop fisso da config
    stop_price = sym_data.get("stop_price", 0.0)
    if stop_price <= 0 or stop_price >= price:
        fallback_sl = cfg.get("stopLoss", 0.01)
        stop_price  = price * (1 - fallback_sl)

    R_pct = (price - stop_price) / price  # rischio in % per questa posizione

    # TP1 = entry + 1R, TP2 = entry + tp2R (default 2.5R)
    tp2_multiplier = cfg.get("tp2R", 2.5)
    tp1_price = price * (1 + R_pct)
    tp2_price = price * (1 + R_pct * tp2_multiplier)

    # Determina exchange da usare
    use_revx = state.get("use_revx", False)

    if is_real:
        if use_revx:
            # ── REVOLUT X ────────────────────────────────────────────────────
            revx_key_id  = state.get("revx_key_id", "")
            revx_priv    = state.get("revx_private_key", "")
            try:
                symbol_revx = f"{sym}-EUR"
                import uuid as _uuid
                order_body = {
                    "client_order_id": str(_uuid.uuid4()),
                    "symbol": symbol_revx,
                    "side": "BUY",
                    "order_configuration": {"market": {"quote_size": str(round(size, 2))}}
                }
                add_log(state, "info", "DEBUG", f"Ordine RevX {symbol_revx} size=€{size:.2f}")
                result = await revx_request("POST", "/api/1.0/orders", order_body, key_id=revx_key_id, private_key=revx_priv)
                print(f"[REVX ORDER RESULT] {sym}: {result}")
                # Revolut X risponde con {"data": {"venue_order_id": ..., "client_order_id": ...}}
                data = result.get("data") or result
                order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
                # Se non c'è order_id e c'è un errore esplicito, fallisce
                if not order_id:
                    err_msg = result.get("message") or result.get("error") or result.get("detail") or str(result)
                    add_log(state, "info", "ERRORE", f"Ordine RevX {sym} fallito: {err_msg}")
                    await send_telegram(f"ERRORE ORDINE RevX {sym}: {err_msg[:100]}")
                    return
                actual_price = float(data.get("average_price") or data.get("price") or price)
                qty_purchased = size / actual_price if actual_price > 0 else 0.0
                stop_price  = actual_price * (1 - R_pct)
                tp1_price   = actual_price * (1 + R_pct)
                tp2_price   = actual_price * (1 + R_pct * tp2_multiplier)
                add_log(state, "buy", "ACQUISTO REALE (RevX)",
                    f"{sym} @ {fmt_price(actual_price)} | Size: €{size:.0f} | Qty: {qty_purchased:.6f} | "
                    f"SL: {fmt_price(stop_price)} | TP1: {fmt_price(tp1_price)} | TP2: {fmt_price(tp2_price)} | R: {R_pct*100:.2f}%")
                await send_telegram(f"ACQUISTO REALE RevX\n{sym} @ €{actual_price:.4f}\nSize: €{size:.2f}")
            except Exception as e:
                add_log(state, "info", "ERRORE", f"RevX error: {e}")
                return
            # Aggiorna stato posizione
            state["currentCapital"] -= size
            pos = {
                "symbol": sym, "icon": sym_data["icon"],
                "entryPrice": actual_price, "currentPrice": actual_price, "highPrice": actual_price,
                "size": size, "size_remaining": size, "tp1_hit": False,
                "entryTime": datetime.utcnow().isoformat() + "Z",
                "stopPrice": stop_price, "tp1Price": tp1_price, "tp2Price": tp2_price,
                "R_pct": R_pct, "realMode": True, "fee_pct": 0.001,
                "qty_purchased": qty_purchased, "exchange": "revx", "symbol_pair": symbol_revx,
            }
            state["positions"].append(pos)
            return
        # ── COINBASE ─────────────────────────────────────────────────────────
        cb_key    = state.get("cb_key", "") or _ENV_CB_KEY
        cb_secret = state.get("cb_secret", "") or _ENV_CB_SECRET
        try:
            product_id = _coinbase_products.get(sym, {}).get("product_id", f"{sym}-USDC")
            body = {
                "client_order_id": f"ca-{sym}-{int(time.time())}",
                "product_id": product_id,
                "side": "BUY",
                "order_configuration": {"market_market_ioc": {"quote_size": str(round(size, 2))}}
            }
            add_log(state, "info", "DEBUG", f"Ordine {sym}: product_id={product_id} size=${size:.2f}")
            result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
            # Se fallisce con USDC prova USD e viceversa
            if result.get("success") != True:
                err_str = str(result).lower()
                if "not available" in err_str or "invalid_argument" in err_str:
                    alt_id = product_id.replace("-USDC", "-USD") if "-USDC" in product_id else product_id.replace("-USD", "-USDC")
                    if alt_id != product_id:
                        add_log(state, "info", "RETRY", f"{sym}: provo {alt_id}")
                        body["product_id"] = alt_id
                        result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
                        if result.get("success") == True:
                            product_id = alt_id
                            # Aggiorna il product_id in cache per i prossimi ordini
                            if sym in _coinbase_products:
                                _coinbase_products[sym]["product_id"] = alt_id
            if result.get("success") != True:
                err = result.get("error_response") or result
                err_msg = err.get("message") or err.get("error_details") or str(result)
                err_str = str(result).lower()
                add_log(state, "info", "ERRORE", f"Ordine {sym} fallito [{product_id}]: {err_msg}")
                # Cooldown automatico per errori che indicano coin non tradabile temporaneamente
                if any(x in err_str for x in ["not available", "cancel only", "permission_denied", "orderbook", "suspended"]):
                    state["cooldowns"][sym] = (datetime.now().timestamp() + 3600) * 1000
                    add_log(state, "info", "ESCLUSA", f"{sym} esclusa per 1h — {err_msg[:60]}")
                # Saldo insufficiente: ferma la sessione
                if any(x in err_str for x in ["insufficient", "insufficient_fund", "not enough"]):
                    state["running"] = False
                    add_log(state, "info", "STOP AUTO", f"Saldo insufficiente — sessione fermata")
                    await send_telegram(f"STOP AUTO: saldo insufficiente")
                return
            filled       = result.get("success_response", {})
            actual_price = float(filled.get("average_filled_price", price)) or price
            # Quantità effettivamente acquistata — useremo questo per vendere solo ciò che abbiamo comprato
            qty_purchased = size / actual_price if actual_price > 0 else 0.0
            # Ricalcola stop e TP sull'actual price
            stop_price  = actual_price * (1 - R_pct)
            tp1_price   = actual_price * (1 + R_pct)
            tp2_price   = actual_price * (1 + R_pct * tp2_multiplier)
            add_log(state, "buy", "ACQUISTO REALE",
                f"{sym} @ {fmt_price(actual_price)} | Size: ${size:.0f} | Qty: {qty_purchased:.6f} | Fee: ${entry_fee:.2f} | "
                f"SL: {fmt_price(stop_price)} | TP1: {fmt_price(tp1_price)} | TP2: {fmt_price(tp2_price)} | R: {R_pct*100:.2f}%")
            await send_telegram(
                "ACQUISTO REALE\n" + sym + " @ $" + f"{actual_price:.4f}" +
                "\nSize: $" + f"{size:.2f}" +
                "\nSL: $" + f"{stop_price:.4f}" +
                "\nTP1: $" + f"{tp1_price:.4f}" + " | TP2: $" + f"{tp2_price:.4f}"
            )
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Coinbase error: {sanitize_error(e, cb_key, cb_secret)}")
            return
    else:
        actual_price = price
        add_log(state, "buy", "ACQUISTO SIM",
            f"{sym} @ {fmt_price(actual_price)} | Size: ${size:.0f} | Fee: ${entry_fee:.2f} | "
            f"SL: {fmt_price(stop_price)} | TP1: {fmt_price(tp1_price)} | TP2: {fmt_price(tp2_price)} | R: {R_pct*100:.2f}%")

    # In sim sottraiamo anche la fee di entrata dal capitale disponibile
    state["currentCapital"] -= size + (entry_fee if not is_real else 0)
    pos = {
        "symbol":        sym,
        "icon":          sym_data["icon"],
        "entryPrice":    actual_price,
        "currentPrice":  actual_price,
        "highPrice":     actual_price,
        "size":          size,
        "size_remaining": size,
        "tp1_hit":       False,
        "entryTime":     datetime.utcnow().isoformat() + "Z",
        "stopPrice":     stop_price,
        "tp1Price":      tp1_price,
        "tp2Price":      tp2_price,
        "R_pct":         R_pct,
        "realMode":      is_real,
        "fee_pct":       COINBASE_FEE,
        "qty_purchased": qty_purchased if is_real else 0.0,  # quantità crypto acquistata (solo reale)
        "product_id":    _coinbase_products.get(sym, {}).get("product_id", f"{sym}-USDC"),
    }
    state["positions"].append(pos)

async def exit_position(state: dict, pos: dict, reason: str, partial: bool = False, user_id: int = None):
    """
    Se partial=True: chiude il 50% della posizione (TP1).
    Se partial=False: chiude tutto.
    """
    cur  = pos["currentPrice"]
    sym  = pos["symbol"]
    dur  = (datetime.utcnow() - datetime.fromisoformat(pos["entryTime"].replace("Z", ""))).total_seconds() / 60

    # Dimensione effettiva da chiudere
    close_size = pos["size_remaining"] * 0.5 if partial else pos["size_remaining"]

    if pos.get("realMode", False):
        # ── REVOLUT X EXIT ────────────────────────────────────────────────────
        if pos.get("exchange") == "revx":
            revx_key_id = state.get("revx_key_id", "")
            revx_priv   = state.get("revx_private_key", "")
            qty_purchased = pos.get("qty_purchased", 0.0)
            if qty_purchased <= 0:
                add_log(state, "info", "ERRORE", f"qty_purchased non disponibile per {sym} RevX — vendita annullata")
                return
            try:
                import uuid as _uuid
                qty_to_sell = round(qty_purchased * 0.5, 8) if partial else round(qty_purchased, 8)
                order_body = {
                    "client_order_id": str(_uuid.uuid4()),
                    "symbol": pos.get("symbol_pair", f"{sym}-EUR"),
                    "side": "SELL",
                    "order_configuration": {"market": {"base_size": str(qty_to_sell)}}
                }
                result = await revx_request("POST", "/api/1.0/orders", order_body, key_id=revx_key_id, private_key=revx_priv)
                print(f"[REVX SELL RESULT] {sym}: {result}")
                data = result.get("data") or result
                order_id = data.get("venue_order_id") or data.get("order_id") or data.get("id", "")
                if not order_id:
                    err_msg = result.get("message") or result.get("error") or result.get("detail") or str(result)
                    add_log(state, "info", "ERRORE", f"Vendita RevX {sym} fallita: {err_msg}")
                    await send_telegram(f"ERRORE VENDITA RevX {sym}: {err_msg[:100]}")
                    return
                filled_price = float(data.get("average_price") or data.get("price") or cur)
                if filled_price > 0:
                    cur = filled_price
                add_log(state, "info", "VENDUTO RevX", f"{sym} qty: {qty_to_sell:.6f} @ €{cur:.4f}")
                if partial:
                    pos["qty_purchased"] = qty_purchased - qty_to_sell
            except Exception as e:
                add_log(state, "info", "ERRORE", f"RevX exit error: {e}")
                return
        # ── COINBASE EXIT ─────────────────────────────────────────────────────
        else:
            cb_key    = state.get("cb_key", "") or _ENV_CB_KEY
            cb_secret = state.get("cb_secret", "") or _ENV_CB_SECRET
            try:
                qty_purchased = pos.get("qty_purchased", 0.0)
                if qty_purchased <= 0:
                    add_log(state, "info", "ERRORE", f"qty_purchased non disponibile per {sym} — vendita annullata")
                    return
                qty_to_sell = round(qty_purchased * 0.5, 8) if partial else round(qty_purchased, 8)
                product_id  = pos.get("product_id", f"{sym}-USDC")
                body = {
                    "client_order_id": f"ca-exit-{sym}-{int(time.time())}",
                    "product_id": product_id, "side": "SELL",
                    "order_configuration": {"market_market_ioc": {"base_size": str(qty_to_sell)}}
                }
                result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
                if result.get("success") != True:
                    err = result.get("error_response") or result
                    err_msg = err.get("message") or err.get("error_details") or str(result)
                    add_log(state, "info", "ERRORE", f"Vendita {sym} fallita [{product_id}]: {err_msg}")
                    await send_telegram(f"ERRORE VENDITA {sym}: {err_msg[:100]}")
                    return
                filled = result.get("success_response", {})
                cur = float(filled.get("average_filled_price", cur)) or cur
                add_log(state, "info", "VENDUTO", f"{sym} qty: {qty_to_sell:.6f} @ {_fp(cur)}")
                if partial:
                    pos["qty_purchased"] = qty_purchased - qty_to_sell
            except Exception as e:
                add_log(state, "info", "ERRORE", f"Coinbase exit error: {sanitize_error(e, cb_key, cb_secret)}")
                return

    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * close_size
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    # Fee di uscita: 0.60% sul valore liquidato (applicata sempre per riflettere realtà)
    fee_pct = pos.get("fee_pct", 0.006)
    exit_fee = close_size * fee_pct
    pnl -= exit_fee  # riduce il PnL netto

    if partial:
        # TP1: restituisce metà capitale, aggiorna size_remaining
        # Il nuovo stop viene gestito dal trailing in scan_and_trade
        state["currentCapital"] += close_size + pnl
        pos["size_remaining"] -= close_size
        pos["stopPrice"]       = pos["entryPrice"]  # breakeven minimo
        pos["tp1_hit"]         = True
        mode = "REALE" if pos.get("realMode") else "SIM"
        add_log(state, "sell", f"TP1 {mode}",
            f"{sym} 50% @ ${cur:.4f} | +{pnl:.2f}$ ({pct:+.2f}%) | trailing stop attivo")
        if pos.get("realMode"):
            await send_telegram(
                "TP1 REALE\n" + sym + " 50% @ $" + f"{cur:.4f}" +
                "\nP&L parziale: +" + f"{pnl:.2f}" + "$\nStop spostato a breakeven"
            )
        return  # posizione resta aperta per TP2

    # Chiusura totale
    # Usa size originale per il PnL finale (già parte è stata realizzata a TP1)
    state["currentCapital"] += pos["size_remaining"] + pnl
    state["tradeCount"] += 1
    if pnl > 0:
        state["wins"] += 1
        state["consecutiveLosses"] = 0
    else:
        state["consecutiveLosses"] = state.get("consecutiveLosses", 0) + 1

    cfg = state["config"]
    state["cooldowns"][sym] = (datetime.now().timestamp() + cfg.get("cooldown", 1) * 3600) * 1000
    trade_record = {
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": pnl, "pct": pct, "time": datetime.utcnow().isoformat() + "Z",
        "entryTime": pos["entryTime"], "durationMin": round(dur, 1),
        "size": pos["size"], "realMode": pos.get("realMode", False),
        "tp1_hit": pos.get("tp1_hit", False),
    }
    state["trades"].append(trade_record)
    # Salva su DB se disponibile
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
                    float(pos["size"]), float(pnl), float(pct),
                    reason, bool(pos.get("tp1_hit", False)), float(round(dur, 1)),
                    pos["entryTime"], datetime.utcnow().isoformat() + "Z",
                    "real" if pos.get("realMode") else "sim"
                )
        except Exception as e:
            print(f"DB trade save error: {e}")
    def _fp(p):
        if p >= 1: return f"${p:.4f}"
        if p >= 0.0001: return f"${p:.6f}"
        return f"${p:.8f}"

    state["positions"] = [p for p in state["positions"] if p is not pos]
    mode = "REALE" if pos.get("realMode") else "SIM"
    add_log(state, "sell", f"{reason} {mode}",
        f"{sym} @ {_fp(cur)} | {pnl:+.2f}$ ({pct:+.2f}%) | fee: ${exit_fee:.2f} | {dur:.0f} min")
    if pos.get("realMode"):
        esito = "PROFITTO" if pnl >= 0 else "PERDITA"
        msg = ("VENDITA REALE - " + esito + "\n" + sym + " @ $" + f"{cur:.4f}" +
               "\nP&L: " + f"{pnl:+.2f}" + "$")
        await send_telegram(msg)

    # Controllo stop automatico per perdite consecutive
    max_losses = cfg.get("maxConsecutiveLosses", 0)
    if max_losses > 0 and state.get("consecutiveLosses", 0) >= max_losses:
        state["running"] = False
        add_log(state, "info", "STOP AUTO",
            f"{max_losses} perdite consecutive — sessione fermata automaticamente")
        await send_telegram(f"STOP AUTO: {max_losses} perdite consecutive")

# ── main loop ─────────────────────────────────────────────────────────────────

async def scan_and_trade(state: dict, user_id: int = None):
    if not state["running"]:
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

    # Gestione posizioni aperte: TP1, TP2, trailing stop, stop loss
    for pos in list(state["positions"]):
        cur   = pos["currentPrice"]
        entry = pos["entryPrice"]
        trailing_stop   = cfg.get("trailingStop", True)
        trailing_pct    = cfg.get("trailingPct", 0.5)

        if cur > pos.get("highPrice", cur):
            pos["highPrice"] = cur

        # TP1: prima volta che tocca +1R
        if not pos.get("tp1_hit", False) and cur >= pos["tp1Price"]:
            await exit_position(state, pos, "TP1", partial=True, user_id=user_id)
            continue

        # Dopo TP1: trailing stop (segue il massimo * trailingPct invece di breakeven fisso)
        if pos.get("tp1_hit", False):
            if trailing_stop and pos.get("highPrice", 0) > 0:
                trail_price = pos["highPrice"] * (1 - trailing_pct * pos["R_pct"])
                # Lo stop non può scendere sotto il breakeven
                new_stop = max(trail_price, pos["entryPrice"])
                if new_stop > pos["stopPrice"]:
                    pos["stopPrice"] = new_stop

            # TP2
            if cur >= pos["tp2Price"]:
                await exit_position(state, pos, "TP2", user_id=user_id)
                continue

        # Stop loss (include trailing/breakeven dopo TP1)
        if cur <= pos["stopPrice"]:
            reason = "STOP TRAILING" if pos.get("tp1_hit") else "STOP LOSS"
            await exit_position(state, pos, reason, user_id=user_id)

    alloc_pct   = cfg.get("allocPct", 0.20)
    capital_pct = cfg.get("capitalPct", 1.0)
    COINBASE_FEE = 0.006  # 0.60% per lato (taker fee)

    # Calcola il capitale tradabile dinamicamente
    if cfg.get("realMode", False):
        use_revx = state.get("use_revx", False)
        if use_revx:
            revx_key_id = state.get("revx_key_id", "")
            revx_priv   = state.get("revx_private_key", "")
            try:
                eur_balance = await get_revx_eur_balance(revx_key_id, revx_priv)
                tradable_capital = eur_balance * capital_pct
            except Exception as e:
                add_log(state, "info", "ERRORE", f"Fetch saldo RevX fallito: {e}")
                _update_pnl(state)
                return
        else:
            cb_key    = state.get("cb_key", "") or _ENV_CB_KEY
            cb_secret = state.get("cb_secret", "") or _ENV_CB_SECRET
            try:
                usdc_balance = await get_coinbase_usdc_balance(cb_key, cb_secret)
                tradable_capital = usdc_balance * capital_pct
            except Exception as e:
                add_log(state, "info", "ERRORE", f"Fetch saldo fallito: {sanitize_error(e, cb_key, cb_secret)}")
                _update_pnl(state)
                return
    else:
        # Sim: usa currentCapital (già aggiornato dopo ogni trade)
        tradable_capital = state["currentCapital"] * capital_pct

    # Soglia minima: ferma solo se non ci sono posizioni aperte e il saldo USDC è davvero esaurito
    # Se ci sono posizioni aperte il capitale è "bloccato" in crypto — non è perso
    min_tradable = max(1.0, state["capital"] * alloc_pct * capital_pct * 0.1)
    open_positions = state["positions"]
    if tradable_capital < min_tradable and cfg.get("realMode", False):
        if open_positions:
            # Capitale in posizioni aperte — aspetta che si chiudano, non stoppare
            _update_pnl(state)
            return
        else:
            # Nessuna posizione aperta e saldo USDC esaurito — stop legittimo
            state["running"] = False
            add_log(state, "info", "STOP AUTO",
                f"Saldo insufficiente ({'€' if state.get('use_revx') else '$'}{tradable_capital:.2f}) — sessione fermata")
            await send_telegram(f"STOP AUTO: saldo insufficiente (€{tradable_capital:.2f})" if state.get("use_revx") else f"STOP AUTO: saldo USDC ${tradable_capital:.2f} insufficiente")
            return
    elif tradable_capital < 1.0 and not cfg.get("realMode", False):
        # Sim con capitale esaurito
        add_log(state, "info", "INFO", f"Capitale sim esaurito (${tradable_capital:.2f}) — attesa recupero da posizioni aperte")
        _update_pnl(state)
        return

    # Numero massimo di posizioni aperte contemporaneamente
    max_pos   = max(1, int(round(1 / alloc_pct)))
    open_syms = {p["symbol"] for p in state["positions"]}
    slots     = max_pos - len(state["positions"])

    # Sottrai le commissioni round-trip attese per tutte le posizioni apribili
    # fee_totale = size_per_trade * 1.2% * slot_disponibili
    size_per_trade = tradable_capital * alloc_pct
    fee_reserve = size_per_trade * COINBASE_FEE * 2 * slots  # entrata + uscita per ogni slot
    tradable_capital_net = tradable_capital - fee_reserve

    # Non aprire nuove posizioni se maxTrades raggiunto
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        _update_pnl(state)
        return

    if slots <= 0 or tradable_capital < state["capital"] * alloc_pct * capital_pct * 0.5:
        _update_pnl(state)
        return

    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]

    # Filtro BTC: deve essere sopra EMA20 su 1h con tolleranza 0.1%
    # Evita falsi negativi quando BTC è praticamente sulla EMA (zona di contatto)
    btc_cd = candle_data.get("BTC", {})
    btc_ema20_1h = btc_cd.get("ema20_1h", 0)
    btc_ema50_1h = btc_cd.get("ema50_1h", 0)
    btc_price    = market_data.get("BTC", {}).get("price", 0)
    btc_filter   = cfg.get("btcEmaFilter", True)
    if btc_filter and btc_ema20_1h > 0 and btc_price > 0:
        tolerance = btc_ema20_1h * 0.001  # 0.1% sotto EMA20 è ancora accettabile
        if btc_price < btc_ema20_1h - tolerance:
            add_log(state, "info", "PAUSA",
                f"BTC sotto EMA20 1h (${btc_price:.0f} < ${btc_ema20_1h:.0f}) — agente in attesa")
            _update_pnl(state)
            return

    min_vol       = cfg.get("minVolume", 0)
    ema_filter    = cfg.get("emaFilter", True)
    pullback_tol  = cfg.get("pullbackTolerance", 0.015)
    vol_mult      = cfg.get("volMultiplier", 1.2)
    max_stop_pct  = cfg.get("maxStopPct", 0.025)
    trend1h_filter = cfg.get("trend1hFilter", True)
    rsi_filter    = cfg.get("rsiFilter", True)
    rsi_min       = cfg.get("rsiMin", 35.0)
    rsi_max       = cfg.get("rsiMax", 70.0)
    min_r         = cfg.get("minR", 0.01)

    # Se Revolut X: usa tutte le coin con candele disponibili (non filtriamo per _coinbase_products)
    # Se Coinbase: filtra solo le coin con prodotto disponibile
    use_revx_filter = state.get("use_revx", False)
    universe = [
            {**d, "symbol": sym}
            for sym, d in market_data.items()
            if d["price"] > 0
            and d.get("volume24h", 0) >= min_vol
            and sym not in open_syms
            and (use_revx_filter or sym in _coinbase_products)
            and sym in candle_data
            and (state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
        ]
    universe_sorted = sorted(universe, key=lambda d: d.get("volume24h", 0), reverse=True)

    candidates  = []
    ema_skipped = 0
    block_count = {"trend1h": 0, "trend": 0, "pullback": 0, "bounce": 0, "volume": 0, "rsi": 0, "body": 0, "stop": 0}

    for d in universe_sorted:
        sym = d["symbol"]
        if ema_filter:
            signal = get_ema_signal(sym, d["price"], pullback_tol, vol_mult, max_stop_pct,
                                    trend1h_filter, rsi_filter, rsi_min, rsi_max, min_r)
            if not signal["signal"]:
                ema_skipped += 1
                # Conta quale filtro ha bloccato
                if not signal.get("trend1h_ok", True): block_count["trend1h"] += 1
                elif not signal["trend_ok"]:            block_count["trend"] += 1
                elif not signal["pullback_ok"]:         block_count["pullback"] += 1
                elif not signal["bounce_ok"]:           block_count["bounce"] += 1
                elif not signal["vol_ok"]:              block_count["volume"] += 1
                elif not signal.get("rsi_ok", True):   block_count["rsi"] += 1
                elif not signal.get("body_ok", True):  block_count["body"] += 1
                elif not signal["stop_ok"]:             block_count["stop"] += 1
                continue
            d["ema_reason"]  = signal["reason"]
            d["stop_price"]  = signal["stop_price"]
            d["R_pct"]       = signal["R"]
        candidates.append(d)
        if len(candidates) >= slots:
            break

    # Trova il filtro che blocca di più
    top_blocker = max(block_count, key=block_count.get) if ema_skipped > 0 else "-"
    top_blocker_n = block_count.get(top_blocker, 0)

    top3 = [(d["symbol"], round(d.get("volume24h", 0) / 1e6, 0)) for d in universe_sorted[:3]]
    add_log(state, "info", "SCAN",
        f"Universe: {len(universe_sorted)} | Candidati: {len(candidates)} | "
        f"Saltati: {ema_skipped} | Blocco: {top_blocker}({top_blocker_n}) | "
        f"RSI range: {rsi_min:.0f}-{rsi_max:.0f} | Candele: {len(candle_data)}"
    )

    for d in candidates:
        add_log(state, "info", "SEGNALE", f"{d['symbol']} | {d.get('ema_reason', 'EMA off')}")
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

async def poll_telegram():
    global _tg_last_update
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates",
                params={"offset": _tg_last_update + 1, "timeout": 0}
            )
            data = r.json()
        for update in data.get("result", []):
            _tg_last_update = update["update_id"]
            msg = update.get("message", {})
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = msg.get("text", "").strip()
            if chat_id != str(TELEGRAM_CHAT_ID):
                continue
            tg_state = None
            for s in user_sessions.values():
                if s["running"]:
                    tg_state = s
                    break
            if tg_state is None and user_sessions:
                tg_state = next(iter(user_sessions.values()))

            if text.upper().startswith("/CLOSE") and tg_state:
                parts = text.split()
                if len(parts) >= 2:
                    sym = parts[1].upper()
                    pos = next((p for p in tg_state["positions"] if p["symbol"] == sym), None)
                    if pos:
                        await exit_position(tg_state, pos, "TELEGRAM")  # no user_id in telegram context
                        await send_telegram("Posizione " + sym + " chiusa via Telegram")
                    else:
                        await send_telegram("Nessuna posizione aperta su " + sym)
            elif text.upper() == "/STATUS":
                lines = []
                for uid, s in user_sessions.items():
                    if s["running"]:
                        pos_list = ", ".join([p["symbol"] for p in s["positions"]]) or "nessuna"
                        pnl = unrealized_pnl(s)
                        lines.append(f"Sessione {uid}: {pos_list} | P&L: ${pnl:.2f}")
                await send_telegram("\n".join(lines) if lines else "Nessuna sessione attiva")
            elif text.upper() == "/STOP" and tg_state:
                tg_state["running"] = False
                await send_telegram("Agente fermato via Telegram")
    except Exception as e:
        print(f"Telegram poll error: {e}")

# ── background loop ───────────────────────────────────────────────────────────

async def background_loop():
    consecutive_errors = 0
    last_persist = 0.0
    while True:
        try:
            await fetch_prices()

            if time.time() - _candles_last_update >= CANDLE_UPDATE_INTERVAL:
                await fetch_all_candles()

            sessions_snapshot = list(user_sessions.items())
            for uid, state in sessions_snapshot:
                if state["running"]:
                    await scan_and_trade(state, user_id=uid)

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
    sessions_snapshot = list(user_sessions.items())
    for uid, state in sessions_snapshot:
        try:
            state_to_save = {k: v for k, v in state.items() if k != "log"}
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
    """Loop separato per Telegram — non blocca il trading se Telegram è lento."""
    while True:
        try:
            await poll_telegram()
        except Exception as e:
            print(f"Telegram loop error: {e}")
        await asyncio.sleep(10)

# ── startup ───────────────────────────────────────────────────────────────────

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
                        cb_key TEXT DEFAULT '',
                        cb_secret TEXT DEFAULT '',
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
                    )
                """)
            print("Database connesso e schema creato")

            # Ripristina sessioni attive dopo riavvio
            await restore_sessions_from_db(db_pool)

        except Exception as e:
            print(f"Database error: {e}")
    asyncio.create_task(background_loop())
    asyncio.create_task(telegram_loop())

async def restore_sessions_from_db(pool):
    """Ripristina sessioni attive salvate nel DB dopo un riavvio."""
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT user_id, state_json FROM active_sessions")
        for row in rows:
            uid = row["user_id"]
            try:
                state = json.loads(row["state_json"])
                # Ripristina solo se era in running e la sessione non è scaduta
                if not state.get("running"):
                    continue
                session_start = state.get("sessionStart", 0)
                session_dur   = state.get("sessionDuration", 0)
                if session_dur > 0:
                    elapsed = (datetime.now().timestamp() - session_start) * 1000
                    if elapsed >= session_dur:
                        continue  # sessione scaduta durante il downtime
                user_sessions[uid] = state
                print(f"Sessione ripristinata per user {uid} con {len(state.get('positions',[]))} posizioni")
            except Exception as e:
                print(f"Errore ripristino sessione user {uid}: {e}")
    except Exception as e:
        print(f"Errore restore sessioni: {e}")

# ── RATE LIMITING ─────────────────────────────────────────────────────────────
from collections import defaultdict
_login_attempts: dict = defaultdict(list)  # ip -> [timestamps]

def check_rate_limit(ip: str, max_attempts: int = 10, window: int = 300):
    """Max 10 tentativi per 5 minuti per IP."""
    now = time.time()
    attempts = [t for t in _login_attempts[ip] if now - t < window]
    _login_attempts[ip] = attempts
    if len(attempts) >= max_attempts:
        raise HTTPException(status_code=429, detail="Troppi tentativi — riprova tra qualche minuto")
    _login_attempts[ip].append(now)

# ── AUTH ENDPOINTS ─────────────────────────────────────────────────────────────

@app.post("/auth/register")
async def register(req: RegisterRequest, request: Request):
    check_rate_limit(request.client.host)
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username troppo corto")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password troppo corta (min 6 caratteri)")
    pw_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO users (username, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id",
                req.username.lower(), pw_hash, req.username
            )
        token = create_token(row["id"])
        return {"token": token, "username": req.username, "has_api_keys": False}
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=400, detail="Username già in uso")

@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    check_rate_limit(request.client.host)
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash, cb_key FROM users WHERE username = $1",
            req.username.lower()
        )
    if not row:
        raise HTTPException(status_code=401, detail="Username o password errati")
    if not bcrypt.checkpw(req.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Username o password errati")
    token = create_token(row["id"])
    has_keys = bool(row["cb_key"])
    # Usa display_name se disponibile
    async with db_pool.acquire() as conn2:
        urow = await conn2.fetchrow("SELECT display_name FROM users WHERE id = $1", row["id"])
    dname = (urow["display_name"] or req.username) if urow else req.username
    return {"token": token, "username": dname, "has_api_keys": has_keys}

@app.post("/auth/save_keys")
async def save_keys(req: ApiKeyRequest, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET cb_key = $1, cb_secret = $2 WHERE id = $3",
            encrypt_key(req.cb_key), encrypt_key(req.cb_secret), user_id
        )
    return {"ok": True}

# ── WATCHLIST ─────────────────────────────────────────────────────────────────

@app.get("/watchlist")
async def get_watchlist(user_id: int = Depends(get_current_user)):
    if not db_pool:
        return {"symbols": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT symbol FROM watchlist WHERE user_id = $1", user_id)
    return {"symbols": [r["symbol"] for r in rows]}

@app.post("/watchlist/{symbol}")
async def add_watchlist(symbol: str, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO watchlist (user_id, symbol) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                user_id, symbol.upper()
            )
        except Exception:
            pass
    return {"ok": True}

@app.delete("/watchlist/{symbol}")
async def remove_watchlist(symbol: str, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM watchlist WHERE user_id = $1 AND symbol = $2",
            user_id, symbol.upper()
        )
    return {"ok": True}

# ── AVATAR ─────────────────────────────────────────────────────────────────────

class AvatarRequest(BaseModel):
    avatar_b64: str

@app.post("/auth/avatar")
async def save_avatar(req: AvatarRequest, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    # Limita a 500KB
    if len(req.avatar_b64) > 700000:
        raise HTTPException(status_code=400, detail="Immagine troppo grande (max 500KB)")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET avatar_b64 = $1 WHERE id = $2",
            req.avatar_b64, user_id
        )
    return {"ok": True}

@app.get("/auth/me")
async def get_me(user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, display_name, cb_key, avatar_b64, sim_mode, revx_key_id FROM users WHERE id = $1", user_id
        )
    has_keys = bool(row["cb_key"])
    sim = row["sim_mode"] if row["sim_mode"] is not None else True
    # Se non ha API keys, forza sempre simulazione
    if not has_keys:
        sim = True
    dname = row["display_name"] or row["username"]
    return {
        "username": dname,
        "has_api_keys": has_keys,
        "avatar_b64": row["avatar_b64"] or "",
        "sim_mode": sim,
        "has_revx_keys": bool(row.get("revx_key_id") or ""),
    }

class SimModeRequest(BaseModel):
    sim_mode: bool

@app.post("/auth/sim_mode")
async def set_sim_mode(req: SimModeRequest, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        # Verifica che l'utente abbia API keys prima di permettere reale
        row = await conn.fetchrow("SELECT cb_key FROM users WHERE id = $1", user_id)
        if not row["cb_key"] and not req.sim_mode:
            raise HTTPException(status_code=400, detail="API keys richieste per modalità reale")
        await conn.execute(
            "UPDATE users SET sim_mode = $1 WHERE id = $2",
            req.sim_mode, user_id
        )
    return {"ok": True, "sim_mode": req.sim_mode}

# ── TRADES HISTORY ─────────────────────────────────────────────────────────────

@app.get("/trades_history")
async def get_trades_history(user_id: int = Depends(get_current_user)):
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
async def get_status(user_id: int = Depends(get_current_user)):
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
        "log": state["log"][:40],
    }

@app.get("/market")
def get_market():
    items = []
    # Usa i parametri della prima sessione attiva, altrimenti default
    active_cfg = {}
    for s in user_sessions.values():
        if s.get("running"):
            active_cfg = s.get("config", {})
            break

    pullback_tol   = active_cfg.get("pullbackTolerance", 0.015)
    vol_mult       = active_cfg.get("volMultiplier", 1.2)
    max_stop_pct   = active_cfg.get("maxStopPct", 0.025)
    trend1h_filter = active_cfg.get("trend1hFilter", True)
    rsi_filter     = active_cfg.get("rsiFilter", True)
    rsi_min        = active_cfg.get("rsiMin", 35.0)
    rsi_max        = active_cfg.get("rsiMax", 70.0)
    min_r          = active_cfg.get("minR", 0.01)

    for s, d in market_data.items():
        if d["price"] <= 0:
            continue
        if s not in candle_data:
            continue
        item = {"symbol": s, **d}
        sig = get_ema_signal(s, d["price"], pullback_tol, vol_mult, max_stop_pct,
                             trend1h_filter, rsi_filter, rsi_min, rsi_max, min_r)
        item["ema"] = {
            "trend":      sig["trend_ok"],
            "trend1h_ok": sig["trend1h_ok"],
            "pullback":   sig["pullback_ok"],
            "volume":     sig["vol_ok"],
            "rsi_ok":     sig["rsi_ok"],
            "stop":       sig["stop_ok"],
            "signal":     sig["signal"],
            "rsi":        sig.get("rsi", 50),
            "reason":     sig["reason"],
        }
        items.append(item)
    result = sorted(items, key=lambda x: x["change24h"], reverse=True)
    return {"market": result}

@app.get("/trades")
async def get_trades(user_id: int = Depends(get_current_user)):
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

@app.post("/start")
async def start_agent(body: dict, user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    if state["running"]:
        return {"error": "Already running"}
    cfg     = body.get("config", {})
    capital = float(cfg.get("capital", 1000))
    if capital <= 0 or capital > 1_000_000:
        return {"error": "Capitale non valido (min $1, max $1,000,000)"}
    if float(cfg.get("allocPct", 0.20)) <= 0 or float(cfg.get("allocPct", 0.20)) > 1:
        return {"error": "Allocazione non valida (0-100%)"}

    cb_key, cb_secret, real_mode = "", "", False
    revx_key_id, revx_private_key, use_revx = "", "", False
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT cb_key, cb_secret, sim_mode, revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
                if row:
                    cb_key    = decrypt_key(row["cb_key"] or "")
                    cb_secret = decrypt_key(row["cb_secret"] or "")
                    revx_key_id     = decrypt_key(row["revx_key_id"] or "")
                    revx_private_key = decrypt_key(row["revx_private_key"] or "")
                    sim = row["sim_mode"] if row["sim_mode"] is not None else True
                    # Preferisci Revolut X se configurato
                    use_revx = bool(revx_key_id) and not sim
                    real_mode = (bool(cb_key) or use_revx) and not sim
        except Exception as e:
            print(f"DB key fetch error: {e}")

    state.update({
        "running": True,
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
            "pullbackTolerance":   float(cfg.get("pullbackTolerance", 0.015)),
            "volMultiplier":       float(cfg.get("volMultiplier", 1.2)),
            "maxStopPct":          float(cfg.get("maxStopPct", 0.025)),
            "maxTrades":           int(cfg.get("maxTrades", 0)),
            "maxConsecutiveLosses": int(cfg.get("maxConsecutiveLosses", 3)),
            "trend1hFilter":       bool(cfg.get("trend1hFilter", True)),
            "btcEmaFilter":        bool(cfg.get("btcEmaFilter", True)),
            "rsiFilter":           bool(cfg.get("rsiFilter", True)),
            "rsiMin":              float(cfg.get("rsiMin", 35.0)),
            "rsiMax":              float(cfg.get("rsiMax", 70.0)),
            "minR":                float(cfg.get("minR", 0.01)),
            "tp2R":                float(cfg.get("tp2R", 2.5)),
            "trailingStop":        bool(cfg.get("trailingStop", True)),
            "trailingPct":         float(cfg.get("trailingPct", 0.5)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "cb_key": cb_key, "cb_secret": cb_secret,
        "revx_key_id": revx_key_id, "revx_private_key": revx_private_key,
        "use_revx": use_revx,
        "consecutiveLosses": 0,
    })
    alloc  = float(cfg.get("allocPct", 0.20)) * 100
    capp   = float(cfg.get("capitalPct", 1.0)) * 100
    vol    = float(cfg.get("minVolume", 0)) / 1_000_000
    mode   = "REALE" if real_mode else "SIMULAZIONE"
    ema_s  = "ON" if cfg.get("emaFilter", True) else "OFF"
    ptol   = float(cfg.get("pullbackTolerance", 0.015)) * 100
    mt     = int(cfg.get("maxTrades", 0))
    mcl    = int(cfg.get("maxConsecutiveLosses", 3))
    tp2r   = float(cfg.get("tp2R", 2.5))
    rsi_s  = f"{cfg.get('rsiMin',40):.0f}-{cfg.get('rsiMax',60):.0f}" if cfg.get("rsiFilter", True) else "OFF"
    t1h_s  = "ON" if cfg.get("trend1hFilter", True) else "OFF"
    trl_s  = f"{cfg.get('trailingPct',0.5)*100:.0f}%" if cfg.get("trailingStop", True) else "OFF"
    curr_sym = "€" if use_revx else "$"
    exchange_name = "Revolut X" if use_revx else ("Coinbase" if cb_key else "SIM")
    add_log(state, "info", "AVVIO",
        f"{curr_sym}{capital:.0f} | {mode} [{exchange_name}] | Cap: {capp:.0f}% | Alloc: {alloc:.0f}% | "
        f"EMA: {ema_s} | Trend1h: {t1h_s} | RSI: {rsi_s} | "
        f"TP2: {tp2r}R | Trailing: {trl_s} | MaxLoss: {mcl}"
    )
    return {"ok": True}

@app.post("/stop")
async def stop_agent(user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    if not state["running"]:
        return {"error": "Not running"}
    state["running"] = False
    for p in list(state["positions"]):
        await exit_position(state, p, "STOP MANUALE", user_id=user_id)
    pnl = state["currentCapital"] - state["capital"]
    add_log(state, "info", "STOP", f"P&L finale: {pnl:+.2f}$")
    await persist_sessions()  # rimuovi dal DB
    return {"ok": True, "pnl": pnl}

@app.post("/close_position/{symbol}")
async def close_symbol(symbol: str, user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    pos = next((p for p in state["positions"] if p["symbol"] == symbol), None)
    if not pos:
        return {"error": f"No position on {symbol}"}
    await exit_position(state, pos, "CHIUSURA MANUALE", user_id=user_id)
    return {"ok": True}

@app.post("/chat")
async def chat(body: dict, user_id: int = Depends(get_current_user)):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "API key non configurata"}
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
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 500, "system": system, "messages": body.get("messages", [])}
        )
        data = res.json()
        if "content" in data:
            return {"reply": data["content"][0]["text"]}
        return {"error": str(data.get("error", data))}

# ── DEBUG / UTILITY ENDPOINTS ──────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "market_data": any(d["price"] > 0 for d in market_data.values()),
        "candles": len(candle_data),
        "candles_age_min": round((time.time() - _candles_last_update) / 60, 1) if _candles_last_update else None,
    }

@app.get("/candles_status")
async def candles_status(user_id: int = Depends(get_current_user)):
    """Mostra stato aggiornamento candele e un esempio di segnale EMA."""
    sample = {}
    for sym in list(candle_data.keys())[:5]:
        price = market_data.get(sym, {}).get("price", 0)
        sample[sym] = get_ema_signal(sym, price)
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
async def save_revx_keys(req: RevxKeysRequest, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="DB non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET revx_key_id = $1, revx_private_key = $2 WHERE id = $3",
            encrypt_key(req.key_id), encrypt_key(req.private_key), user_id
        )
    return {"ok": True}

@app.get("/test_revx")
async def test_revx(user_id: int = Depends(get_current_user)):
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
        return {"ok": True, "balances": balances, "raw": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/debug_revx_ticker")
async def debug_revx_ticker(user_id: int = Depends(get_current_user)):
    """Prova path diversi per trovare quello corretto dei ticker Revolut X."""
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
        if not row or not row["revx_key_id"]:
            return {"error": "Chiavi RevX non configurate"}
        key_id = decrypt_key(row["revx_key_id"])
        priv   = decrypt_key(row["revx_private_key"])
        results = {}
        for path in ["/api/1.0/market/tickers", "/api/1.0/market/ticker",
                     "/api/1.0/tickers", "/api/1.0/orders/active"]:
            try:
                r = await revx_request("GET", path, key_id=key_id, private_key=priv, params={})
                results[path] = str(r)[:300]
            except Exception as e:
                results[path] = f"ERROR: {e}"
        return results
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug_revx_candles")
async def debug_revx_candles(user_id: int = Depends(get_current_user)):
    """Prova path diversi per trovare quello corretto delle candles Revolut X."""
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT revx_key_id, revx_private_key FROM users WHERE id = $1", user_id)
        if not row or not row["revx_key_id"]:
            return {"error": "Chiavi RevX non configurate"}
        key_id = decrypt_key(row["revx_key_id"])
        priv   = decrypt_key(row["revx_private_key"])
        results = {}
        tests = [
            ("/api/1.0/market/candles", {"symbol": "BTC-EUR", "interval": "5", "limit": "3"}),
            ("/api/1.0/market/candles", {"symbol": "BTC-EUR", "interval": "5m", "limit": "3"}),
            ("/api/1.0/market/ohlcv",   {"symbol": "BTC-EUR", "interval": "5", "limit": "3"}),
            ("/api/1.0/market/klines",  {"symbol": "BTC-EUR", "interval": "5m", "limit": "3"}),
        ]
        for path, params in tests:
            key = path + "?" + "&".join(f"{k}={v}" for k,v in params.items())
            try:
                r = await revx_request("GET", path, key_id=key_id, private_key=priv, params=params)
                results[key] = str(r)[:300]
            except Exception as e:
                results[key] = f"ERROR: {e}"
        return results
    except Exception as e:
        return {"error": str(e)}

@app.get("/test_coinbase")
async def test_coinbase(user_id: int = Depends(get_current_user)):
    cb_key, cb_secret = _ENV_CB_KEY, _ENV_CB_SECRET
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT cb_key, cb_secret FROM users WHERE id = $1", user_id)
                if row and row["cb_key"]:
                    cb_key    = decrypt_key(row["cb_key"])
                    cb_secret = decrypt_key(row["cb_secret"])
        except Exception as e:
            print(f"DB error: {e}")
    if not cb_key:
        return {"ok": False, "error": "API key non configurata"}
    try:
        # Leggi saldo USDC/USD
        usdc_balance = await get_coinbase_usdc_balance(cb_key, cb_secret)
        # Leggi anche tutti gli account crypto
        result = await coinbase_request("GET", "/api/v3/brokerage/accounts", cb_key=cb_key, cb_secret=cb_secret)
        accounts = result.get("accounts", [])
        balances = [
            {"currency": a["currency"], "available": a["available_balance"]["value"]}
            for a in accounts
            if float(a.get("available_balance", {}).get("value", 0) or 0) > 0
        ]
        # Aggiungi USDC in cima se trovato
        if usdc_balance > 0:
            balances.insert(0, {"currency": "USDC/USD", "available": str(round(usdc_balance, 2))})
        return {"ok": True, "balances": balances, "usdc_tradable": usdc_balance}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/debug_coinbase")
async def debug_coinbase(user_id: int = Depends(get_current_user)):
    """Mostra la risposta raw di Coinbase per debug saldi."""
    cb_key, cb_secret = _ENV_CB_KEY, _ENV_CB_SECRET
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT cb_key, cb_secret FROM users WHERE id = $1", user_id)
                if row and row["cb_key"]:
                    cb_key    = decrypt_key(row["cb_key"])
                    cb_secret = decrypt_key(row["cb_secret"])
        except Exception as e:
            pass
    if not cb_key:
        return {"error": "no keys"}
    try:
        # Prova endpoint portfolios per trovare USDC
        portfolios_result = await coinbase_request("GET", "/api/v3/brokerage/portfolios", cb_key=cb_key, cb_secret=cb_secret)

        # Cerca UUID del portfolio default
        portfolios = portfolios_result.get("portfolios", [])
        default_uuid = None
        for p in portfolios:
            if p.get("type") == "DEFAULT" or p.get("name") in ("Default", "Portafoglio principale"):
                default_uuid = p.get("uuid")
                break
        if not default_uuid and portfolios:
            default_uuid = portfolios[0].get("uuid")

        portfolio_balances = {}
        if default_uuid:
            bal_result = await coinbase_request("GET", f"/api/v3/brokerage/portfolios/{default_uuid}", cb_key=cb_key, cb_secret=cb_secret)
            portfolio_balances = bal_result

        return {
            "portfolios": portfolios,
            "default_uuid": default_uuid,
            "portfolio_detail": portfolio_balances,
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/logos")
async def get_logos():
    LOGO_URLS = {
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
    return LOGO_URLS

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
