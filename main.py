import asyncio
import os
import time
import jwt
import hashlib
import json
import secrets
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx
import uvicorn
import asyncpg
import bcrypt

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "crypto-agent-secret-key-change-in-prod")

db_pool = None

async def get_db():
    return db_pool

security = HTTPBearer()

def create_token(user_id: int) -> str:
    import base64
    payload = f"{user_id}:{int(time.time()) + 86400 * 30}"
    return base64.urlsafe_b64encode(f"{payload}:{hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:16]}".encode()).decode()

def verify_token(token: str) -> int:
    import base64
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split(":")
        user_id, expires, sig = int(parts[0]), int(parts[1]), parts[2]
        if int(time.time()) > expires:
            raise HTTPException(status_code=401, detail="Token scaduto")
        payload = f"{user_id}:{expires}"
        expected = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:16]
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

market_data = {}  # sym -> {price, change1h, change24h, volume24h, priceHistory, icon}
user_sessions: dict = {}

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

async def fetch_candles_for_symbol(sym: str, client: httpx.AsyncClient) -> dict | None:
    """Scarica candele 5min e 15min da Binance e calcola EMA20/50."""
    pair = f"{sym}USDT"
    try:
        r5 = await client.get(
            f"{BINANCE_BASE}/api/v3/klines",
            params={"symbol": pair, "interval": "5m", "limit": 60}
        )
        r15 = await client.get(
            f"{BINANCE_BASE}/api/v3/klines",
            params={"symbol": pair, "interval": "15m", "limit": 60}
        )
        if r5.status_code != 200 or r15.status_code != 200:
            return None

        klines5  = r5.json()
        klines15 = r15.json()

        if not isinstance(klines5, list) or not isinstance(klines15, list):
            return None
        if len(klines5) < 50 or len(klines15) < 50:
            return None

        closes5  = [float(k[4]) for k in klines5]
        closes15 = [float(k[4]) for k in klines15]
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

        return {
            "ema20_5m":         calc_ema(closes5,  20),
            "ema50_5m":         calc_ema(closes5,  50),
            "ema20_15m":        calc_ema(closes15, 20),
            "ema50_15m":        calc_ema(closes15, 50),
            "last_close_5m":    closes5[-1],
            "atr_5m":           atr_5m,
            "pullback_low_5m":  pullback_low_5m,
            "vol_avg_20":       vol_avg_20,
            "vol_last":         vol_last,
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
                   vol_multiplier: float = 1.2, max_stop_pct: float = 0.025) -> dict:
    """
    Analizza il segnale EMA + volume per una coin.
    Restituisce segnale, stop price contestuale e R (rischio per unità).
    """
    cd = candle_data.get(sym)
    if not cd:
        return {"signal": False, "reason": "no candle data", "stop_price": 0.0, "R": 0.0}

    ema20_15m       = cd["ema20_15m"]
    ema50_15m       = cd["ema50_15m"]
    ema20_5m        = cd["ema20_5m"]
    last_close_5m   = cd["last_close_5m"]
    atr_5m          = cd["atr_5m"]
    pullback_low_5m = cd["pullback_low_5m"]
    vol_avg_20      = cd["vol_avg_20"]
    vol_last        = cd["vol_last"]

    # 1. Trend rialzista su 15min
    trend_ok = ema20_15m > ema50_15m

    # 2. Prezzo vicino a EMA20 su 5min (pullback)
    dist_from_ema20 = abs(current_price - ema20_5m) / ema20_5m
    pullback_ok = dist_from_ema20 <= pullback_tolerance

    # 3. Ultima candela 5min chiusa sopra EMA20 (rimbalzo)
    bounce_ok = last_close_5m > ema20_5m

    # 4. Volume candela corrente >= media * coefficiente
    vol_ok = (vol_avg_20 > 0) and (vol_last >= vol_avg_20 * vol_multiplier)

    # Stop contestuale: il più basso tra minimo pullback e entry - 1xATR
    # (calcolato su current_price come proxy entry)
    stop_from_low = pullback_low_5m
    stop_from_atr = current_price - atr_5m if atr_5m > 0 else 0.0
    stop_price    = min(stop_from_low, stop_from_atr) if stop_from_atr > 0 else stop_from_low

    # R = distanza percentuale entry → stop
    R = (current_price - stop_price) / current_price if stop_price > 0 else 0.0

    # Se stop troppo largo rispetto al limite configurato → no trade
    stop_ok = 0 < R <= max_stop_pct

    signal = trend_ok and pullback_ok and bounce_ok and vol_ok and stop_ok

    if not trend_ok:
        reason = f"no trend (EMA20 15m {ema20_15m:.4f} < EMA50 15m {ema50_15m:.4f})"
    elif not pullback_ok:
        reason = f"no pullback (dist EMA20: {dist_from_ema20*100:.1f}% > {pullback_tolerance*100:.1f}%)"
    elif not bounce_ok:
        reason = f"no rimbalzo (close 5m {last_close_5m:.4f} < EMA20 {ema20_5m:.4f})"
    elif not vol_ok:
        ratio = vol_last / vol_avg_20 if vol_avg_20 > 0 else 0
        reason = f"volume basso ({ratio:.1f}x media, richiesto {vol_multiplier}x)"
    elif not stop_ok:
        reason = f"stop troppo largo ({R*100:.1f}% > {max_stop_pct*100:.1f}%)" if R > 0 else "stop non calcolabile"
    else:
        reason = (f"OK | EMA20/50 15m: {ema20_15m:.4f}/{ema50_15m:.4f} | "
                  f"dist EMA20: {dist_from_ema20*100:.2f}% | "
                  f"vol: {vol_last/vol_avg_20:.1f}x | R: {R*100:.2f}%")

    return {
        "signal":      signal,
        "reason":      reason,
        "stop_price":  round(stop_price, 8),
        "R":           round(R, 6),
        "trend_ok":    trend_ok,
        "pullback_ok": pullback_ok,
        "bounce_ok":   bounce_ok,
        "vol_ok":      vol_ok,
        "stop_ok":     stop_ok,
    }

# ── rest of market data ───────────────────────────────────────────────────────

STABLES = {'USDT','USDC','BUSD','DAI','FDUSD','TUSD','USDP','GUSD','FRAX',
           'LUSD','SUSD','EUR','GBP','USD','USDD','USTC','PAX','CBBTC','WBTC'}

_coinbase_products: dict = {}
_products_last_update: float = 0

async def fetch_prices():
    global _products_last_update
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get("https://api.exchange.coinbase.com/products")
            all_products = r.json()

        usd_syms = {}
        for p in all_products:
            if not isinstance(p, dict): continue
            if p.get("quote_currency") != "USD": continue
            if p.get("status") != "online": continue
            sym = p.get("base_currency", "")
            if not sym or not sym.isascii() or not sym.isalpha(): continue
            if sym in STABLES: continue
            usd_syms[p["id"]] = sym

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

            _coinbase_products[sym] = {"price": price, "change24h": change24h, "volume24h": vol_usd, "logo_url": ""}

            if sym not in market_data:
                market_data[sym] = {
                    "price": 0.0, "change1h": 0.0, "change24h": 0.0,
                    "volume24h": 0.0, "priceHistory": [], "icon": sym[0]
                }

            hist = market_data[sym]["priceHistory"]
            hist.append(price)
            if len(hist) > 450:
                hist.pop(0)

            if len(hist) >= 10:
                price_1h_ago = hist[0]
                change1h = (price - price_1h_ago) / price_1h_ago * 100
            else:
                change1h = change24h * 0.04

            market_data[sym]["price"] = price
            market_data[sym]["change1h"] = change1h
            market_data[sym]["change24h"] = change24h
            market_data[sym]["volume24h"] = vol_usd

            for state in user_sessions.values():
                for pos in state["positions"]:
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
    return sum(
        (p["currentPrice"] - p["entryPrice"]) / p["entryPrice"] * p.get("size_remaining", p["size"])
        for p in state["positions"]
    )

# ── trading ───────────────────────────────────────────────────────────────────

async def enter_position(state: dict, sym_data: dict):
    cfg      = state["config"]
    price    = sym_data["price"]
    sym      = sym_data["symbol"]
    is_real  = cfg.get("realMode", False)

    alloc_pct = cfg.get("allocPct", 0.20)
    size = state["capital"] * alloc_pct
    size = min(size, state["currentCapital"])
    if size < 1:
        return

    # Stop price: dalla funzione EMA signal (contestuale ATR/low)
    # Fallback: stop fisso da config
    stop_price = sym_data.get("stop_price", 0.0)
    if stop_price <= 0 or stop_price >= price:
        fallback_sl = cfg.get("stopLoss", 0.01)
        stop_price  = price * (1 - fallback_sl)

    R_pct = (price - stop_price) / price  # rischio in % per questa posizione

    # TP1 = entry + 1R, TP2 = entry + 1.5R
    tp1_price = price * (1 + R_pct)
    tp2_price = price * (1 + R_pct * 1.5)

    if is_real:
        cb_key    = state.get("cb_key", "") or _ENV_CB_KEY
        cb_secret = state.get("cb_secret", "") or _ENV_CB_SECRET
        try:
            body = {
                "client_order_id": f"ca-{sym}-{int(time.time())}",
                "product_id": f"{sym}-USDC",
                "side": "BUY",
                "order_configuration": {"market_market_ioc": {"quote_size": str(round(size, 2))}}
            }
            result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
            if result.get("success") != True:
                err = result.get("error_response", {})
                err_msg = err.get("message", str(result))
                err_str = str(result).lower()
                add_log(state, "info", "ERRORE", f"Ordine {sym} fallito: {err_msg}")
                # Cooldown automatico per errori che indicano coin non tradabile temporaneamente
                if any(x in err_str for x in ["not available", "cancel only", "permission_denied", "orderbook", "suspended"]):
                    state["cooldowns"][sym] = (datetime.now().timestamp() + 3600) * 1000
                    add_log(state, "info", "ESCLUSA", f"{sym} esclusa per 1h — {err_msg[:60]}")
                return
            filled      = result.get("success_response", {})
            actual_price = float(filled.get("average_filled_price", price)) or price
            # Ricalcola stop e TP sull'actual price
            stop_price  = actual_price * (1 - R_pct)
            tp1_price   = actual_price * (1 + R_pct)
            tp2_price   = actual_price * (1 + R_pct * 1.5)
            add_log(state, "buy", "ACQUISTO REALE",
                f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | "
                f"SL: ${stop_price:.4f} | TP1: ${tp1_price:.4f} | TP2: ${tp2_price:.4f} | R: {R_pct*100:.2f}%")
            await send_telegram(
                "ACQUISTO REALE\n" + sym + " @ $" + f"{actual_price:.4f}" +
                "\nSize: $" + f"{size:.2f}" +
                "\nSL: $" + f"{stop_price:.4f}" +
                "\nTP1: $" + f"{tp1_price:.4f}" + " | TP2: $" + f"{tp2_price:.4f}"
            )
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Coinbase error: {e}")
            return
    else:
        actual_price = price
        add_log(state, "buy", "ACQUISTO SIM",
            f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | "
            f"SL: ${stop_price:.4f} | TP1: ${tp1_price:.4f} | TP2: ${tp2_price:.4f} | R: {R_pct*100:.2f}%")

    state["currentCapital"] -= size
    pos = {
        "symbol":      sym,
        "icon":        sym_data["icon"],
        "entryPrice":  actual_price,
        "currentPrice": actual_price,
        "highPrice":   actual_price,
        "size":        size,
        "size_remaining": size,        # per TP parziale
        "tp1_hit":     False,          # TP1 già raggiunto?
        "entryTime":   datetime.now().isoformat(),
        "stopPrice":   stop_price,
        "tp1Price":    tp1_price,
        "tp2Price":    tp2_price,
        "R_pct":       R_pct,
        "realMode":    is_real,
    }
    state["positions"].append(pos)

async def exit_position(state: dict, pos: dict, reason: str, partial: bool = False):
    """
    Se partial=True: chiude il 50% della posizione (TP1).
    Se partial=False: chiude tutto.
    """
    cur  = pos["currentPrice"]
    sym  = pos["symbol"]
    dur  = (datetime.now() - datetime.fromisoformat(pos["entryTime"])).total_seconds() / 60

    # Dimensione effettiva da chiudere
    close_size = pos["size_remaining"] * 0.5 if partial else pos["size_remaining"]

    if pos.get("realMode", False):
        cb_key    = state.get("cb_key", "") or _ENV_CB_KEY
        cb_secret = state.get("cb_secret", "") or _ENV_CB_SECRET
        try:
            accounts = await coinbase_request("GET", "/api/v3/brokerage/accounts", cb_key=cb_key, cb_secret=cb_secret)
            real_qty = 0.0
            for acc in accounts.get("accounts", []):
                if acc["currency"] == sym:
                    real_qty = float(acc["available_balance"]["value"])
                    break
            # In caso parziale vendiamo metà qty, arrotondata
            qty_to_sell = round(real_qty * 0.5, 8) if partial else round(real_qty, 8)
            if qty_to_sell <= 0:
                add_log(state, "info", "ERRORE", f"Saldo {sym}: {real_qty} — vendita annullata")
            else:
                body = {
                    "client_order_id": f"ca-exit-{sym}-{int(time.time())}",
                    "product_id": f"{sym}-USDC", "side": "SELL",
                    "order_configuration": {"market_market_ioc": {"base_size": str(qty_to_sell)}}
                }
                result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
                if result.get("success") != True:
                    add_log(state, "info", "ERRORE", f"Vendita {sym} fallita: {result.get('error_response', {}).get('message', str(result))}")
                else:
                    filled = result.get("success_response", {})
                    cur = float(filled.get("average_filled_price", cur)) or cur
                    add_log(state, "info", "VENDUTO", f"{sym} qty: {qty_to_sell:.6f} @ ${cur:.4f}")
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Coinbase exit error: {e}")

    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * close_size
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    if partial:
        # TP1: restituisce metà capitale, aggiorna size_remaining, sposta stop a breakeven
        state["currentCapital"] += close_size + pnl
        pos["size_remaining"] -= close_size
        pos["stopPrice"]       = pos["entryPrice"]  # breakeven
        pos["tp1_hit"]         = True
        mode = "REALE" if pos.get("realMode") else "SIM"
        add_log(state, "sell", f"TP1 {mode}",
            f"{sym} 50% @ ${cur:.4f} | +{pnl:.2f}$ ({pct:+.2f}%) | stop → breakeven")
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
    state["trades"].append({
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": pnl, "pct": pct, "time": datetime.now().isoformat(),
        "entryTime": pos["entryTime"], "durationMin": round(dur, 1),
        "size": pos["size"], "realMode": pos.get("realMode", False),
        "tp1_hit": pos.get("tp1_hit", False),
    })
    state["positions"] = [p for p in state["positions"] if p is not pos]
    mode = "REALE" if pos.get("realMode") else "SIM"
    add_log(state, "sell", f"{reason} {mode}",
        f"{sym} @ ${cur:.4f} | {pnl:+.2f}$ ({pct:+.2f}%) | {dur:.0f} min")
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

async def scan_and_trade(state: dict):
    if not state["running"]:
        return
    cfg = state["config"]

    elapsed_ms = (datetime.now().timestamp() - state["sessionStart"]) * 1000
    if elapsed_ms >= state["sessionDuration"]:
        state["running"] = False
        for p in list(state["positions"]):
            await exit_position(state, p, "SESSIONE SCADUTA")
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

    # Gestione posizioni aperte: TP1, TP2, stop loss
    for pos in list(state["positions"]):
        cur   = pos["currentPrice"]
        entry = pos["entryPrice"]

        if cur > pos.get("highPrice", cur):
            pos["highPrice"] = cur

        # TP1: prima volta che tocca +1R
        if not pos.get("tp1_hit", False) and cur >= pos["tp1Price"]:
            await exit_position(state, pos, "TP1", partial=True)
            continue

        # TP2: tocca +1.5R → chiude tutto il rimanente
        if pos.get("tp1_hit", False) and cur >= pos["tp2Price"]:
            await exit_position(state, pos, "TP2")
            continue

        # Stop loss (include breakeven dopo TP1)
        if cur <= pos["stopPrice"]:
            reason = "STOP BREAKEVEN" if pos.get("tp1_hit") else "STOP LOSS"
            await exit_position(state, pos, reason)

    alloc_pct = cfg.get("allocPct", 0.20)
    max_pos   = max(1, int(round(1 / alloc_pct)))
    open_syms = {p["symbol"] for p in state["positions"]}
    slots     = max_pos - len(state["positions"])

    # Non aprire nuove posizioni se maxTrades raggiunto
    if max_trades > 0 and state["tradeCount"] >= max_trades:
        _update_pnl(state)
        return

    if slots <= 0 or state["currentCapital"] < state["capital"] * alloc_pct * 0.5:
        _update_pnl(state)
        return

    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]

    # Filtro BTC trend
    btc    = market_data.get("BTC", {})
    btc_1h = btc.get("change1h", 0)
    if btc_1h < -0.3:
        add_log(state, "info", "PAUSA", f"BTC {btc_1h:+.2f}% 1h — agente in attesa")
        _update_pnl(state)
        return

    min_vol      = cfg.get("minVolume", 0)
    ema_filter   = cfg.get("emaFilter", True)
    pullback_tol = cfg.get("pullbackTolerance", 0.015)
    vol_mult     = cfg.get("volMultiplier", 1.2)
    max_stop_pct = cfg.get("maxStopPct", 0.025)

    universe = [
        {**d, "symbol": sym}
        for sym, d in market_data.items()
        if d["price"] > 0
        and d.get("volume24h", 0) >= min_vol
        and sym not in open_syms
        and sym in _coinbase_products
        and (state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
    ]
    universe_sorted = sorted(universe, key=lambda d: d.get("volume24h", 0), reverse=True)

    candidates  = []
    ema_skipped = 0

    for d in universe_sorted:
        sym = d["symbol"]
        if ema_filter:
            signal = get_ema_signal(sym, d["price"], pullback_tol, vol_mult, max_stop_pct)
            if not signal["signal"]:
                ema_skipped += 1
                continue
            d["ema_reason"]  = signal["reason"]
            d["stop_price"]  = signal["stop_price"]
            d["R_pct"]       = signal["R"]
        candidates.append(d)
        if len(candidates) >= slots:
            break

    top3 = [(d["symbol"], round(d.get("volume24h", 0) / 1e6, 0)) for d in universe_sorted[:3]]
    add_log(state, "info", "SCAN",
        f"Universe: {len(prices_ok)} | Top3 vol (M$): {top3} | "
        f"Candidati: {len(candidates)} | Saltati EMA: {ema_skipped} | "
        f"Candele: {len(candle_data)} | BTC1h: {btc_1h:+.2f}% | Trade: {state['tradeCount']}/{max_trades or 'inf'}"
    )

    for d in candidates:
        add_log(state, "info", "SEGNALE", f"{d['symbol']} | {d.get('ema_reason', 'EMA off')}")
        await enter_position(state, d)

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
                        await exit_position(tg_state, pos, "TELEGRAM")
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
    while True:
        try:
            await fetch_prices()

            # Aggiorna candele ogni 5 minuti
            if time.time() - _candles_last_update >= CANDLE_UPDATE_INTERVAL:
                await fetch_all_candles()

            for state in list(user_sessions.values()):
                if state["running"]:
                    await scan_and_trade(state)
            await poll_telegram()
        except Exception as e:
            import traceback
            print(f"Loop error: {e}\n{traceback.format_exc()}")
        await asyncio.sleep(8)

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
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
            print("Database connesso e schema creato")
        except Exception as e:
            print(f"Database error: {e}")
    asyncio.create_task(background_loop())

# ── AUTH ENDPOINTS ─────────────────────────────────────────────────────────────

@app.post("/auth/register")
async def register(req: RegisterRequest):
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
                "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
                req.username.lower(), pw_hash
            )
        token = create_token(row["id"])
        return {"token": token, "username": req.username.lower(), "has_api_keys": False}
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=400, detail="Username già in uso")

@app.post("/auth/login")
async def login(req: LoginRequest):
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
    return {"token": token, "username": req.username.lower(), "has_api_keys": has_keys}

@app.post("/auth/save_keys")
async def save_keys(req: ApiKeyRequest, user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET cb_key = $1, cb_secret = $2 WHERE id = $3",
            req.cb_key, req.cb_secret, user_id
        )
    return {"ok": True}

@app.get("/auth/me")
async def get_me(user_id: int = Depends(get_current_user)):
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database non disponibile")
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, cb_key FROM users WHERE id = $1", user_id
        )
    return {"username": row["username"], "has_api_keys": bool(row["cb_key"])}

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
    for s, d in market_data.items():
        if d["price"] <= 0:
            continue
        item = {"symbol": s, **d}
        cd = candle_data.get(s)
        if cd:
            sig = get_ema_signal(s, d["price"])
            item["ema"] = {
                "trend":    sig["trend_ok"],
                "pullback": sig["pullback_ok"],
                "volume":   sig["vol_ok"],
                "stop":     sig["stop_ok"],
                "signal":   sig["signal"],
            }
        else:
            item["ema"] = None
        items.append(item)
    result = sorted(items, key=lambda x: x["change24h"], reverse=True)
    return {"market": result}

@app.get("/trades")
async def get_trades(user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    return {"trades": state["trades"]}

@app.post("/start")
async def start_agent(body: dict, user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    if state["running"]:
        return {"error": "Already running"}
    cfg     = body.get("config", {})
    capital = float(cfg.get("capital", 1000))

    cb_key, cb_secret = "", ""
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT cb_key, cb_secret FROM users WHERE id = $1", user_id)
                if row:
                    cb_key    = row["cb_key"] or ""
                    cb_secret = row["cb_secret"] or ""
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
            "stopLoss":            float(cfg.get("stopLoss", 0.01)),
            "cooldown":            float(cfg.get("cooldown", 1)),
            "minVolume":           float(cfg.get("minVolume", 0)),
            "sessionDuration":     int(cfg.get("sessionDuration", 8)),
            "realMode":            bool(cfg.get("realMode", False)),
            "emaFilter":           bool(cfg.get("emaFilter", True)),
            "pullbackTolerance":   float(cfg.get("pullbackTolerance", 0.015)),
            "volMultiplier":       float(cfg.get("volMultiplier", 1.2)),
            "maxStopPct":          float(cfg.get("maxStopPct", 0.025)),
            "maxTrades":           int(cfg.get("maxTrades", 0)),
            "maxConsecutiveLosses": int(cfg.get("maxConsecutiveLosses", 3)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "cb_key": cb_key, "cb_secret": cb_secret,
        "consecutiveLosses": 0,
    })
    alloc  = float(cfg.get("allocPct", 0.20)) * 100
    vol    = float(cfg.get("minVolume", 0)) / 1_000_000
    mode   = "REALE" if cfg.get("realMode", False) else "SIMULAZIONE"
    ema_s  = "ON" if cfg.get("emaFilter", True) else "OFF"
    ptol   = float(cfg.get("pullbackTolerance", 0.015)) * 100
    mt     = int(cfg.get("maxTrades", 0))
    mcl    = int(cfg.get("maxConsecutiveLosses", 3))
    add_log(state, "info", "AVVIO",
        f"${capital:.0f} | {mode} | Alloc: {alloc:.0f}% | Vol: ${vol:.0f}M | "
        f"EMA: {ema_s} | Pullback: {ptol:.1f}% | MaxTrade: {mt or 'inf'} | MaxLoss: {mcl}"
    )
    return {"ok": True}

@app.post("/stop")
async def stop_agent(user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    if not state["running"]:
        return {"error": "Not running"}
    state["running"] = False
    for p in list(state["positions"]):
        await exit_position(state, p, "STOP MANUALE")
    pnl = state["currentCapital"] - state["capital"]
    add_log(state, "info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.post("/close_position/{symbol}")
async def close_symbol(symbol: str, user_id: int = Depends(get_current_user)):
    state = get_session(user_id)
    pos = next((p for p in state["positions"] if p["symbol"] == symbol), None)
    if not pos:
        return {"error": f"No position on {symbol}"}
    await exit_position(state, pos, "CHIUSURA MANUALE")
    return {"ok": True}

@app.post("/chat")
async def chat(body: dict):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "API key non configurata"}
    state = get_session(0)
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
        "coinbase": any(d["price"] > 0 for d in market_data.values()),
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

@app.get("/test_coinbase")
async def test_coinbase(user_id: int = Depends(get_current_user)):
    cb_key, cb_secret = _ENV_CB_KEY, _ENV_CB_SECRET
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT cb_key, cb_secret FROM users WHERE id = $1", user_id)
                if row and row["cb_key"]:
                    cb_key    = row["cb_key"]
                    cb_secret = row["cb_secret"]
        except Exception as e:
            print(f"DB error: {e}")
    if not cb_key:
        return {"ok": False, "error": "API key non configurata"}
    try:
        result = await coinbase_request("GET", "/api/v3/brokerage/accounts", cb_key=cb_key, cb_secret=cb_secret)
        accounts = result.get("accounts", [])
        balances = [
            {"currency": a["currency"], "available": a["available_balance"]["value"]}
            for a in accounts
            if float(a["available_balance"]["value"]) > 0
        ]
        return {"ok": True, "balances": balances}
    except Exception as e:
        return {"ok": False, "error": str(e)}

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
