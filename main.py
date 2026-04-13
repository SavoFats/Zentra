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

        return {
            "ema20_5m":      calc_ema(closes5,  20),
            "ema50_5m":      calc_ema(closes5,  50),
            "ema20_15m":     calc_ema(closes15, 20),
            "ema50_15m":     calc_ema(closes15, 50),
            "last_close_5m": closes5[-1],
            "updated_at":    time.time(),
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

def get_ema_signal(sym: str, current_price: float, pullback_tolerance: float = 0.015) -> dict:
    """
    Analizza il segnale EMA per una coin.
    Restituisce: {
        "trend_ok": bool,       # EMA20 > EMA50 su 15min
        "pullback_ok": bool,    # prezzo vicino a EMA20 su 5min
        "bounce_ok": bool,      # ultima candela 5min chiusa sopra EMA20
        "signal": bool,         # tutti e tre veri
        "reason": str           # descrizione leggibile
    }
    """
    cd = candle_data.get(sym)
    if not cd:
        return {"trend_ok": False, "pullback_ok": False, "bounce_ok": False,
                "signal": False, "reason": "no candle data"}

    ema20_15m = cd["ema20_15m"]
    ema50_15m = cd["ema50_15m"]
    ema20_5m  = cd["ema20_5m"]
    last_close_5m = cd["last_close_5m"]

    # 1. Trend rialzista su 15min
    trend_ok = ema20_15m > ema50_15m

    # 2. Prezzo attuale vicino a EMA20 su 5min (pullback)
    #    "vicino" = entro pullback_tolerance sopra o sotto EMA20
    dist_from_ema20 = abs(current_price - ema20_5m) / ema20_5m
    pullback_ok = dist_from_ema20 <= pullback_tolerance

    # 3. Ultima candela 5min chiusa sopra EMA20 (rimbalzo confermato)
    bounce_ok = last_close_5m > ema20_5m

    signal = trend_ok and pullback_ok and bounce_ok

    if not trend_ok:
        reason = f"no trend (EMA20 15m {ema20_15m:.4f} < EMA50 15m {ema50_15m:.4f})"
    elif not pullback_ok:
        dist_pct = dist_from_ema20 * 100
        reason = f"no pullback (dist da EMA20: {dist_pct:.1f}% > {pullback_tolerance*100:.1f}%)"
    elif not bounce_ok:
        reason = f"no rimbalzo (close 5m {last_close_5m:.4f} < EMA20 {ema20_5m:.4f})"
    else:
        reason = f"OK (EMA20/50 15m: {ema20_15m:.4f}/{ema50_15m:.4f}, dist EMA20: {dist_from_ema20*100:.2f}%)"

    return {
        "trend_ok": trend_ok,
        "pullback_ok": pullback_ok,
        "bounce_ok": bounce_ok,
        "signal": signal,
        "reason": reason,
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
    }

def get_session(user_id: int) -> dict:
    if user_id not in user_sessions:
        user_sessions[user_id] = make_session()
    return user_sessions[user_id]

def add_log(state: dict, type_: str, label: str, desc: str):
    state["log"].insert(0, {
        "type": type_, "label": label, "desc": desc,
        "time": datetime.now().strftime("%H:%M:%S")
    })
    if len(state["log"]) > 200:
        state["log"].pop()

def unrealized_pnl(state: dict) -> float:
    return sum(
        (p["currentPrice"] - p["entryPrice"]) / p["entryPrice"] * p["size"]
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

    sl_pct = cfg.get("stopLoss", 0.03)

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
                add_log(state, "info", "ERRORE", f"Ordine {sym} fallito: {err_msg}")
                if "not available" in err_msg:
                    state["cooldowns"][sym] = (datetime.now().timestamp() + 3600) * 1000
                    add_log(state, "info", "ESCLUSA", f"{sym} non disponibile — esclusa per 1h")
                return
            filled = result.get("success_response", {})
            actual_price = float(filled.get("average_filled_price", price)) or price
            add_log(state, "buy", "ACQUISTO REALE", f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | SL: {sl_pct*100:.1f}%")
            await send_telegram("ACQUISTO REALE\n" + sym + " @ $" + f"{actual_price:.4f}" + "\nSize: $" + f"{size:.2f}")
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Coinbase error: {e}")
            return
    else:
        actual_price = price
        add_log(state, "buy", "ACQUISTO SIM", f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | SL: {sl_pct*100:.1f}%")

    state["currentCapital"] -= size
    pos = {
        "symbol": sym, "icon": sym_data["icon"],
        "entryPrice": actual_price, "currentPrice": actual_price,
        "highPrice": actual_price, "size": size,
        "entryTime": datetime.now().isoformat(),
        "stopPrice": actual_price * (1 - sl_pct),
        "realMode": is_real,
    }
    state["positions"].append(pos)

async def exit_position(state: dict, pos: dict, reason: str):
    cur  = pos["currentPrice"]
    sym  = pos["symbol"]
    dur  = (datetime.now() - datetime.fromisoformat(pos["entryTime"])).total_seconds() / 60

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
            if real_qty <= 0:
                add_log(state, "info", "ERRORE", f"Saldo {sym}: {real_qty} — vendita annullata")
            else:
                body = {
                    "client_order_id": f"ca-exit-{sym}-{int(time.time())}",
                    "product_id": f"{sym}-USDC", "side": "SELL",
                    "order_configuration": {"market_market_ioc": {"base_size": str(round(real_qty, 8))}}
                }
                result = await coinbase_request("POST", "/api/v3/brokerage/orders", body, cb_key=cb_key, cb_secret=cb_secret)
                if result.get("success") != True:
                    add_log(state, "info", "ERRORE", f"Vendita {sym} fallita: {result.get('error_response', {}).get('message', str(result))}")
                else:
                    filled = result.get("success_response", {})
                    cur = float(filled.get("average_filled_price", cur)) or cur
                    add_log(state, "info", "VENDUTO", f"{sym} qty: {real_qty:.6f} @ ${cur:.4f}")
        except Exception as e:
            add_log(state, "info", "ERRORE", f"Coinbase exit error: {e}")

    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    state["currentCapital"] += pos["size"] + pnl
    state["tradeCount"] += 1
    if pnl > 0:
        state["wins"] += 1

    cfg = state["config"]
    state["cooldowns"][sym] = (datetime.now().timestamp() + cfg.get("cooldown", 1) * 3600) * 1000
    state["trades"].append({
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": pnl, "pct": pct, "time": datetime.now().isoformat(),
        "entryTime": pos["entryTime"], "durationMin": round(dur, 1),
        "size": pos["size"], "realMode": pos.get("realMode", False),
    })
    state["positions"] = [p for p in state["positions"] if p is not pos]
    mode = "REALE" if pos.get("realMode") else "SIM"
    add_log(state, "sell", f"{reason} {mode}", f"{sym} @ ${cur:.4f} | {pnl:+.2f}$ ({pct:+.2f}%) | {dur:.0f} min")
    if pos.get("realMode"):
        esito = "PROFITTO" if pnl >= 0 else "PERDITA"
        msg = "VENDITA REALE - " + esito + "\n" + sym + " @ $" + f"{cur:.4f}" + "\nP&L: " + f"{pnl:+.2f}" + "$"
        await send_telegram(msg)

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

    # Gestione trailing stop per posizioni aperte
    for pos in list(state["positions"]):
        cur = pos["currentPrice"]
        entry = pos["entryPrice"]
        profit_pct = (cur - entry) / entry * 100
        if cur > pos.get("highPrice", cur):
            pos["highPrice"] = cur
        high = pos["highPrice"]
        if profit_pct >= 5.0:
            new_stop = high * 0.99
        elif profit_pct >= 3.0:
            new_stop = high * 0.985
        elif profit_pct >= 1.5:
            new_stop = entry
        else:
            new_stop = pos["stopPrice"]
        if new_stop > pos["stopPrice"]:
            pos["stopPrice"] = new_stop
        if cur <= pos["stopPrice"]:
            await exit_position(state, pos, "STOP LOSS")

    alloc_pct = cfg.get("allocPct", 0.20)
    max_pos   = max(1, int(round(1 / alloc_pct)))
    open_syms = {p["symbol"] for p in state["positions"]}
    slots     = max_pos - len(state["positions"])

    if slots <= 0 or state["currentCapital"] < state["capital"] * alloc_pct * 0.5:
        _update_pnl(state)
        return

    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]

    # Filtro BTC trend: pausa se BTC scende
    btc = market_data.get("BTC", {})
    btc_1h = btc.get("change1h", 0)
    if btc_1h < -0.3:
        add_log(state, "info", "PAUSA", f"BTC {btc_1h:+.2f}% 1h — agente in attesa")
        _update_pnl(state)
        return

    min_vol   = cfg.get("minVolume", 0)
    ema_filter = cfg.get("emaFilter", True)
    pullback_tol = cfg.get("pullbackTolerance", 0.015)

    # Universe: coin con volume sufficiente, non in posizione, non in cooldown
    universe = [
        {**d, "symbol": sym}
        for sym, d in market_data.items()
        if d["price"] > 0
        and d.get("volume24h", 0) >= min_vol
        and sym not in open_syms
        and sym in _coinbase_products
        and (state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
    ]

    # Ordina per volume (top coin prima) poi applica filtro EMA
    universe_sorted = sorted(universe, key=lambda d: d.get("volume24h", 0), reverse=True)

    candidates = []
    ema_skipped = 0

    for d in universe_sorted:
        sym = d["symbol"]
        if ema_filter:
            signal = get_ema_signal(sym, d["price"], pullback_tol)
            if not signal["signal"]:
                ema_skipped += 1
                continue
            d["ema_reason"] = signal["reason"]
        candidates.append(d)
        if len(candidates) >= slots:
            break

    top3 = [(d["symbol"], round(d.get("volume24h",0)/1e6,0)) for d in universe_sorted[:3]]
    candles_ok = len(candle_data)
    add_log(state, "info", "SCAN",
        f"Universe: {len(prices_ok)} | Top3 vol (M$): {top3} | "
        f"Candidati EMA: {len(candidates)} | Saltati: {ema_skipped} | "
        f"Candele: {candles_ok} | BTC1h: {btc_1h:+.2f}%"
    )

    for d in candidates:
        ema_info = d.get("ema_reason", "EMA filter off")
        add_log(state, "info", "SEGNALE", f"{d['symbol']} | {ema_info}")
        await enter_position(state, d)

    _update_pnl(state)

def _update_pnl(state: dict):
    if not state["sessionStart"]:
        return
    unr     = unrealized_pnl(state)
    pos_val = sum(p["size"] for p in state["positions"])
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
    pos_val = sum(p["size"] for p in state["positions"])
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
    result = sorted(
        [{"symbol": s, **d} for s, d in market_data.items() if d["price"] > 0],
        key=lambda x: x["change24h"], reverse=True
    )
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
            "allocPct":           float(cfg.get("allocPct", 0.20)),
            "stopLoss":           float(cfg.get("stopLoss", 0.03)),
            "cooldown":           float(cfg.get("cooldown", 1)),
            "minVolume":          float(cfg.get("minVolume", 0)),
            "sessionDuration":    int(cfg.get("sessionDuration", 8)),
            "realMode":           bool(cfg.get("realMode", False)),
            "emaFilter":          bool(cfg.get("emaFilter", True)),
            "pullbackTolerance":  float(cfg.get("pullbackTolerance", 0.015)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "cb_key": cb_key, "cb_secret": cb_secret,
    })
    alloc = float(cfg.get("allocPct", 0.20)) * 100
    sl    = float(cfg.get("stopLoss", 0.03)) * 100
    vol   = float(cfg.get("minVolume", 0)) / 1_000_000
    mode  = "REALE" if cfg.get("realMode", False) else "SIMULAZIONE"
    ema_s = "ON" if cfg.get("emaFilter", True) else "OFF"
    ptol  = float(cfg.get("pullbackTolerance", 0.015)) * 100
    add_log(state, "info", "AVVIO",
        f"${capital:.0f} | {mode} | Alloc: {alloc:.0f}% | SL: {sl:.1f}% | "
        f"Vol: ${vol:.0f}M | EMA: {ema_s} | Pullback tol: {ptol:.1f}%"
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
