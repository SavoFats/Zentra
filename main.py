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

# Database pool
db_pool = None

async def get_db():
    return db_pool

# Auth
security = HTTPBearer()

def create_token(user_id: int) -> str:
    import base64
    payload = f"{user_id}:{int(time.time()) + 86400 * 30}"  # 30 giorni
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

# Pydantic models
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

# Credenziali Coinbase da variabili d'ambiente
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

COINBASE_API_KEY     = os.environ.get("CB_KEY", "")
COINBASE_PRIVATE_KEY = os.environ.get("CB_SECRET", "")

def make_coinbase_jwt(method: str, path: str) -> str:
    """Genera JWT per autenticazione Coinbase Advanced API"""
    import re
    # Gestisce sia \n letterali che newline reali
    key = COINBASE_PRIVATE_KEY
    if '\\n' in key:
        key = key.replace('\\n', '\n')
    elif '\n' not in key and 'BEGIN' in key:
        # prova a ricostruire i newline dai delimitatori PEM
        key = key.replace('-----BEGIN EC PRIVATE KEY----- ', '-----BEGIN EC PRIVATE KEY-----\n')
        key = key.replace(' -----END EC PRIVATE KEY-----', '\n-----END EC PRIVATE KEY-----')
    payload = {
        "sub": COINBASE_API_KEY,
        "iss": "cdp",
        "nbf": int(time.time()),
        "exp": int(time.time()) + 120,
        "uri": f"{method} api.coinbase.com{path}",
    }
    token = jwt.encode(payload, key, algorithm="ES256",
                       headers={"kid": COINBASE_API_KEY, "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:16]})
    return token

async def coinbase_request(method: str, path: str, body: dict = None) -> dict:
    """Esegue una richiesta autenticata all'API Coinbase Advanced"""
    # JWT usa solo il path senza query string
    jwt_path = path.split("?")[0]
    token = make_coinbase_jwt(method, jwt_path)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            r = await client.get(f"{COINBASE_BASE}{path}", headers=headers)
        else:
            r = await client.post(f"{COINBASE_BASE}{path}", headers=headers, json=body)
    return r.json()

# universe dinamico — popolato da fetch_prices()
market_data = {}  # sym -> {price, change1h, change24h, volume24h, priceHistory, icon}

agent_state = {
    "running": False,
    "capital": 0.0,
    "currentCapital": 0.0,
    "positions": [],
    "pnlHistory": [],
    "sessionStart": None,
    "sessionDuration": 0,
    "config": {},
    "cooldowns": {},
    "tradeCount": 0,
    "wins": 0,
    "trades": [],
    "log": [],
}

# ── helpers ──────────────────────────────────────────────────────────────────

def add_log(type_, label, desc):
    agent_state["log"].insert(0, {
        "type": type_, "label": label, "desc": desc,
        "time": datetime.now().strftime("%H:%M:%S")
    })
    if len(agent_state["log"]) > 200:
        agent_state["log"].pop()

def unrealized_pnl():
    return sum(
        (p["currentPrice"] - p["entryPrice"]) / p["entryPrice"] * p["size"]
        for p in agent_state["positions"]
    )

# ── coinbase ─────────────────────────────────────────────────────────────────

STABLES = {'USDT','USDC','BUSD','DAI','FDUSD','TUSD','USDP','GUSD','FRAX',
           'LUSD','SUSD','EUR','GBP','USD','USDD','USTC','PAX','CBBTC','WBTC'}

# Coin con logo verificato — fallback finche non troviamo campo logo Coinbase
LOGO_APPROVED = {
    'BTC','ETH','SOL','BNB','XRP','ADA','AVAX','DOT','LINK','MATIC','UNI','NEAR',
    'INJ','APT','ARB','OP','ATOM','DOGE','SHIB','LTC','TON','TRX','HBAR','VET',
    'FIL','ALGO','ETC','AAVE','GRT','MKR','SNX','CRV','LDO','RUNE','FTM','ENJ',
    'ENA','RENDER','RNDR','JUP','PYTH','SUI','SEI','TAO','WLD','PEPE','FLOKI',
    'BONK','WIF','RAVE','CTSI','IOTX','NKN','DRIFT','XLM','SAND','MANA','AXS',
    'CHZ','EGLD','THETA','ZEC','BAT','ZRX','COMP','YFI','SUSHI','SKL','ANKR',
    'STORJ','OGN','RLC','LOOM','1INCH','ICP','FET','OCEAN','IMX','GRT','BLUR',
    'ENS','TIA','DYDX','LRC','FLOW','MINA','APE','GALA','YFI','QNT','EGLD',
}

# Cache prodotti Coinbase — aggiornata ogni ora
# sym -> {price, change24h, volume24h, logo_url}
_coinbase_products: dict = {}
_products_last_update: float = 0

async def refresh_coinbase_products():
    """Scarica lista prodotti, prezzi e loghi da Coinbase Advanced API"""
    global _coinbase_products, _products_last_update
    try:
        result = await coinbase_request("GET", "/api/v3/brokerage/market/products?product_type=SPOT&limit=500")
        products = result.get("products", [])
        new_products = {}
        for p in products:
            if p.get("quote_currency_id") not in ("USD", "USDC"):
                continue
            if p.get("status") != "online":
                continue
            sym = p.get("base_currency_id", "")
            if not sym or not sym.isascii() or not sym.isalpha():
                continue
            if sym in STABLES:
                continue
            try:
                price = float(p.get("price", 0) or 0)
                change24h = float(p.get("price_percentage_change_24h", 0) or 0)
                vol = float(p.get("volume_24h", 0) or 0) * price
                # logo direttamente da Coinbase
                logo_url = p.get("base_currency_details", {}).get("image_url", "") or ""
                # fallback: prova altri campi dove Coinbase potrebbe mettere il logo
                if not logo_url:
                    logo_url = p.get("base_asset_image", "") or p.get("image_url", "") or ""
            except:
                continue
            if price <= 0:
                continue
            # debug: stampa struttura primo prodotto
            if sym == "BTC":
                btc_details = p.get("base_currency_details", {})
                print(f"DEBUG BTC all keys: {list(p.keys())}")
                print(f"DEBUG BTC base_currency_details: {btc_details}")
            if not logo_url:
                continue
            new_products[sym] = {"price": price, "change24h": change24h, "volume24h": vol, "logo_url": logo_url}
        if new_products:
            _coinbase_products = new_products
            _products_last_update = time.time()
            print(f"Coinbase products aggiornati: {len(_coinbase_products)} coin")
    except Exception as e:
        print(f"Products refresh error: {e}")

async def fetch_prices():
    global _products_last_update
    try:
        # API pubblica Coinbase Exchange — no autenticazione necessaria
        async with httpx.AsyncClient(timeout=15) as client:
            # Ticker 24h per tutti i prodotti USD
            r = await client.get("https://api.exchange.coinbase.com/products")
            all_products = r.json()

        # Filtra solo prodotti USD online
        usd_syms = {}
        for p in all_products:
            if not isinstance(p, dict): continue
            if p.get("quote_currency") != "USD": continue
            if p.get("status") != "online": continue
            sym = p.get("base_currency", "")
            if not sym or not sym.isascii() or not sym.isalpha(): continue
            if sym in STABLES: continue
            usd_syms[p["id"]] = sym  # es. "BTC-USD" -> "BTC"

        # Fetch stats 24h per tutti i prodotti in una chiamata
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get("https://api.exchange.coinbase.com/products/stats")
            # questo endpoint non esiste — usiamo ticker individuale via batch
            # invece usiamo Binance per i dati 24h ma filtriamo per coin Coinbase
            r2 = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            tickers = r2.json()

        # Mappa Binance ticker filtrato per coin Coinbase
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

            # aggiorna cache prodotti (logo vuoto per ora, gestito dal frontend)
            _coinbase_products[sym] = {"price": price, "change24h": change24h, "volume24h": vol_usd, "logo_url": ""}

            if sym not in market_data:
                market_data[sym] = {
                    "price": 0.0, "change1h": 0.0, "change24h": 0.0,
                    "volume24h": 0.0, "priceHistory": [], "icon": sym[0]
                }

            # change1h: usa priceHistory se ha >= 10 campioni (80+ secondi)
            # altrimenti stima proporzionale dal 24h
            hist = market_data[sym]["priceHistory"]
            hist.append(price)
            if len(hist) > 450:  # 450 * 8s = 1 ora esatta
                hist.pop(0)

            if len(hist) >= 10:
                # prezzo di ~1 ora fa (o il piu vecchio disponibile)
                price_1h_ago = hist[0]
                change1h = (price - price_1h_ago) / price_1h_ago * 100
            else:
                change1h = change24h * 0.04  # stima conservativa

            market_data[sym]["price"] = price
            market_data[sym]["change1h"] = change1h
            market_data[sym]["change24h"] = change24h
            market_data[sym]["volume24h"] = vol_usd

            for pos in agent_state["positions"]:
                if pos["symbol"] == sym:
                    pos["currentPrice"] = price
                    if price > pos["highPrice"]:
                        pos["highPrice"] = price

    except Exception as e:
        print(f"Fetch error: {e}")


async def fetch_atr_1h(symbol_usdt: str, periods: int = 14):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                f"{BINANCE_BASE}/api/v3/klines",
                params={"symbol": symbol_usdt, "interval": "1h", "limit": periods + 1}
            )
            klines = res.json()
            if len(klines) < periods + 1:
                return None
            trs = []
            for i in range(1, len(klines)):
                high = float(klines[i][2])
                low  = float(klines[i][3])
                prev = float(klines[i-1][4])
                trs.append(max(high - low, abs(high - prev), abs(low - prev)))
            return sum(trs[-periods:]) / periods
    except Exception as e:
        print(f"ATR error: {e}")
        return None

# ── trading ───────────────────────────────────────────────────────────────────

async def enter_position(sym_data: dict):
    cfg      = agent_state["config"]
    price    = sym_data["price"]
    sym      = sym_data["symbol"]
    is_real  = cfg.get("realMode", False)

    alloc_pct = cfg.get("allocPct", 0.20)
    size = agent_state["capital"] * alloc_pct
    size = min(size, agent_state["currentCapital"])
    if size < 1:
        return

    sl_pct = cfg.get("stopLoss", 0.03)

    # ── MODALITA' REALE ────────────────────────────────────────────────────────
    if is_real:
        try:
            # calcola quantita' coin da comprare
            qty = round(size / price, 8)
            product_id = f"{sym}-USDC"
            body = {
                "client_order_id": f"ca-{sym}-{int(time.time())}",
                "product_id": product_id,
                "side": "BUY",
                "order_configuration": {
                    "market_market_ioc": {
                        "quote_size": str(round(size, 2))  # spendi X USD
                    }
                }
            }
            result = await coinbase_request("POST", "/api/v3/brokerage/orders", body)
            if result.get("success") != True:
                err = result.get("error_response", {})
                err_msg = err.get("message", str(result))
                add_log("info", "ERRORE", f"Ordine {sym} fallito: {err_msg}")
                # se account non disponibile, metti cooldown lungo su questa coin
                if "account is not available" in str(result) or "not available" in err_msg:
                    agent_state["cooldowns"][sym] = (datetime.now().timestamp() + 3600) * 1000
                    add_log("info", "ESCLUSA", f"{sym} non disponibile su questo account — esclusa per 1h")
                return
            # usa il prezzo reale dall'ordine se disponibile
            filled = result.get("success_response", {})
            actual_price = float(filled.get("average_filled_price", price)) or price
            add_log("buy", "ACQUISTO REALE", f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | SL: {sl_pct*100:.1f}% | Trailing ON")
            await send_telegram("ACQUISTO REALE\n" + sym + " @ $" + f"{actual_price:.4f}" + "\nSize: $" + f"{size:.2f}" + " | SL: " + f"{sl_pct*100:.1f}" + "%")
        except Exception as e:
            add_log("info", "ERRORE", f"Coinbase error: {e}")
            return
    else:
        actual_price = price
        add_log("buy", "ACQUISTO SIM", f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | SL: {sl_pct*100:.1f}% | Trailing ON")

    agent_state["currentCapital"] -= size
    pos = {
        "symbol": sym,
        "icon": sym_data["icon"],
        "entryPrice": actual_price,
        "currentPrice": actual_price,
        "highPrice": actual_price,
        "size": size,
        "entryTime": datetime.now().isoformat(),
        "stopPrice": actual_price * (1 - sl_pct),
        "realMode": is_real,
    }
    agent_state["positions"].append(pos)

async def exit_position(pos: dict, reason: str):
    cur  = pos["currentPrice"]
    sym  = pos["symbol"]
    pnl  = (cur - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct  = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100
    dur  = (datetime.now() - datetime.fromisoformat(pos["entryTime"])).total_seconds() / 60

    # ── MODALITA' REALE ────────────────────────────────────────────────────────
    if pos.get("realMode", False):
        try:
            # leggi il saldo reale della coin da Coinbase
            accounts = await coinbase_request("GET", "/api/v3/brokerage/accounts")
            real_qty = 0.0
            for acc in accounts.get("accounts", []):
                if acc["currency"] == sym:
                    real_qty = float(acc["available_balance"]["value"])
                    break

            if real_qty <= 0:
                add_log("info", "ERRORE", f"Saldo {sym} su Coinbase: {real_qty} — vendita annullata")
            else:
                body = {
                    "client_order_id": f"ca-exit-{sym}-{int(time.time())}",
                    "product_id": f"{sym}-USDC",
                    "side": "SELL",
                    "order_configuration": {
                        "market_market_ioc": {
                            "base_size": str(round(real_qty, 8))
                        }
                    }
                }
                result = await coinbase_request("POST", "/api/v3/brokerage/orders", body)
                if result.get("success") != True:
                    add_log("info", "ERRORE", f"Vendita {sym} fallita: {result.get('error_response', {}).get('message', str(result))}")
                else:
                    filled = result.get("success_response", {})
                    cur = float(filled.get("average_filled_price", cur)) or cur
                    add_log("info", "VENDUTO", f"{sym} qty reale: {real_qty:.6f} @ ${cur:.4f}")
        except Exception as e:
            add_log("info", "ERRORE", f"Coinbase exit error: {e}")

    # ricalcola pnl con prezzo reale
    pnl = (cur - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100

    agent_state["currentCapital"] += pos["size"] + pnl
    agent_state["tradeCount"] += 1
    if pnl > 0:
        agent_state["wins"] += 1

    cfg = agent_state["config"]
    agent_state["cooldowns"][sym] = (
        datetime.now().timestamp() + cfg.get("cooldown", 1) * 3600
    ) * 1000

    agent_state["trades"].append({
        "symbol": sym, "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": pnl, "pct": pct,
        "time": datetime.now().isoformat(),
        "entryTime": pos["entryTime"],
        "durationMin": round(dur, 1),
        "size": pos["size"],
        "realMode": pos.get("realMode", False),
    })

    agent_state["positions"] = [p for p in agent_state["positions"] if p is not pos]
    mode = "REALE" if pos.get("realMode") else "SIM"
    add_log("sell", f"{reason} {mode}",
        f"{sym} @ ${cur:.4f} | {pnl:+.2f}$ ({pct:+.2f}%) | {dur:.0f} min"
    )
    if pos.get("realMode"):
        esito = "PROFITTO" if pnl >= 0 else "PERDITA"
        msg = "VENDITA REALE - " + esito + "\n" + sym + " @ $" + f"{cur:.4f}" + "\nP&L: " + f"{pnl:+.2f}" + "$ (" + f"{pct:+.2f}" + "%)\nDurata: " + f"{dur:.0f}" + " min | " + reason
        await send_telegram(msg)

# ── main loop ─────────────────────────────────────────────────────────────────

async def scan_and_trade():
    if not agent_state["running"]:
        return
    cfg = agent_state["config"]

    # session expired?
    elapsed_ms = (datetime.now().timestamp() - agent_state["sessionStart"]) * 1000
    if elapsed_ms >= agent_state["sessionDuration"]:
        agent_state["running"] = False
        for p in list(agent_state["positions"]):
            await exit_position(p, "SESSIONE SCADUTA")
        add_log("info", "FINE SESSIONE", "Durata massima raggiunta.")
        return

    # trailing stop dinamico + check exits
    for pos in list(agent_state["positions"]):
        cur = pos["currentPrice"]
        entry = pos["entryPrice"]
        profit_pct = (cur - entry) / entry * 100

        # aggiorna highPrice
        if cur > pos.get("highPrice", cur):
            pos["highPrice"] = cur
        high = pos["highPrice"]

        # trailing stop dinamico - lo stop sale mai scende
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

        # check uscita
        if cur <= pos["stopPrice"]:
            await exit_position(pos, "STOP LOSS")

    # how many more positions can we open?
    alloc_pct   = cfg.get("allocPct", 0.20)
    max_pos     = max(1, int(round(1 / alloc_pct)))   # e.g. 20% → 5
    open_syms   = {p["symbol"] for p in agent_state["positions"]}
    slots       = max_pos - len(agent_state["positions"])

    if slots <= 0 or agent_state["currentCapital"] < agent_state["capital"] * alloc_pct * 0.5:
        # update pnl history and return
        _update_pnl()
        return

    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]

    # ── FILTRO BTC ─────────────────────────────────────────────────────────────
    btc = market_data.get("BTC", {})
    btc_1h = btc.get("change1h", 0)
    btc_ok = btc_1h >= -0.3  # blocca se BTC sta scendendo > 0.3% nell'ultima ora
    if not btc_ok:
        add_log("info", "PAUSA",
            f"BTC {btc_1h:+.2f}% 1h — agente in attesa"
        )
        _update_pnl()
        return

    min_vol = cfg.get("minVolume", 10_000_000)

    # rank coins — filtro cooldown, posizioni aperte, volume, solo coin con logo approvato
    ranked = sorted(
        [
            {**d, "symbol": sym} for sym, d in market_data.items()
            if d["price"] > 0
            and d.get("volume24h", 0) >= min_vol   # filtro volume solo qui
            and sym not in open_syms
            and sym in _coinbase_products  # solo coin disponibili su Coinbase
            and (agent_state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
        ],
        key=lambda d: d["change24h"],
        reverse=True
    )

    min_mom = cfg.get("minMomentum", 0.0)
    candidates = [
        d for d in ranked
        if d.get("change1h", 0) >= min_mom   # momentum ultima ora (configurabile)
    ]

    top3_detail = [(d["symbol"], round(d["change24h"],2), round(d.get("change1h",0),2)) for d in ranked[:3]]
    # log coin con change1h positivo ma escluse dal filtro volume
    vol_blocked = [(sym, round(d.get("change1h",0),2), round(d.get("volume24h",0)/1e6,1)) 
                   for sym, d in market_data.items() 
                   if d.get("change1h",0) >= min_mom and d.get("volume24h",0) < min_vol][:3]
    add_log("info", "SCAN",
        f"Top3 (24h,1h): {top3_detail} | "
        f"Candidati: {len(candidates)} | Slot: {slots} | Universe: {len(prices_ok)} | BTC1h: {btc_1h:+.2f}%"
        + (f" | VolBlocked: {vol_blocked}" if vol_blocked else "")
    )

    for d in candidates[:slots]:
        await enter_position(d)

def _update_pnl():
    if not agent_state["sessionStart"]:
        return
    unr      = unrealized_pnl()
    pos_val  = sum(p["size"] for p in agent_state["positions"])
    total    = agent_state["currentCapital"] + pos_val + unr
    pnl_val  = total - agent_state["capital"]
    t        = (datetime.now().timestamp() - agent_state["sessionStart"]) / 60
    agent_state["pnlHistory"].append({"t": t, "v": pnl_val})
    if len(agent_state["pnlHistory"]) > 500:
        agent_state["pnlHistory"].pop(0)

# Telegram polling
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
            # solo comandi dal tuo chat
            if chat_id != str(TELEGRAM_CHAT_ID):
                continue
            if text.upper().startswith("/CLOSE"):
                parts = text.split()
                if len(parts) >= 2:
                    sym = parts[1].upper()
                    pos = next((p for p in agent_state["positions"] if p["symbol"] == sym), None)
                    if pos:
                        await exit_position(pos, "TELEGRAM")
                        await send_telegram("Posizione " + sym + " chiusa manualmente via Telegram")
                    else:
                        await send_telegram("Nessuna posizione aperta su " + sym)
            elif text.upper() == "/STATUS":
                pos_list = ", ".join([p["symbol"] for p in agent_state["positions"]]) or "nessuna"
                pnl = agent_state.get("pnl", 0)
                await send_telegram("Stato agente\nRunning: " + str(agent_state["running"]) + "\nPosizioni: " + pos_list + "\nP&L: $" + f"{pnl:.2f}")
            elif text.upper() == "/STOP":
                agent_state["running"] = False
                await send_telegram("Agente fermato via Telegram")
    except Exception as e:
        print(f"Telegram poll error: {e}")

async def background_loop():
    while True:
        try:
            await fetch_prices()
            await scan_and_trade()
            if agent_state["running"]:
                _update_pnl()
            await poll_telegram()
        except Exception as e:
            import traceback
            print(f"Loop error: {e}\n{traceback.format_exc()}")
        await asyncio.sleep(8)

# ── endpoints ─────────────────────────────────────────────────────────────────

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

@app.get("/status")
def get_status():
    unr     = unrealized_pnl()
    pos_val = sum(p["size"] for p in agent_state["positions"])
    total   = agent_state["currentCapital"] + pos_val + unr
    pnl     = total - agent_state["capital"]
    pct     = pnl / agent_state["capital"] * 100 if agent_state["capital"] > 0 else 0
    wr      = agent_state["wins"] / agent_state["tradeCount"] * 100 if agent_state["tradeCount"] > 0 else 0
    remaining = 0
    if agent_state["running"] and agent_state["sessionStart"]:
        elapsed   = (datetime.now().timestamp() - agent_state["sessionStart"]) * 1000
        remaining = max(0, agent_state["sessionDuration"] - elapsed)
    return {
        "running": agent_state["running"],
        "capital": agent_state["capital"],
        "currentCapital": agent_state["currentCapital"],
        "pnl": pnl, "pct": pct,
        "tradeCount": agent_state["tradeCount"],
        "winRate": wr,
        "positions": agent_state["positions"],
        "remainingMs": remaining,
        "pnlHistory": agent_state["pnlHistory"][-100:],
        "log": agent_state["log"][:40],
    }

@app.get("/market")
def get_market():
    result = sorted(
        [{"symbol": s, **d} for s, d in market_data.items() if d["price"] > 0],
        key=lambda x: x["change24h"], reverse=True
    )
    return {"market": result}

@app.get("/trades")
def get_trades():
    return {"trades": agent_state["trades"]}

@app.post("/start")
async def start_agent(body: dict):
    if agent_state["running"]:
        return {"error": "Already running"}
    cfg     = body.get("config", {})
    capital = float(cfg.get("capital", 1000))
    agent_state.update({
        "running": True,
        "capital": capital,
        "currentCapital": capital,
        "positions": [],
        "pnlHistory": [{"t": 0, "v": 0}],
        "sessionStart": datetime.now().timestamp(),
        "sessionDuration": int(cfg.get("sessionDuration", 8)) * 3600 * 1000,
        "config": {
            "allocPct":      float(cfg.get("allocPct", 0.20)),
            "stopLoss":      float(cfg.get("stopLoss", 0.03)),
            "cooldown":      float(cfg.get("cooldown", 1)),
            "minMomentum":   float(cfg.get("minMomentum", 0.05)),
            "minVolume":     float(cfg.get("minVolume", 10_000_000)),
            "sessionDuration": int(cfg.get("sessionDuration", 8)),
            "realMode":      bool(cfg.get("realMode", False)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
    })
    alloc = float(cfg.get("allocPct", 0.20)) * 100
    sl    = float(cfg.get("stopLoss", 0.03)) * 100

    vol   = float(cfg.get("minVolume", 10_000_000)) / 1_000_000
    mode  = "🔴 REALE" if cfg.get("realMode", False) else "⚪ SIMULAZIONE"
    add_log("info", "AVVIO",
        f"${capital:.0f} | {mode} | Alloc: {alloc:.0f}% | SL: {sl:.1f}% | Vol: ${vol:.0f}M"
    )
    return {"ok": True}

@app.post("/stop")
async def stop_agent():
    if not agent_state["running"]:
        return {"error": "Not running"}
    agent_state["running"] = False
    for p in list(agent_state["positions"]):
        await exit_position(p, "STOP MANUALE")
    pnl = agent_state["currentCapital"] - agent_state["capital"]
    add_log("info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.post("/close_position/{symbol}")
async def close_symbol(symbol: str):
    pos = next((p for p in agent_state["positions"] if p["symbol"] == symbol), None)
    if not pos:
        return {"error": f"No position on {symbol}"}
    await exit_position(pos, "CHIUSURA MANUALE")
    return {"ok": True}

@app.post("/chat")
async def chat(body: dict):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "API key non configurata"}
    positions = agent_state["positions"]
    pnl = agent_state["currentCapital"] - agent_state["capital"]
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

@app.get("/health")
def health():
    return {"status": "ok", "coinbase": any(d["price"] > 0 for d in market_data.values())}

@app.get("/test_coinbase")
async def test_coinbase():
    if not COINBASE_API_KEY:
        return {"ok": False, "error": "CB_KEY non configurata"}
    try:
        result = await coinbase_request("GET", "/api/v3/brokerage/accounts")
        accounts = result.get("accounts", [])
        balances = [
            {"currency": a["currency"], "available": a["available_balance"]["value"]}
            for a in accounts
            if float(a["available_balance"]["value"]) > 0
        ]
        return {"ok": True, "balances": balances}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/test_order_blur")
async def test_order_blur():
    """Testa un ordine minimo su TON-USD e mostra risposta completa"""
    try:
        body = {
            "client_order_id": f"ca-test-{int(time.time())}",
            "product_id": "BLUR-USDC",
            "side": "BUY",
            "order_configuration": {
                "market_market_ioc": {
                    "quote_size": "1.00"
                }
            }
        }
        result = await coinbase_request("POST", "/api/v3/brokerage/orders", body)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug_product")
async def debug_product():
    """Mostra struttura grezza del prodotto BTC-USD da Coinbase"""
    try:
        result = await coinbase_request("GET", "/api/v3/brokerage/market/products/BTC-USDC")
        return result
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug_key")
async def debug_key():
    key = COINBASE_PRIVATE_KEY
    return {
        "len": len(key),
        "has_literal_backslash_n": chr(92)+"n" in key,
        "has_real_newline": chr(10) in key,
        "first_50": key[:50],
        "lines": len(key.splitlines())
    }

@app.get("/logos")
async def get_logos():
    """Restituisce mappa sym->logo_url da CoinGecko per le coin approvate"""
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
        "VET":"https://assets.coingecko.com/coins/images/1167/small/VET_Token_Icon.png",
        "FIL":"https://assets.coingecko.com/coins/images/12817/small/filecoin.png",
        "ALGO":"https://assets.coingecko.com/coins/images/4380/small/download.png",
        "ETC":"https://assets.coingecko.com/coins/images/453/small/ethereum-classic-logo.png",
        "AAVE":"https://assets.coingecko.com/coins/images/12645/small/AAVE.png",
        "GRT":"https://assets.coingecko.com/coins/images/13397/small/Graph_Token.png",
        "MKR":"https://assets.coingecko.com/coins/images/1364/small/Mark_Maker.png",
        "SNX":"https://assets.coingecko.com/coins/images/3406/small/SNX.png",
        "CRV":"https://assets.coingecko.com/coins/images/12124/small/Curve.png",
        "LDO":"https://assets.coingecko.com/coins/images/13573/small/Lido_DAO.png",
        "RUNE":"https://assets.coingecko.com/coins/images/6595/small/Rune200x200.png",
        "FTM":"https://assets.coingecko.com/coins/images/4001/small/Fantom_round.png",
        "ENJ":"https://assets.coingecko.com/coins/images/1102/small/enjin-coin-logo.png",
        "ENA":"https://assets.coingecko.com/coins/images/36530/small/ethena.png",
        "RENDER":"https://assets.coingecko.com/coins/images/11636/small/rndr.png",
        "RNDR":"https://assets.coingecko.com/coins/images/11636/small/rndr.png",
        "JUP":"https://assets.coingecko.com/coins/images/34188/small/jup.png",
        "PYTH":"https://assets.coingecko.com/coins/images/31924/small/pyth.png",
        "SUI":"https://assets.coingecko.com/coins/images/26375/small/sui_asset.jpeg",
        "SEI":"https://assets.coingecko.com/coins/images/28205/small/Sei_Logo_-_Transparent.png",
        "TAO":"https://assets.coingecko.com/coins/images/28452/small/ARUsPeNQ_400x400.jpeg",
        "WLD":"https://assets.coingecko.com/coins/images/31069/small/worldcoin.jpeg",
        "PEPE":"https://assets.coingecko.com/coins/images/29850/small/pepe-token.jpeg",
        "FLOKI":"https://assets.coingecko.com/coins/images/16746/small/PNG_image.png",
        "BONK":"https://assets.coingecko.com/coins/images/28600/small/bonk.jpg",
        "WIF":"https://assets.coingecko.com/coins/images/33566/small/wif.png",
        "RAVE":"https://assets.coingecko.com/coins/images/25686/small/rave.png",
        "CTSI":"https://assets.coingecko.com/coins/images/11038/small/cartesi.png",
        "IOTX":"https://assets.coingecko.com/coins/images/3334/small/iotex-logo.png",
        "NKN":"https://assets.coingecko.com/coins/images/3375/small/nkn.png",
        "DRIFT":"https://assets.coingecko.com/coins/images/35254/small/drift.png",
        "XLM":"https://assets.coingecko.com/coins/images/100/small/Stellar_symbol_black_RGB.png",
        "SAND":"https://assets.coingecko.com/coins/images/12129/small/sandbox_logo.jpg",
        "MANA":"https://assets.coingecko.com/coins/images/878/small/decentraland-mana.png",
        "AXS":"https://assets.coingecko.com/coins/images/13029/small/axie_infinity_logo.png",
        "CHZ":"https://assets.coingecko.com/coins/images/8834/small/Chiliz.png",
        "EGLD":"https://assets.coingecko.com/coins/images/12335/small/egld-token-logo.png",
        "THETA":"https://assets.coingecko.com/coins/images/2538/small/theta-token-logo.png",
        "ZEC":"https://assets.coingecko.com/coins/images/486/small/circle-zcash-color.png",
        "BAT":"https://assets.coingecko.com/coins/images/677/small/basic-attention-token.png",
        "ZRX":"https://assets.coingecko.com/coins/images/863/small/0x.png",
        "COMP":"https://assets.coingecko.com/coins/images/10775/small/COMP.png",
        "YFI":"https://assets.coingecko.com/coins/images/11849/small/yfi-192x192.png",
        "SUSHI":"https://assets.coingecko.com/coins/images/12271/small/512x512_Logo_no_chop.png",
        "SKL":"https://assets.coingecko.com/coins/images/13245/small/SKALE_token_300x300.png",
        "ANKR":"https://assets.coingecko.com/coins/images/8710/small/Ankr.png",
        "STORJ":"https://assets.coingecko.com/coins/images/949/small/storj.png",
        "OGN":"https://assets.coingecko.com/coins/images/3296/small/op.jpg",
        "RLC":"https://assets.coingecko.com/coins/images/821/small/iExec_RLC_icon_Hex_Black.png",
        "LOOM":"https://assets.coingecko.com/coins/images/3387/small/1_QGdkBrYnqEADO-8Qavqxvg.png",
        "ICP":"https://assets.coingecko.com/coins/images/14495/small/Internet_Computer_logo.png",
        "FET":"https://assets.coingecko.com/coins/images/5681/small/Fetch.jpg",
        "IMX":"https://assets.coingecko.com/coins/images/17233/small/imx.png",
        "BLUR":"https://assets.coingecko.com/coins/images/28453/small/blur.png",
        "ENS":"https://assets.coingecko.com/coins/images/19785/small/acatxTm8_400x400.jpg",
        "DYDX":"https://assets.coingecko.com/coins/images/17500/small/hjnIm9bV.jpg",
        "LRC":"https://assets.coingecko.com/coins/images/5765/small/loopring.png",
        "FLOW":"https://assets.coingecko.com/coins/images/13446/small/5f6294c0c7a8cda55cb1c936_Flow_Wordmark.png",
        "MINA":"https://assets.coingecko.com/coins/images/15628/small/JM4_vQ34_400x400.png",
        "APE":"https://assets.coingecko.com/coins/images/24383/small/apecoin.jpg",
        "QNT":"https://assets.coingecko.com/coins/images/3370/small/5ZOu7brX_400x400.jpg",
        "1INCH":"https://assets.coingecko.com/coins/images/13469/small/1inch-token.png",
    }
    return LOGO_URLS

@app.get("/debug_products")
async def debug_products():
    """Debug: mostra i prodotti USD tradabili su Coinbase Advanced"""
    if not COINBASE_API_KEY:
        return {"error": "CB_KEY non configurata"}
    try:
        result = await coinbase_request("GET", "/api/v3/brokerage/market/products?product_type=SPOT&limit=500")
        products = result.get("products", [])
        usd = [
            {"sym": p.get("base_currency_id"), "status": p.get("status"), "price": p.get("price")}
            for p in products
            if p.get("quote_currency_id") == "USD"
        ]
        return {"total": len(usd), "products": usd}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
