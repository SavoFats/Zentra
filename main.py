import asyncio
import os
import time
import jwt
import hashlib
import json
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BINANCE_BASE = "https://api.binance.com"
COINBASE_BASE = "https://api.coinbase.com"

# Credenziali Coinbase da variabili d'ambiente
COINBASE_API_KEY     = os.environ.get("CB_KEY", "")
COINBASE_PRIVATE_KEY = os.environ.get("CB_SECRET", "")

def make_coinbase_jwt(method: str, path: str) -> str:
    """Genera JWT per autenticazione Coinbase Advanced API"""
    import re
    key = COINBASE_PRIVATE_KEY.replace("\\n", "\n")
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
    token = make_coinbase_jwt(method, path)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=15) as client:
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

# ── binance ───────────────────────────────────────────────────────────────────

async def fetch_prices():
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            tickers = res.json()

        for t in tickers:
            pair = t["symbol"]
            # solo coppie USDT
            if not pair.endswith("USDT"):
                continue
            # filtro volume
            try:
                vol_usdt = float(t["quoteVolume"])
            except:
                continue
            min_vol = agent_state["config"].get("minVolume", 10_000_000)
            if vol_usdt < min_vol:
                continue

            sym = pair[:-4]  # es. BTCUSDT -> BTC
            price = float(t["lastPrice"])
            change24h = float(t["priceChangePercent"])

            if sym not in market_data:
                market_data[sym] = {
                    "price": 0.0, "change1h": 0.0, "change24h": 0.0,
                    "volume24h": 0.0, "priceHistory": [], "icon": sym[0]
                }

            hist = market_data[sym]["priceHistory"]
            hist.append(price)
            if len(hist) > 60:
                hist.pop(0)
            change1h = (
                (price - hist[0]) / hist[0] * 100
                if len(hist) >= 10 else change24h * 0.08
            )
            market_data[sym]["price"] = price
            market_data[sym]["change1h"] = change1h
            market_data[sym]["change24h"] = change24h
            market_data[sym]["volume24h"] = vol_usdt

            # update open positions
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
            product_id = f"{sym}-USD"
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
                add_log("info", "ERRORE", f"Ordine {sym} fallito: {result.get('error_response', {}).get('message', str(result))}")
                return
            # usa il prezzo reale dall'ordine se disponibile
            filled = result.get("success_response", {})
            actual_price = float(filled.get("average_filled_price", price)) or price
            add_log("buy", "ACQUISTO REALE", f"{sym} @ ${actual_price:.4f} | Size: ${size:.0f} | SL: {sl_pct*100:.1f}% | Trailing ON")
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
            qty_coin = pos["size"] / pos["entryPrice"]  # stima quantita'
            body = {
                "client_order_id": f"ca-exit-{sym}-{int(time.time())}",
                "product_id": f"{sym}-USD",
                "side": "SELL",
                "order_configuration": {
                    "market_market_ioc": {
                        "base_size": str(round(qty_coin, 8))
                    }
                }
            }
            result = await coinbase_request("POST", "/api/v3/brokerage/orders", body)
            if result.get("success") != True:
                add_log("info", "ERRORE", f"Vendita {sym} fallita: {result.get('error_response', {}).get('message', str(result))}")
            else:
                filled = result.get("success_response", {})
                cur = float(filled.get("average_filled_price", cur)) or cur
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

    # rank coins — filtro cooldown, posizioni aperte, solo simboli ASCII
    ranked = sorted(
        [
            {**d, "symbol": sym} for sym, d in market_data.items()
            if d["price"] > 0
            and sym not in open_syms
            and sym.isascii() and sym.isalnum()  # escludi coin con simboli strani
            and (agent_state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
        ],
        key=lambda d: d["change24h"],
        reverse=True
    )

    min_mom = cfg.get("minMomentum", 0.05)
    candidates = [
        d for d in ranked
        if d["change24h"] >= min_mom      # momentum 24h
        and d.get("change1h", 0) > 0      # sta salendo ADESSO (1h positivo)
    ]

    add_log("info", "SCAN",
        f"Top3: {[(d['symbol'], round(d['change24h'],2)) for d in ranked[:3]]} | "
        f"Candidati: {len(candidates)} | Slot: {slots} | Universe: {len(prices_ok)} | BTC1h: {btc_1h:+.2f}%"
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

async def background_loop():
    while True:
        try:
            await fetch_prices()
            await scan_and_trade()
            if agent_state["running"]:
                _update_pnl()
        except Exception as e:
            import traceback
            print(f"Loop error: {e}\n{traceback.format_exc()}")
        await asyncio.sleep(8)

# ── endpoints ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    asyncio.create_task(background_loop())

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
def stop_agent():
    if not agent_state["running"]:
        return {"error": "Not running"}
    agent_state["running"] = False
    for p in list(agent_state["positions"]):
        await exit_position(p, "STOP MANUALE")
    pnl = agent_state["currentCapital"] - agent_state["capital"]
    add_log("info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.post("/close_position/{symbol}")
def close_symbol(symbol: str):
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
    return {"status": "ok", "binance": any(d["price"] > 0 for d in market_data.values())}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
