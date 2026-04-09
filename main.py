import asyncio
import os
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BINANCE_BASE = "https://api.binance.com"

SYM_META = {
    "BTCUSDT":  {"symbol": "BTC",  "icon": "B"},
    "ETHUSDT":  {"symbol": "ETH",  "icon": "E"},
    "SOLUSDT":  {"symbol": "SOL",  "icon": "S"},
    "BNBUSDT":  {"symbol": "BNB",  "icon": "B"},
    "XRPUSDT":  {"symbol": "XRP",  "icon": "X"},
    "ADAUSDT":  {"symbol": "ADA",  "icon": "A"},
    "AVAXUSDT": {"symbol": "AVAX", "icon": "A"},
    "DOTUSDT":  {"symbol": "DOT",  "icon": "D"},
    "LINKUSDT": {"symbol": "LINK", "icon": "L"},
    "MATICUSDT":{"symbol": "MATIC","icon": "M"},
    "UNIUSDT":  {"symbol": "UNI",  "icon": "U"},
    "NEARUSDT": {"symbol": "NEAR", "icon": "N"},
    "INJUSDT":  {"symbol": "INJ",  "icon": "I"},
    "APTUSDT":  {"symbol": "APT",  "icon": "A"},
    "ARBUSDT":  {"symbol": "ARB",  "icon": "R"},
    "OPUSDT":   {"symbol": "OP",   "icon": "O"},
    "ATOMUSDT": {"symbol": "ATOM", "icon": "A"},
}

market_data = {}
for pair, meta in SYM_META.items():
    market_data[meta["symbol"]] = {
        "price": 0.0, "change1h": 0.0, "change24h": 0.0,
        "priceHistory": [], "icon": meta["icon"]
    }

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
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            for t in res.json():
                meta = SYM_META.get(t["symbol"])
                if not meta:
                    continue
                sym = meta["symbol"]
                price = float(t["lastPrice"])
                change24h = float(t["priceChangePercent"])
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
    cfg   = agent_state["config"]
    price = sym_data["price"]
    sym   = sym_data["symbol"]

    alloc_pct = cfg.get("allocPct", 0.20)           # % capitale per trade
    size = agent_state["capital"] * alloc_pct
    size = min(size, agent_state["currentCapital"])  # non superare il disponibile
    if size < 1:
        return

    sl_pct = cfg.get("stopLoss", 0.03)
    tp_pct = cfg.get("takeProfit", 0.06)

    agent_state["currentCapital"] -= size
    pos = {
        "symbol": sym,
        "icon": sym_data["icon"],
        "entryPrice": price,
        "currentPrice": price,
        "highPrice": price,
        "size": size,
        "entryTime": datetime.now().isoformat(),
        "stopPrice": price * (1 - sl_pct),
        "tpPrice": price * (1 + tp_pct),
    }
    agent_state["positions"].append(pos)
    add_log("buy", "ACQUISTO",
        f"{sym} @ ${price:.4f} | Size: ${size:.0f} | "
        f"SL: {sl_pct*100:.1f}% | TP: {tp_pct*100:.1f}%"
    )

def exit_position(pos: dict, reason: str):
    cur   = pos["currentPrice"]
    pnl   = (cur - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct   = (cur - pos["entryPrice"]) / pos["entryPrice"] * 100
    dur   = (datetime.now() - datetime.fromisoformat(pos["entryTime"])).total_seconds() / 60

    agent_state["currentCapital"] += pos["size"] + pnl
    agent_state["tradeCount"] += 1
    if pnl > 0:
        agent_state["wins"] += 1

    cfg = agent_state["config"]
    agent_state["cooldowns"][pos["symbol"]] = (
        datetime.now().timestamp() + cfg.get("cooldown", 1) * 3600
    ) * 1000

    agent_state["trades"].append({
        "symbol": pos["symbol"], "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur,
        "pnl": pnl, "pct": pct,
        "time": datetime.now().isoformat(),
        "entryTime": pos["entryTime"],
        "durationMin": round(dur, 1),
        "size": pos["size"],
    })

    agent_state["positions"] = [p for p in agent_state["positions"] if p is not pos]
    add_log("sell", reason,
        f"{pos['symbol']} @ ${cur:.4f} | {pnl:+.2f}$ ({pct:+.2f}%) | {dur:.0f} min"
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
            exit_position(p, "SESSIONE SCADUTA")
        add_log("info", "FINE SESSIONE", "Durata massima raggiunta.")
        return

    # check exits
    for pos in list(agent_state["positions"]):
        cur = pos["currentPrice"]
        if cur <= pos["stopPrice"]:
            exit_position(pos, "STOP LOSS")
        elif cur >= pos["tpPrice"]:
            exit_position(pos, "TAKE PROFIT")

    # how many more positions can we open?
    alloc_pct   = cfg.get("allocPct", 0.20)
    max_pos     = max(1, int(round(1 / alloc_pct)))   # e.g. 20% → 5
    open_syms   = {p["symbol"] for p in agent_state["positions"]}
    slots       = max_pos - len(agent_state["positions"])

    if slots <= 0 or agent_state["currentCapital"] < agent_state["capital"] * alloc_pct * 0.5:
        # update pnl history and return
        _update_pnl()
        return

    # rank coins by 24h change (real Binance data), skip cooldowns and already open
    prices_ok = [sym for sym, d in market_data.items() if d["price"] > 0]
    ranked = sorted(
        [
            d for sym, d in market_data.items()
            if d["price"] > 0
            and sym not in open_syms
            and (agent_state["cooldowns"].get(sym, 0) < datetime.now().timestamp() * 1000)
        ],
        key=lambda d: d["change24h"],
        reverse=True
    )

    min_mom = cfg.get("minMomentum", 0.05)
    candidates = [d for d in ranked if d["change24h"] >= min_mom]

    add_log("info", "SCAN",
        f"Top3: {[(d['symbol'], round(d['change24h'],2)) for d in ranked[:3]]} | "
        f"Candidati: {len(candidates)} | Slot: {slots} | Prezzi: {len(prices_ok)}"
    )

    for d in candidates[:slots]:
        await enter_position(d)

def _update_pnl():
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
        key=lambda x: x["change1h"], reverse=True
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
            "allocPct":     float(cfg.get("allocPct", 0.20)),
            "stopLoss":     float(cfg.get("stopLoss", 0.03)),
            "takeProfit":   float(cfg.get("takeProfit", 0.06)),
            "cooldown":     float(cfg.get("cooldown", 1)),
            "minMomentum":  float(cfg.get("minMomentum", 0.05)),
            "sessionDuration": int(cfg.get("sessionDuration", 8)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
    })
    alloc = float(cfg.get("allocPct", 0.20)) * 100
    sl    = float(cfg.get("stopLoss", 0.03)) * 100
    tp    = float(cfg.get("takeProfit", 0.06)) * 100
    add_log("info", "AVVIO",
        f"${capital:.0f} | Alloc: {alloc:.0f}% | SL: {sl:.1f}% | TP: {tp:.1f}%"
    )
    return {"ok": True}

@app.post("/stop")
def stop_agent():
    if not agent_state["running"]:
        return {"error": "Not running"}
    agent_state["running"] = False
    for p in list(agent_state["positions"]):
        exit_position(p, "STOP MANUALE")
    pnl = agent_state["currentCapital"] - agent_state["capital"]
    add_log("info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.post("/close_position/{symbol}")
def close_symbol(symbol: str):
    pos = next((p for p in agent_state["positions"] if p["symbol"] == symbol), None)
    if not pos:
        return {"error": f"No position on {symbol}"}
    exit_position(pos, "CHIUSURA MANUALE")
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
