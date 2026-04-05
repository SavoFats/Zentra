import asyncio
import json
import os
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== CONFIG =====
BINANCE_BASE = "https://api.binance.com"

TRACKED_PAIRS = [
    "BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT",
    "ADAUSDT", "AVAXUSDT", "DOTUSDT", "LINKUSDT",
    "MATICUSDT", "UNIUSDT", "NEARUSDT", "INJUSDT",
    "APTUSDT", "ARBUSDT", "OPUSDT", "ATOMUSDT",
]

SYM_META = {
    "BTCUSDT":  {"symbol": "BTC",   "icon": "₿",  "vol": "high"},
    "ETHUSDT":  {"symbol": "ETH",   "icon": "Ξ",  "vol": "high"},
    "SOLUSDT":  {"symbol": "SOL",   "icon": "◎",  "vol": "high"},
    "BNBUSDT":  {"symbol": "BNB",   "icon": "B",  "vol": "high"},
    "XRPUSDT":  {"symbol": "XRP",   "icon": "✕",  "vol": "high"},
    "ADAUSDT":  {"symbol": "ADA",   "icon": "₳",  "vol": "med"},
    "AVAXUSDT": {"symbol": "AVAX",  "icon": "A",  "vol": "med"},
    "DOTUSDT":  {"symbol": "DOT",   "icon": "●",  "vol": "med"},
    "LINKUSDT": {"symbol": "LINK",  "icon": "⬡",  "vol": "med"},
    "MATICUSDT":{"symbol": "MATIC", "icon": "M",  "vol": "med"},
    "UNIUSDT":  {"symbol": "UNI",   "icon": "🦄", "vol": "med"},
    "NEARUSDT": {"symbol": "NEAR",  "icon": "N",  "vol": "low"},
    "INJUSDT":  {"symbol": "INJ",   "icon": "I",  "vol": "low"},
    "APTUSDT":  {"symbol": "APT",   "icon": "A",  "vol": "med"},
    "ARBUSDT":  {"symbol": "ARB",   "icon": "R",  "vol": "med"},
    "OPUSDT":   {"symbol": "OP",    "icon": "O",  "vol": "med"},
    "ATOMUSDT": {"symbol": "ATOM",  "icon": "⚛",  "vol": "med"},
}

# ===== IN-MEMORY STATE =====
market_data = {}
agent_state = {
    "running": False,
    "capital": 0.0,
    "currentCapital": 0.0,
    "position": None,
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

for pair, meta in SYM_META.items():
    market_data[meta["symbol"]] = {
        "price": 0.0, "change24h": 0.0, "change1h": 0.0,
        "priceHistory": [], "vol": meta["vol"], "icon": meta["icon"]
    }

# ===== BINANCE FETCH =====
async def fetch_binance_prices():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            tickers = res.json()
            for t in tickers:
                pair = t["symbol"]
                meta = SYM_META.get(pair)
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
                    (price - hist[max(0, len(hist) - 10)]) / hist[max(0, len(hist) - 10)] * 100
                    if len(hist) > 2 else change24h * 0.08
                )
                market_data[sym]["price"] = price
                market_data[sym]["change24h"] = change24h
                market_data[sym]["change1h"] = change1h
                pos = agent_state["position"]
                if pos and pos["symbol"] == sym:
                    pos["currentPrice"] = price
                    if price > pos["highPrice"]:
                        pos["highPrice"] = price
    except Exception as e:
        print(f"Binance fetch error: {e}")

# ===== TRADING LOGIC =====
def get_sorted_market(vol_filter="high", top_n=10):
    result = []
    for sym, d in market_data.items():
        if d["price"] == 0:
            continue
        if vol_filter == "high" and d["vol"] != "high":
            continue
        if vol_filter == "med" and d["vol"] == "low":
            continue
        cd = agent_state["cooldowns"].get(sym)
        in_cd = cd is not None and datetime.now().timestamp() * 1000 < cd
        # Use change1h if history is long enough, otherwise use change24h as proxy
        hist = d.get("priceHistory", [])
        mom = d["change1h"] if len(hist) >= 5 else d["change24h"] * 0.1
        result.append({
            "symbol": sym, "icon": d["icon"], "price": d["price"],
            "mom": mom, "change24h": d["change24h"],
            "vol": d["vol"], "inCooldown": in_cd
        })
    result.sort(key=lambda x: x["mom"], reverse=True)
    return result[:top_n]

def add_log(type_, label, desc):
    entry = {
        "type": type_, "label": label, "desc": desc,
        "time": datetime.now().strftime("%H:%M:%S")
    }
    agent_state["log"].insert(0, entry)
    if len(agent_state["log"]) > 100:
        agent_state["log"].pop()

def unrealized_pnl():
    pos = agent_state["position"]
    if not pos:
        return 0.0
    return (pos["currentPrice"] - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]

def enter_position(crypto):
    cfg = agent_state["config"]
    size = agent_state["currentCapital"] * cfg["posSize"]
    agent_state["currentCapital"] -= size
    agent_state["position"] = {
        "symbol": crypto["symbol"],
        "icon": crypto["icon"],
        "entryPrice": crypto["price"],
        "currentPrice": crypto["price"],
        "highPrice": crypto["price"],
        "size": size,
        "entryTime": datetime.now().isoformat(),
    }
    add_log("buy", "ACQUISTO",
        f"{crypto['symbol']} @ ${crypto['price']:.4f} | "
        f"Mom: {crypto['mom']:+.2f}% | 24h: {crypto['change24h']:+.2f}% | "
        f"Size: ${size:.2f}"
    )

def exit_position(reason, cur_price):
    pos = agent_state["position"]
    cfg = agent_state["config"]
    pnl = (cur_price - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct = (cur_price - pos["entryPrice"]) / pos["entryPrice"] * 100
    agent_state["currentCapital"] += pos["size"] + pnl
    agent_state["tradeCount"] += 1
    if pnl > 0:
        agent_state["wins"] += 1
    agent_state["trades"].append({
        "symbol": pos["symbol"], "reason": reason,
        "entryPrice": pos["entryPrice"], "exitPrice": cur_price,
        "pnl": pnl, "pct": pct, "time": datetime.now().isoformat()
    })
    agent_state["cooldowns"][pos["symbol"]] = (
        datetime.now().timestamp() + cfg["cooldown"] * 3600
    ) * 1000
    add_log("sell", reason,
        f"{pos['symbol']} @ ${cur_price:.4f} | "
        f"{pnl:+.2f}$ ({pct:+.2f}%)"
    )
    agent_state["position"] = None

def check_exit():
    pos = agent_state["position"]
    if not pos:
        return
    cfg = agent_state["config"]
    cur = pos["currentPrice"]
    trail_price = pos["highPrice"] * (1 - cfg["trailStop"])
    tp_price = pos["entryPrice"] * (1 + cfg["takeProfit"])
    if cur <= trail_price:
        exit_position("TRAILING STOP", cur)
    elif cur >= tp_price:
        exit_position("TAKE PROFIT", cur)

def scan_and_trade():
    if not agent_state["running"]:
        return
    cfg = agent_state["config"]
    elapsed_ms = (datetime.now().timestamp() - agent_state["sessionStart"]) * 1000
    if elapsed_ms >= agent_state["sessionDuration"]:
        agent_state["running"] = False
        if agent_state["position"]:
            exit_position("SESSIONE SCADUTA", agent_state["position"]["currentPrice"])
        add_log("info", "FINE SESSIONE", "Durata massima raggiunta.")
        return
    if agent_state["position"]:
        check_exit()
    else:
        market = get_sorted_market(cfg.get("volFilter", "high"), cfg.get("topN", 10))
        top3 = [(c["symbol"], round(c["mom"], 2)) for c in market[:3]]
        add_log("info", "SCAN", f"Top3: {top3} | Cercando mom>0")
        candidate = next((c for c in market if not c["inCooldown"] and c["mom"] > 0), None)
        if candidate:
            enter_position(candidate)
        else:
            add_log("info", "ATTESA", f"Nessuna crypto con momentum positivo trovata")
    # Calculate P&L AFTER position logic so values are always accurate
    unr = unrealized_pnl()
    pos = agent_state["position"]
    pos_value = pos["size"] if pos else 0
    total_value = agent_state["currentCapital"] + pos_value + unr
    pnl_val = total_value - agent_state["capital"]
    agent_state["pnlHistory"].append({
        "t": (datetime.now().timestamp() - agent_state["sessionStart"]) / 60,
        "v": pnl_val
    })
    if len(agent_state["pnlHistory"]) > 500:
        agent_state["pnlHistory"].pop(0)

# ===== BACKGROUND LOOP =====
async def background_loop():
    while True:
        await fetch_binance_prices()
        scan_and_trade()
        await asyncio.sleep(8)

@app.on_event("startup")
async def startup():
    asyncio.create_task(background_loop())

# ===== ENDPOINTS =====
@app.get("/status")
def get_status():
    unr = unrealized_pnl()
    pos = agent_state["position"]
    pos_value = pos["size"] if pos else 0
    total_value = agent_state["currentCapital"] + pos_value + unr
    pnl = total_value - agent_state["capital"]
    pct = pnl / agent_state["capital"] * 100 if agent_state["capital"] > 0 else 0
    wr = (agent_state["wins"] / agent_state["tradeCount"] * 100) if agent_state["tradeCount"] > 0 else 0
    remaining = 0
    if agent_state["running"] and agent_state["sessionStart"]:
        elapsed = (datetime.now().timestamp() - agent_state["sessionStart"]) * 1000
        remaining = max(0, agent_state["sessionDuration"] - elapsed)
    return {
        "running": agent_state["running"],
        "capital": agent_state["capital"],
        "currentCapital": agent_state["currentCapital"],
        "pnl": pnl,
        "pct": pct,
        "tradeCount": agent_state["tradeCount"],
        "winRate": wr,
        "position": agent_state["position"],
        "remainingMs": remaining,
        "pnlHistory": agent_state["pnlHistory"][-100:],
        "log": agent_state["log"][:30],
    }

@app.get("/market")
def get_market():
    cfg = agent_state["config"]
    market = get_sorted_market(cfg.get("volFilter", "high"), cfg.get("topN", 12))
    return {"market": market}

@app.get("/trades")
def get_trades():
    return {"trades": agent_state["trades"]}

@app.post("/start")
async def start_agent(body: dict):
    if agent_state["running"]:
        return {"error": "Already running"}
    cfg = body.get("config", {})
    capital = float(cfg.get("capital", 1000))
    agent_state.update({
        "running": True,
        "capital": capital,
        "currentCapital": capital,
        "position": None,
        "pnlHistory": [{"t": 0, "v": 0}],
        "sessionStart": datetime.now().timestamp(),
        "sessionDuration": int(cfg.get("sessionDuration", 8)) * 3600 * 1000,
        "config": {
            "posSize": float(cfg.get("posSize", 0.8)),
            "momentumWindow": int(cfg.get("momentumWindow", 2)),
            "topN": int(cfg.get("topN", 10)),
            "volFilter": cfg.get("volFilter", "high"),
            "trailStop": float(cfg.get("trailStop", 0.08)),
            "takeProfit": float(cfg.get("takeProfit", 0.15)),
            "cooldown": int(cfg.get("cooldown", 2)),
            "sessionDuration": int(cfg.get("sessionDuration", 8)),
        },
        "cooldowns": {},
        "tradeCount": 0,
        "wins": 0,
        "trades": [],
        "log": [],
    })
    add_log("info", "AVVIO",
        f"${capital:.0f} USDT | Stop {float(cfg.get('trailStop',0.08))*100:.0f}% | "
        f"TP {float(cfg.get('takeProfit',0.15))*100:.0f}% | CD {cfg.get('cooldown',2)}h"
    )
    return {"ok": True}

@app.post("/close_position")
def close_position():
    pos = agent_state["position"]
    if not pos:
        return {"error": "No position open"}
    exit_position("CHIUSURA MANUALE", pos["currentPrice"])
    return {"ok": True}

@app.post("/stop")
def stop_agent():
    if not agent_state["running"]:
        return {"error": "Not running"}
    agent_state["running"] = False
    pos = agent_state["position"]
    if pos:
        exit_position("STOP MANUALE", pos["currentPrice"])
    pnl = agent_state["currentCapital"] - agent_state["capital"]
    add_log("info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.get("/health")
def health():
    prices_ok = any(d["price"] > 0 for d in market_data.values())
    return {"status": "ok", "binance": prices_ok}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
