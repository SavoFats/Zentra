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

TRACKED_PAIRS = [
    "BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT",
    "ADAUSDT", "AVAXUSDT", "DOTUSDT", "LINKUSDT",
    "MATICUSDT", "UNIUSDT", "NEARUSDT", "INJUSDT",
    "APTUSDT", "ARBUSDT", "OPUSDT", "ATOMUSDT",
]

SYM_META = {
    "BTCUSDT":  {"symbol": "BTC",  "icon": "B", "vol": "high"},
    "ETHUSDT":  {"symbol": "ETH",  "icon": "E", "vol": "high"},
    "SOLUSDT":  {"symbol": "SOL",  "icon": "S", "vol": "high"},
    "BNBUSDT":  {"symbol": "BNB",  "icon": "B", "vol": "high"},
    "XRPUSDT":  {"symbol": "XRP",  "icon": "X", "vol": "high"},
    "ADAUSDT":  {"symbol": "ADA",  "icon": "A", "vol": "med"},
    "AVAXUSDT": {"symbol": "AVAX", "icon": "A", "vol": "med"},
    "DOTUSDT":  {"symbol": "DOT",  "icon": "D", "vol": "med"},
    "LINKUSDT": {"symbol": "LINK", "icon": "L", "vol": "med"},
    "MATICUSDT":{"symbol": "MATIC","icon": "M", "vol": "med"},
    "UNIUSDT":  {"symbol": "UNI",  "icon": "U", "vol": "med"},
    "NEARUSDT": {"symbol": "NEAR", "icon": "N", "vol": "low"},
    "INJUSDT":  {"symbol": "INJ",  "icon": "I", "vol": "low"},
    "APTUSDT":  {"symbol": "APT",  "icon": "A", "vol": "med"},
    "ARBUSDT":  {"symbol": "ARB",  "icon": "R", "vol": "med"},
    "OPUSDT":   {"symbol": "OP",   "icon": "O", "vol": "med"},
    "ATOMUSDT": {"symbol": "ATOM", "icon": "A", "vol": "med"},
}

market_data = {}
agent_state = {
    "running": False, "capital": 0.0, "currentCapital": 0.0,
    "position": None, "pnlHistory": [], "sessionStart": None,
    "sessionDuration": 0, "config": {}, "cooldowns": {},
    "tradeCount": 0, "wins": 0, "trades": [], "log": [],
    "consecutiveLosses": 0,
    "circuitBreakerUntil": None,
    "circuitBreakerTripped": False,
}

for pair, meta in SYM_META.items():
    market_data[meta["symbol"]] = {
        "price": 0.0, "change24h": 0.0, "change1h": 0.0,
        "priceHistory": [], "volumeHistory": [],
        "volume24h": 0.0, "vol": meta["vol"], "icon": meta["icon"],
        "consecutiveUps": 0,  # counter for speculative mode
    }

async def fetch_atr_1h(symbol_usdt: str, periods: int = 14) -> float | None:
    """Fetch real ATR from Binance 1h klines. Returns ATR in price units."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                f"{BINANCE_BASE}/api/v3/klines",
                params={"symbol": symbol_usdt, "interval": "1h", "limit": periods + 1}
            )
            klines = res.json()
            if len(klines) < periods + 1:
                return None
            # True Range = max(high-low, abs(high-prev_close), abs(low-prev_close))
            trs = []
            for i in range(1, len(klines)):
                high = float(klines[i][2])
                low = float(klines[i][3])
                prev_close = float(klines[i-1][4])
                tr = max(high - low, abs(high - prev_close), abs(low - prev_close))
                trs.append(tr)
            atr = sum(trs[-periods:]) / periods
            return atr
    except Exception as e:
        print(f"ATR fetch error: {e}")
        return None

async def fetch_binance_prices():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(f"{BINANCE_BASE}/api/v3/ticker/24hr")
            tickers = res.json()
            for t in tickers:
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
                    (price - hist[max(0, len(hist)-10)]) / hist[max(0, len(hist)-10)] * 100
                    if len(hist) >= 5 else change24h * 0.08
                )
                market_data[sym]["price"] = price
                market_data[sym]["change24h"] = change24h
                market_data[sym]["change1h"] = change1h
                # Track consecutive up ticks for speculative mode
                if len(hist) >= 2:
                    if price > hist[-2]:
                        market_data[sym]["consecutiveUps"] = market_data[sym].get("consecutiveUps", 0) + 1
                    else:
                        market_data[sym]["consecutiveUps"] = 0
                # Track volume
                vol = float(t.get("quoteVolume", 0))
                market_data[sym]["volume24h"] = vol
                vh = market_data[sym]["volumeHistory"]
                vh.append(vol)
                if len(vh) > 60:
                    vh.pop(0)
                pos = agent_state["position"]
                if pos and pos["symbol"] == sym:
                    pos["currentPrice"] = price
                    if price > pos["highPrice"]:
                        pos["highPrice"] = price
    except Exception as e:
        print(f"Binance fetch error: {e}")

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
        hist = d.get("priceHistory", [])
        mom = d["change1h"] if len(hist) >= 5 else d["change24h"] * 0.1
        result.append({
            "symbol": sym, "icon": d["icon"], "price": d["price"],
            "mom": mom, "change24h": d["change24h"],
            "vol": d["vol"], "inCooldown": in_cd
        })
    result.sort(key=lambda x: x["mom"], reverse=True)
    return result[:top_n]

def calc_atr(symbol, periods=14):
    """Calculate Average True Range from price history."""
    hist = market_data.get(symbol, {}).get("priceHistory", [])
    if len(hist) < periods + 1:
        return None
    ranges = [abs(hist[i] - hist[i-1]) for i in range(1, len(hist))]
    atr = sum(ranges[-periods:]) / periods
    return atr

def calc_adx(symbol, periods=14):
    """Simplified ADX from price history. Returns 0-100."""
    hist = market_data.get(symbol, {}).get("priceHistory", [])
    if len(hist) < periods + 2:
        return 0
    ups = [max(hist[i] - hist[i-1], 0) for i in range(1, len(hist))]
    downs = [max(hist[i-1] - hist[i], 0) for i in range(1, len(hist))]
    recent_ups = ups[-periods:]
    recent_downs = downs[-periods:]
    avg_up = sum(recent_ups) / periods
    avg_down = sum(recent_downs) / periods
    if avg_up + avg_down == 0:
        return 0
    dx = abs(avg_up - avg_down) / (avg_up + avg_down) * 100
    return dx

def calc_ema(prices, period):
    """Calculate EMA for a list of prices."""
    if len(prices) < period:
        return None
    k = 2 / (period + 1)
    ema = sum(prices[:period]) / period
    for price in prices[period:]:
        ema = price * k + ema * (1 - k)
    return ema

def ema_aligned(symbol):
    """Check if EMA 9 > EMA 21 (bullish alignment)."""
    hist = market_data.get(symbol, {}).get("priceHistory", [])
    if len(hist) < 21:
        return True  # not enough data, don't block entry
    ema9 = calc_ema(hist, 9)
    ema21 = calc_ema(hist, 21)
    if ema9 is None or ema21 is None:
        return True
    return ema9 > ema21

def volume_ok(symbol):
    """Check if current volume is above 1.2x average of recent history."""
    d = market_data.get(symbol, {})
    vh = d.get("volumeHistory", [])
    current_vol = d.get("volume24h", 0)
    if len(vh) < 5 or current_vol == 0:
        return True  # not enough data, don't block
    avg_vol = sum(vh[-10:]) / len(vh[-10:])
    return current_vol >= avg_vol * 1.0  # slightly relaxed: 1.0x instead of 1.2x initially


def add_log(type_, label, desc):
    agent_state["log"].insert(0, {"type": type_, "label": label, "desc": desc, "time": datetime.now().strftime("%H:%M:%S")})
    if len(agent_state["log"]) > 100:
        agent_state["log"].pop()

def unrealized_pnl():
    pos = agent_state["position"]
    if not pos:
        return 0.0
    return (pos["currentPrice"] - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]

async def enter_position_spec(crypto):
    """Speculative mode entry — fast pump catching with tight trailing stop."""
    cfg = agent_state["config"]
    capital = agent_state["capital"]
    risk_pct = cfg.get("riskPerTrade", 0.02)
    risk_amount = capital * risk_pct
    price = crypto["price"]

    # Tight stop: 1% trailing
    stop_distance_pct = 0.01
    size = risk_amount / stop_distance_pct
    size = min(size, agent_state["currentCapital"] * 0.20)
    size = max(size, 1.0)

    agent_state["currentCapital"] -= size
    agent_state["position"] = {
        "symbol": crypto["symbol"], "icon": crypto["icon"],
        "entryPrice": price, "currentPrice": price,
        "highPrice": price, "size": size,
        "entryTime": datetime.now().isoformat(),
        "stopDistance": stop_distance_pct,
        "atr": None,
        "partialTaken": False,
        "stopPrice": price * 0.99,
        "specMode": True,
    }
    add_log("buy", "PUMP ENTRY",
        f"{crypto['symbol']} @ ${price:.4f} | "
        f"Mom: {crypto['mom']:+.2f}% | Size: ${size:.2f} | Trail: 1%"
    )

async def enter_position_async(crypto):
    """Async version of enter_position that fetches real 1h ATR."""
    cfg = agent_state["config"]
    capital = agent_state["capital"]

    # Fetch real ATR from 1h klines
    pair = crypto["symbol"] + "USDT"
    atr = await fetch_atr_1h(pair)
    price = crypto["price"]

    # Fallback to tick ATR if klines fail
    if not atr or atr <= 0:
        atr = calc_atr(crypto["symbol"])

    trail_stop = cfg.get("trailStop", 0.08)
    risk_pct = cfg.get("riskPerTrade", 0.02)
    risk_amount = capital * risk_pct

    if atr and atr > 0:
        # Stop = 1.5x ATR below entry
        stop_distance_pct = (atr * 1.5) / price
        stop_distance_pct = max(stop_distance_pct, 0.01)   # min 1%
        stop_distance_pct = min(stop_distance_pct, trail_stop)
    else:
        stop_distance_pct = trail_stop

    # Size = risk / stop_distance, cap at 20%
    size = risk_amount / stop_distance_pct
    size = min(size, agent_state["currentCapital"] * 0.20)
    size = max(size, 1.0)

    agent_state["currentCapital"] -= size
    atr_str = f"ATR1h: ${atr:.4f} | Stop: {stop_distance_pct*100:.2f}%" if atr else "ATR: n/a"
    agent_state["position"] = {
        "symbol": crypto["symbol"], "icon": crypto["icon"],
        "entryPrice": price, "currentPrice": price,
        "highPrice": price, "size": size,
        "entryTime": datetime.now().isoformat(),
        "stopDistance": stop_distance_pct,
        "atr": atr,
        "partialTaken": False,
        "stopPrice": price * (1 - stop_distance_pct),
    }
    add_log("buy", "ACQUISTO",
        f"{crypto['symbol']} @ ${price:.4f} | "
        f"Mom: {crypto['mom']:+.2f}% | Size: ${size:.2f} | {atr_str}"
    )

def exit_position(reason, cur_price):
    pos = agent_state["position"]
    cfg = agent_state["config"]
    pnl = (cur_price - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    pct = (cur_price - pos["entryPrice"]) / pos["entryPrice"] * 100

    # Calculate trade duration
    entry_time = datetime.fromisoformat(pos["entryTime"])
    duration_min = (datetime.now() - entry_time).total_seconds() / 60

    # Max profit reached during trade
    max_profit = (pos["highPrice"] - pos["entryPrice"]) / pos["entryPrice"] * pos["size"]
    max_profit_pct = (pos["highPrice"] - pos["entryPrice"]) / pos["entryPrice"] * 100

    # Was partial TP taken?
    partial = pos.get("partialTaken", False)

    agent_state["currentCapital"] += pos["size"] + pnl
    agent_state["tradeCount"] += 1

    if pnl > 0:
        agent_state["wins"] += 1
        agent_state["consecutiveLosses"] = 0
    else:
        agent_state["consecutiveLosses"] += 1
        if agent_state["consecutiveLosses"] >= 3:
            pause_until = datetime.now().timestamp() * 1000 + 2 * 3600 * 1000
            agent_state["circuitBreakerUntil"] = pause_until
            add_log("info", "CIRCUIT BREAKER", "3 perdite consecutive — pausa 2h per rivalutare condizioni")

    agent_state["trades"].append({
        "symbol": pos["symbol"],
        "reason": reason,
        "entryPrice": pos["entryPrice"],
        "exitPrice": cur_price,
        "pnl": pnl,
        "pct": pct,
        "time": datetime.now().isoformat(),
        "entryTime": pos["entryTime"],
        "durationMin": round(duration_min, 1),
        "maxProfit": round(max_profit, 4),
        "maxProfitPct": round(max_profit_pct, 3),
        "partialTaken": partial,
        "atr": pos.get("atr"),
        "size": pos["size"],
    })
    agent_state["cooldowns"][pos["symbol"]] = (datetime.now().timestamp() + cfg.get("cooldown", 2) * 3600) * 1000
    partial_str = " | TP parziale ✓" if partial else ""
    add_log("sell", reason,
        f"{pos['symbol']} @ ${cur_price:.4f} | {pnl:+.2f}$ ({pct:+.2f}%) | "
        f"{duration_min:.0f} min{partial_str}"
    )
    agent_state["position"] = None

async def scan_and_trade():
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

    # Circuit breaker: P&L < -5% → stop sessione
    unr = unrealized_pnl()
    pos = agent_state["position"]
    pos_value = pos["size"] if pos else 0
    total_value = agent_state["currentCapital"] + pos_value + unr
    pnl_pct = (total_value - agent_state["capital"]) / agent_state["capital"] * 100 if agent_state["capital"] > 0 else 0
    if pnl_pct <= -5.0 and not agent_state.get("circuitBreakerTripped"):
        agent_state["circuitBreakerTripped"] = True
        agent_state["running"] = False
        if agent_state["position"]:
            exit_position("CIRCUIT BREAKER -5%", agent_state["position"]["currentPrice"])
        add_log("info", "CIRCUIT BREAKER", f"P&L sessione: {pnl_pct:.1f}% — agente fermato per protezione capitale")
        return

    # Circuit breaker: pausa temporanea per 3 perdite consecutive
    cb_until = agent_state.get("circuitBreakerUntil")
    if cb_until and datetime.now().timestamp() * 1000 < cb_until:
        remaining_min = (cb_until - datetime.now().timestamp() * 1000) / 60000
        add_log("info", "PAUSA CB", f"Rivalutazione in corso — riprendo tra {remaining_min:.0f} min")
        return
    elif cb_until and datetime.now().timestamp() * 1000 >= cb_until:
        agent_state["circuitBreakerUntil"] = None
        agent_state["consecutiveLosses"] = 0
        add_log("info", "RIPRESA", "Pausa terminata — riprendo scansione mercato")

    if agent_state["position"]:
        pos = agent_state["position"]
        cur = pos["currentPrice"]

        # Speculative mode: tight 1% trailing stop
        if pos.get("specMode"):
            trail_price = pos["highPrice"] * 0.99
            if cur <= trail_price:
                exit_position("TRAILING STOP 1%", cur)
            elif agent_state["position"]:
                entry_time = datetime.fromisoformat(pos["entryTime"])
                elapsed_min = (datetime.now() - entry_time).total_seconds() / 60
                if elapsed_min >= 15:
                    exit_position("TIME STOP", cur)
        else:
            atr = pos.get("atr")
            if atr and atr > 0:
                atr_floor = pos["entryPrice"] * 0.005
                atr = max(atr, atr_floor)
                if not pos.get("partialTaken"):
                    tp_partial = pos["entryPrice"] + (atr * 1.5)
                    stop_price = pos.get("stopPrice", pos["highPrice"] - (atr * 2.0))
                    if cur >= tp_partial:
                        half_size = pos["size"] / 2
                        pnl_partial = (cur - pos["entryPrice"]) / pos["entryPrice"] * half_size
                        agent_state["currentCapital"] += half_size + pnl_partial
                        pos["size"] = half_size
                        pos["partialTaken"] = True
                        pos["stopPrice"] = pos["entryPrice"]
                        add_log("sell", "TP PARZIALE",
                            f"{pos['symbol']} @ ${cur:.4f} | 50% chiuso | +${pnl_partial:.2f} | Stop → breakeven"
                        )
                    elif cur <= stop_price:
                        exit_position("TRAILING STOP", cur)
                else:
                    trail_price = max(pos["entryPrice"], pos["highPrice"] - (atr * 2.0))
                    tp_full = pos["entryPrice"] + (atr * 4.0)
                    if cur <= trail_price:
                        exit_position("TRAILING STOP", cur)
                    elif cur >= tp_full:
                        exit_position("TAKE PROFIT FINALE", cur)
            else:
                trail_price = pos["highPrice"] * (1 - cfg.get("trailStop", 0.08))
                tp_price = pos["entryPrice"] * (1 + cfg.get("takeProfit", 0.15))
                if cur <= trail_price:
                    exit_position("TRAILING STOP", cur)
                elif cur >= tp_price:
                    exit_position("TAKE PROFIT", cur)
            if cfg.get("smartExit", False) and not pos.get("partialTaken"):
                sym_data = market_data.get(pos["symbol"], {})
                hist = sym_data.get("priceHistory", [])
                mom = sym_data.get("change1h", 0) if len(hist) >= 5 else sym_data.get("change24h", 0) * 0.1
                if mom < -0.5:
                    exit_position("INVERSIONE TREND", cur)
    else:
        btc = market_data.get("BTC", {})
        btc_hist = btc.get("priceHistory", [])
        btc_mom = btc.get("change1h", 0) if len(btc_hist) >= 5 else btc.get("change24h", 0) * 0.1

        if cfg.get("specMode", False):
            # SPECULATIVE MODE: scan ALL coins, not just high volume
            market = get_sorted_market("low", 17)  # all tracked coins
            candidates = []
            for c in market:
                if c["inCooldown"]:
                    continue
                sym_data = market_data.get(c["symbol"], {})
                hist = sym_data.get("priceHistory", [])
                consecutive_ups = sym_data.get("consecutiveUps", 0)
                vh = sym_data.get("volumeHistory", [])
                vol = sym_data.get("volume24h", 0)
                avg_vol = sum(vh[-10:]) / len(vh[-10:]) if len(vh) >= 5 else 0

                # Check acceleration: last 3 ticks each bigger than previous
                accelerating = False
                if len(hist) >= 4:
                    diffs = [hist[-i] - hist[-i-1] for i in range(1, 4)]
                    accelerating = all(d > 0 for d in diffs) and diffs[0] >= diffs[1]

                vol_spike = vol >= avg_vol * 3.0 if avg_vol > 0 else False

                # Filters: mom > 0.8%, 3+ consecutive ups
                if (c["mom"] > 0.8 and consecutive_ups >= 3):
                    candidates.append((c, c["mom"]))

            candidates.sort(key=lambda x: x[1], reverse=True)
            top3 = [(c["symbol"], round(c["mom"], 2)) for c in market[:3]]
            add_log("info", "PUMP SCAN",
                f"Top3: {top3} | Pump: {len(candidates)}"
            )
            if candidates:
                await enter_position_spec(candidates[0][0])
        elif btc_mom < -1.5:
            add_log("info", "PAUSA", f"BTC in calo ({btc_mom:+.2f}%), sospendo ingressi")
        else:
            market = get_sorted_market(cfg.get("volFilter", "high"), cfg.get("topN", 10))
            top3 = [(c["symbol"], round(c["mom"], 2)) for c in market[:3]]

            candidates = []
            for c in market:
                if c["inCooldown"] or c["mom"] <= 0.05:
                    continue
                adx = calc_adx(c["symbol"])
                if adx < 20:
                    continue
                if not ema_aligned(c["symbol"]):
                    continue
                if not volume_ok(c["symbol"]):
                    continue
                candidates.append((c, adx))

            candidates.sort(key=lambda x: x[1], reverse=True)
            add_log("info", "SCAN",
                f"Top3: {top3} | BTC: {btc_mom:+.2f}% | "
                f"Candidati validi: {len(candidates)}"
            )
            if candidates:
                await enter_position_async(candidates[0][0])

    # P&L history
    unr = unrealized_pnl()
    pos = agent_state["position"]
    pos_value = pos["size"] if pos else 0
    total_value = agent_state["currentCapital"] + pos_value + unr
    pnl_val = total_value - agent_state["capital"]
    agent_state["pnlHistory"].append({"t": (datetime.now().timestamp() - agent_state["sessionStart"]) / 60, "v": pnl_val})
    if len(agent_state["pnlHistory"]) > 500:
        agent_state["pnlHistory"].pop(0)

async def background_loop():
    while True:
        try:
            await fetch_binance_prices()
            await scan_and_trade()
        except Exception as e:
            import traceback
            print(f"Loop error: {e}\n{traceback.format_exc()}")
        await asyncio.sleep(8)

@app.on_event("startup")
async def startup():
    asyncio.create_task(background_loop())

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
        "running": agent_state["running"], "capital": agent_state["capital"],
        "currentCapital": agent_state["currentCapital"], "pnl": pnl, "pct": pct,
        "tradeCount": agent_state["tradeCount"], "winRate": wr,
        "position": pos,
        "positions": [pos] if pos else [],
        "remainingMs": remaining,
        "pnlHistory": agent_state["pnlHistory"][-100:],
        "log": agent_state["log"][:30],
        "consecutiveLosses": agent_state.get("consecutiveLosses", 0),
        "circuitBreakerTripped": agent_state.get("circuitBreakerTripped", False),
        "circuitBreakerUntil": agent_state.get("circuitBreakerUntil"),
    }

@app.get("/market")
def get_market():
    cfg = agent_state["config"]
    return {"market": get_sorted_market(cfg.get("volFilter", "high"), cfg.get("topN", 12))}

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
        "running": True, "capital": capital, "currentCapital": capital,
        "position": None, "pnlHistory": [{"t": 0, "v": 0}],
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
            "smartExit": bool(cfg.get("smartExit", False)),
            "riskPerTrade": float(cfg.get("riskPerTrade", 0.02)),
            "specMode": bool(cfg.get("specMode", False)),
        },
        "cooldowns": {}, "tradeCount": 0, "wins": 0, "trades": [], "log": [],
        "consecutiveLosses": 0, "circuitBreakerUntil": None, "circuitBreakerTripped": False,
    })
    add_log("info", "AVVIO", f"${capital:.0f} USDT | Stop {float(cfg.get('trailStop',0.08))*100:.0f}% | TP {float(cfg.get('takeProfit',0.15))*100:.0f}% | CD {cfg.get('cooldown',2)}h")
    return {"ok": True}

@app.post("/close_position")
def close_position():
    pos = agent_state["position"]
    if not pos:
        return {"error": "No position open"}
    exit_position("CHIUSURA MANUALE", pos["currentPrice"])
    return {"ok": True}

@app.post("/close_position/{symbol}")
def close_position_symbol(symbol: str):
    pos = agent_state["position"]
    if not pos or pos["symbol"] != symbol:
        return {"error": f"No position on {symbol}"}
    exit_position("CHIUSURA MANUALE", pos["currentPrice"])
    return {"ok": True}

@app.post("/stop")
def stop_agent():
    if not agent_state["running"]:
        return {"error": "Not running"}
    agent_state["running"] = False
    if agent_state["position"]:
        exit_position("STOP MANUALE", agent_state["position"]["currentPrice"])
    pnl = agent_state["currentCapital"] - agent_state["capital"]
    add_log("info", "STOP", f"P&L finale: {pnl:+.2f}$")
    return {"ok": True, "pnl": pnl}

@app.post("/chat")
async def chat(body: dict):
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "API key non configurata"}
    messages = body.get("messages", [])
    pos = agent_state.get("position")
    pnl = agent_state.get("currentCapital", 0) - agent_state.get("capital", 0)
    pos_desc = f"IN POSIZIONE su {pos['symbol']} @ ${pos['entryPrice']}" if pos else "Nessuna posizione aperta"
    system = f"Sei un agente di trading crypto. Monitori il mercato in tempo reale con prezzi Binance. Stato: {pos_desc}. P&L sessione: ${pnl:.2f}. Rispondi in italiano, conciso e professionale."
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 500, "system": system, "messages": messages}
        )
        data = res.json()
        if "content" in data:
            return {"reply": data["content"][0]["text"]}
        return {"error": f"Errore API: {data.get('error', {}).get('message', str(data))}"}

@app.get("/health")
def health():
    prices_ok = any(d["price"] > 0 for d in market_data.values())
    return {"status": "ok", "binance": prices_ok}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
