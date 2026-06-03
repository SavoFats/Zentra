import asyncio
import importlib
import os
import sys
import types
import unittest


def _install_import_stubs():
    class _FastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def middleware(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

        def get(self, *args, **kwargs):
            return lambda fn: fn

        def delete(self, *args, **kwargs):
            return lambda fn: fn

        def patch(self, *args, **kwargs):
            return lambda fn: fn

        def on_event(self, *args, **kwargs):
            return lambda fn: fn

    class _HTTPException(Exception):
        def __init__(self, status_code=500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    fastapi = types.ModuleType("fastapi")
    fastapi.FastAPI = _FastAPI
    fastapi.HTTPException = _HTTPException
    fastapi.Depends = lambda dep=None: dep
    fastapi.Query = lambda default=None, *args, **kwargs: default
    fastapi.Request = type("Request", (), {})
    fastapi.Response = type("Response", (), {"__init__": lambda self, *a, **k: None})
    sys.modules.setdefault("fastapi", fastapi)

    responses = types.ModuleType("fastapi.responses")
    responses.PlainTextResponse = type("PlainTextResponse", (), {"__init__": lambda self, *a, **k: None})
    sys.modules.setdefault("fastapi.responses", responses)

    pydantic = types.ModuleType("pydantic")
    pydantic.BaseModel = object
    sys.modules.setdefault("pydantic", pydantic)

    for name in ("websockets", "stripe", "httpx", "uvicorn", "asyncpg", "bcrypt"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["httpx"].AsyncClient = type("AsyncClient", (), {})
    sys.modules["asyncpg"].UniqueViolationError = type("UniqueViolationError", (Exception,), {})

    cryptography = types.ModuleType("cryptography")
    fernet = types.ModuleType("cryptography.fernet")
    fernet.Fernet = type("Fernet", (), {"__init__": lambda self, *a, **k: None})
    sys.modules.setdefault("cryptography", cryptography)
    sys.modules.setdefault("cryptography.fernet", fernet)


def import_main():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    _install_import_stubs()
    return importlib.import_module("main")


class FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *args):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return FakeAcquire(self.conn)


class RevxGuardrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = import_main()

    def test_external_exchange_key_validation_allows_supported_exchanges(self):
        key, secret, cfg = self.main.validate_external_exchange_keys("binance", " api-key-123 ", " secret-123 ")
        self.assertEqual(key, "api-key-123")
        self.assertEqual(secret, "secret-123")
        self.assertEqual(cfg["key_column"], "binance_api_key")

    def test_external_exchange_key_validation_rejects_unknown_exchange(self):
        with self.assertRaises(self.main.HTTPException) as ctx:
            self.main.validate_external_exchange_keys("kraken", "api-key-123", "secret-123")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_external_exchange_key_validation_rejects_short_secret(self):
        with self.assertRaises(self.main.HTTPException) as ctx:
            self.main.validate_external_exchange_keys("coinbase", "api-key-123", "short")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_coinbase_secret_normalizes_escaped_newlines(self):
        raw = "-----BEGIN EC PRIVATE KEY-----\\nabc\\n-----END EC PRIVATE KEY-----\\n"
        normalized = self.main.normalize_coinbase_api_secret(raw)
        self.assertIn("\nabc\n", normalized)
        self.assertNotIn("\\n", normalized)

    def test_coinbase_jwt_uri_strips_query_string(self):
        uri = self.main.coinbase_jwt_uri("GET", "/api/v3/brokerage/accounts?limit=250&cursor=abc")
        self.assertEqual(uri, "GET api.coinbase.com/api/v3/brokerage/accounts")

    def test_parse_coinbase_accounts_accepts_known_shape(self):
        accounts = self.main.parse_coinbase_accounts({
            "accounts": [
                {
                    "name": "USD Wallet",
                    "currency": "USD",
                    "active": True,
                    "ready": True,
                    "available_balance": {"value": "12.34", "currency": "USD"},
                },
                {
                    "name": "BTC Wallet",
                    "currency": "BTC",
                    "available_balance": {"value": "0", "currency": "BTC"},
                },
            ]
        })
        self.assertEqual(accounts[0]["currency"], "USD")
        self.assertEqual(accounts[0]["available"], 12.34)
        self.assertTrue(accounts[0]["active"])
        self.assertEqual(accounts[1]["available"], 0.0)

    def test_parse_coinbase_accounts_rejects_unknown_shape(self):
        with self.assertRaises(ValueError):
            self.main.parse_coinbase_accounts({"error": "unauthorized"})

    def test_fetch_coinbase_accounts_follows_cursor(self):
        main = self.main
        calls = []

        async def fake_coinbase_request(method, path, body=None, api_key="", api_secret=""):
            calls.append(path)
            if "cursor=next" in path:
                return {
                    "accounts": [{"currency": "USDC", "available_balance": {"value": "5", "currency": "USDC"}}],
                    "has_next": False,
                }
            return {
                "accounts": [{"currency": "USD", "available_balance": {"value": "0", "currency": "USD"}}],
                "has_next": True,
                "cursor": "next",
            }

        original = main.coinbase_request
        main.coinbase_request = fake_coinbase_request
        try:
            accounts = asyncio.run(main.fetch_coinbase_accounts("key", "secret"))
        finally:
            main.coinbase_request = original

        self.assertEqual([a["currency"] for a in accounts], ["USD", "USDC"])
        self.assertIn("cursor=next", calls[1])

    def test_coinbase_preflight_allows_tradable_product_with_balance(self):
        result = self.main.build_coinbase_preflight(
            [{"currency": "USD", "available": 12.0}],
            {
                "product_id": "BTC-USD",
                "quote_currency_id": "USD",
                "quote_min_size": "1",
                "price": "50000",
                "trading_disabled": False,
                "cancel_only": False,
                "post_only": False,
                "limit_only": False,
            },
            1.0,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["product_id"], "BTC-USD")
        self.assertEqual(result["blockers"], [])

    def test_coinbase_preflight_blocks_insufficient_balance(self):
        result = self.main.build_coinbase_preflight(
            [{"currency": "USD", "available": 0.5}, {"currency": "USDC", "available": 5.0}],
            {"product_id": "BTC-USD", "quote_currency_id": "USD", "quote_min_size": "1"},
            1.0,
        )
        self.assertFalse(result["ok"])
        self.assertIn("insufficient_quote_balance", result["blockers"])
        self.assertEqual(result["quote_balances"]["USDC"], 5.0)

    def test_coinbase_preflight_candidate_sort_prefers_fewer_blockers(self):
        usd = self.main.build_coinbase_preflight(
            [{"currency": "USD", "available": 0.0}, {"currency": "USDC", "available": 5.0}],
            {"product_id": "BTC-USD", "quote_currency_id": "USD", "quote_min_size": "1"},
            1.0,
        )
        usdc = self.main.build_coinbase_preflight(
            [{"currency": "USD", "available": 0.0}, {"currency": "USDC", "available": 5.0}],
            {"product_id": "BTC-USDC", "quote_currency_id": "USDC", "quote_min_size": "1"},
            1.0,
        )
        best = sorted([usd, usdc], key=lambda c: (len(c.get("blockers", [])), -float(c.get("available_quote") or 0)))[0]
        self.assertEqual(best["product_id"], "BTC-USDC")
        self.assertTrue(best["ok"])

    def test_coinbase_quote_balance_sums_usd_and_usdc(self):
        main = self.main

        async def fake_fetch_accounts(api_key, api_secret):
            return [
                {"currency": "USD", "available": 2.0},
                {"currency": "USDC", "available": 3.5},
                {"currency": "EUR", "available": 9.0},
            ]

        original = main.fetch_coinbase_accounts
        main.fetch_coinbase_accounts = fake_fetch_accounts
        try:
            balance = asyncio.run(main.get_coinbase_quote_balance("key", "secret"))
        finally:
            main.fetch_coinbase_accounts = original

        self.assertEqual(balance, 5.5)

    def test_extract_coinbase_order_id_accepts_success_response(self):
        order_id = self.main.extract_coinbase_order_id({
            "success": True,
            "success_response": {"order_id": "ord-123"},
        })
        self.assertEqual(order_id, "ord-123")

    def test_summarize_coinbase_order_accepts_historical_shape(self):
        summary = self.main.summarize_coinbase_order({
            "order": {
                "order_id": "ord-123",
                "product_id": "BTC-USDC",
                "status": "FILLED",
                "filled_size": "0.00001",
            }
        })
        self.assertEqual(summary["order_id"], "ord-123")
        self.assertEqual(summary["product_id"], "BTC-USDC")
        self.assertEqual(summary["status"], "FILLED")

    def test_coinbase_micro_sell_places_small_btc_market_sell(self):
        main = self.main
        calls = []

        async def fake_load_keys(user_id):
            self.assertEqual(user_id, 123)
            return "api-key", "api-secret"

        async def fake_fetch_accounts(api_key, api_secret):
            return [{"currency": "BTC", "available": 0.00001455}]

        async def fake_coinbase_request(method, path, body=None, api_key="", api_secret=""):
            calls.append((method, path, body))
            if method == "GET" and path == "/api/v3/brokerage/products/BTC-USDC":
                return {"product_id": "BTC-USDC", "trading_disabled": False, "cancel_only": False}
            if method == "POST" and path == "/api/v3/brokerage/orders":
                return {"success": True, "success_response": {"order_id": "ord-sell"}}
            if method == "GET" and path == "/api/v3/brokerage/orders/historical/ord-sell":
                return {"order": {"order_id": "ord-sell", "product_id": "BTC-USDC", "status": "FILLED", "filled_size": "0.00001455"}}
            raise AssertionError((method, path, body))

        async def fake_sleep(*args, **kwargs):
            return None

        original_load = main.load_coinbase_keys_for_user
        original_fetch = main.fetch_coinbase_accounts
        original_request = main.coinbase_request
        original_rate_limit = main.check_rate_limit
        original_sleep = main.asyncio.sleep
        main.load_coinbase_keys_for_user = fake_load_keys
        main.fetch_coinbase_accounts = fake_fetch_accounts
        main.coinbase_request = fake_coinbase_request
        main.check_rate_limit = lambda *args, **kwargs: None
        main.asyncio.sleep = fake_sleep
        try:
            req = types.SimpleNamespace(symbol="BTC", base_size=0.00001455)
            result = asyncio.run(main.coinbase_micro_sell(req, request=object(), user_id=123))
        finally:
            main.load_coinbase_keys_for_user = original_load
            main.fetch_coinbase_accounts = original_fetch
            main.coinbase_request = original_request
            main.check_rate_limit = original_rate_limit
            main.asyncio.sleep = original_sleep

        self.assertTrue(result["ok"])
        self.assertEqual(result["product_id"], "BTC-USDC")
        self.assertEqual(result["order_id"], "ord-sell")
        post_body = next(body for method, path, body in calls if method == "POST" and path == "/api/v3/brokerage/orders")
        self.assertEqual(post_body["side"], "SELL")
        self.assertEqual(post_body["product_id"], "BTC-USDC")
        self.assertEqual(post_body["order_configuration"]["market_market_ioc"]["base_size"], "0.00001455")

    def test_manual_trade_coinbase_creates_real_coinbase_position(self):
        main = self.main
        calls = []
        state = main.make_session()
        state["currentCapital"] = 100.0
        state["capital"] = 100.0
        state["config"] = {}

        async def fake_load_keys(user_id):
            self.assertEqual(user_id, 123)
            return "api-key", "api-secret"

        async def fake_preflight(api_key, api_secret, sym, amount):
            self.assertEqual(sym, "BTC")
            self.assertEqual(amount, 10.0)
            return {"ok": True, "product_id": "BTC-USDC"}

        async def fake_coinbase_request(method, path, body=None, api_key="", api_secret=""):
            calls.append((method, path, body))
            if method == "POST" and path == "/api/v3/brokerage/orders":
                return {"success": True, "success_response": {"order_id": "ord-buy"}}
            raise AssertionError((method, path, body))

        async def fake_wait(order_id, api_key, api_secret):
            self.assertEqual(order_id, "ord-buy")
            return {
                "order_id": "ord-buy",
                "status": "FILLED",
                "product_id": "BTC-USDC",
                "filled_size": "0.0002",
                "average_filled_price": "50000",
                "total_fees": "0.01",
            }

        async def fake_notify(*args, **kwargs):
            return None

        async def fake_persist():
            return None

        original_sessions = main.user_sessions
        original_market = main.market_data
        original_load = main.load_coinbase_keys_for_user
        original_preflight = main.get_coinbase_preflight_result
        original_request = main.coinbase_request
        original_wait = main.wait_coinbase_order_fill
        original_notify = main.notify
        original_persist = main.persist_sessions
        original_rate_limit = main.check_rate_limit
        main.user_sessions = {123: state}
        main.market_data = {"BTC": {"price": 50000.0, "icon": "B"}}
        main.load_coinbase_keys_for_user = fake_load_keys
        main.get_coinbase_preflight_result = fake_preflight
        main.coinbase_request = fake_coinbase_request
        main.wait_coinbase_order_fill = fake_wait
        main.notify = fake_notify
        main.persist_sessions = fake_persist
        main.check_rate_limit = lambda *args, **kwargs: None
        try:
            req = types.SimpleNamespace(symbol="BTCUSDT", amount_usdt=10.0, sl_pct=2.0, tp_pct=4.0, exchange="coinbase")
            result = asyncio.run(main.manual_trade(req, request=object(), user_id=123))
        finally:
            main.user_sessions = original_sessions
            main.market_data = original_market
            main.load_coinbase_keys_for_user = original_load
            main.get_coinbase_preflight_result = original_preflight
            main.coinbase_request = original_request
            main.wait_coinbase_order_fill = original_wait
            main.notify = original_notify
            main.persist_sessions = original_persist
            main.check_rate_limit = original_rate_limit

        self.assertTrue(result["ok"])
        self.assertEqual(result["exchange"], "coinbase")
        self.assertEqual(len(state["positions"]), 1)
        pos = state["positions"][0]
        self.assertTrue(pos["realMode"])
        self.assertEqual(pos["exchange"], "coinbase")
        self.assertEqual(pos["symbol_pair"], "BTC-USDC")
        self.assertEqual(pos["qty_purchased"], 0.0002)
        post_body = next(body for method, path, body in calls if method == "POST" and path == "/api/v3/brokerage/orders")
        self.assertEqual(post_body["side"], "BUY")
        self.assertEqual(post_body["product_id"], "BTC-USDC")
        self.assertEqual(post_body["order_configuration"]["market_market_ioc"]["quote_size"], "10.00")

    def test_monitor_coinbase_position_uses_coinbase_price_before_tp(self):
        main = self.main
        state = main.make_session()
        pos = {
            "symbol": "OCEAN",
            "entryPrice": 0.1315,
            "currentPrice": 0.6123,
            "highPrice": 0.1315,
            "peak_price": 0.1315,
            "size": 1.0,
            "size_remaining": 1.0,
            "entryTime": "2026-06-02T17:35:00Z",
            "stopPrice": 0.1289,
            "tp1Price": 0.1360,
            "realMode": True,
            "exchange": "coinbase",
            "symbol_pair": "OCEAN-USDC",
            "qty_purchased": 7.6,
            "manual": True,
        }
        state["positions"].append(pos)

        async def fake_load_keys(user_id):
            return "api-key", "api-secret"

        async def fake_coinbase_price(product_id, api_key, api_secret):
            self.assertEqual(product_id, "OCEAN-USDC")
            return 0.1324

        async def fail_exit(*args, **kwargs):
            raise AssertionError("Coinbase position should not close from non-Coinbase market price")

        original_market = main.market_data
        original_load = main.load_coinbase_keys_for_user
        original_price = main.get_coinbase_product_price
        original_exit = main.exit_position
        main.market_data = {"OCEAN": {"price": 0.6123}}
        main.load_coinbase_keys_for_user = fake_load_keys
        main.get_coinbase_product_price = fake_coinbase_price
        main.exit_position = fail_exit
        try:
            asyncio.run(main.monitor_manual_positions(state, user_id=123))
        finally:
            main.market_data = original_market
            main.load_coinbase_keys_for_user = original_load
            main.get_coinbase_product_price = original_price
            main.exit_position = original_exit

        self.assertIn(pos, state["positions"])
        self.assertEqual(pos["currentPrice"], 0.1324)

    def test_external_market_price_does_not_overwrite_real_coinbase_position(self):
        pos = {
            "symbol": "OCEAN",
            "entryPrice": 0.1315,
            "currentPrice": 0.1324,
            "highPrice": 0.1324,
            "realMode": True,
            "exchange": "coinbase",
        }

        self.main.update_position_from_external_price(pos, 0.6123)

        self.assertEqual(pos["currentPrice"], 0.1324)
        self.assertEqual(pos["highPrice"], 0.1324)

    def test_sync_coinbase_positions_imports_missing_base_balance(self):
        main = self.main
        state = main.make_session()
        state["capital"] = 10.0
        state["currentCapital"] = 8.0
        existing = {
            "symbol": "BTC",
            "realMode": True,
            "exchange": "coinbase",
        }
        state["positions"].append(existing)

        async def fake_load_keys(user_id):
            self.assertEqual(user_id, 123)
            return "api-key", "api-secret"

        async def fake_fetch_accounts(api_key, api_secret):
            return [
                {"currency": "USDC", "available": 5.0},
                {"currency": "BTC", "available": 0.001},
                {"currency": "OCEAN", "available": 7.5},
                {"currency": "DUST", "available": 0.01},
            ]

        async def fake_resolve_product(sym, api_key, api_secret):
            prices = {"OCEAN": ("OCEAN-USDC", 0.1324), "DUST": ("DUST-USDC", 0.01)}
            return prices[sym]

        async def fake_persist():
            return None

        original_sessions = main.user_sessions
        original_load = main.load_coinbase_keys_for_user
        original_fetch = main.fetch_coinbase_accounts
        original_resolve = main.resolve_coinbase_product
        original_persist = main.persist_sessions
        original_market = main.market_data
        main.user_sessions = {123: state}
        main.load_coinbase_keys_for_user = fake_load_keys
        main.fetch_coinbase_accounts = fake_fetch_accounts
        main.resolve_coinbase_product = fake_resolve_product
        main.persist_sessions = fake_persist
        main.market_data = {"OCEAN": {"icon": "O"}}
        try:
            result = asyncio.run(main.sync_coinbase_positions_for_user(123, min_value_usd=0.50))
        finally:
            main.user_sessions = original_sessions
            main.load_coinbase_keys_for_user = original_load
            main.fetch_coinbase_accounts = original_fetch
            main.resolve_coinbase_product = original_resolve
            main.persist_sessions = original_persist
            main.market_data = original_market

        self.assertTrue(result["ok"])
        self.assertEqual([p["symbol"] for p in result["imported"]], ["OCEAN"])
        self.assertEqual(len(state["positions"]), 2)
        imported = state["positions"][1]
        self.assertTrue(imported["realMode"])
        self.assertEqual(imported["exchange"], "coinbase")
        self.assertEqual(imported["symbol_pair"], "OCEAN-USDC")
        self.assertEqual(imported["qty_purchased"], 7.5)
        self.assertTrue(imported["manual"])
        self.assertTrue(imported["imported"])
        self.assertTrue(imported["_manual_action_required"])
        self.assertAlmostEqual(state["currentCapital"], 7.01, places=2)
        skipped = {item["symbol"]: item["reason"] for item in result["skipped"]}
        self.assertEqual(skipped["USDC"], "quote_or_stable")
        self.assertEqual(skipped["BTC"], "already_open")
        self.assertEqual(skipped["DUST"], "below_min_value")

    def test_coinbase_exit_keeps_position_when_available_balance_is_zero(self):
        main = self.main
        state = main.make_session()
        state["currentCapital"] = 100.0
        state["capital"] = 100.0
        state["config"] = {}
        pos = {
            "symbol": "OCEAN",
            "entryPrice": 0.1315,
            "currentPrice": 0.1324,
            "highPrice": 0.1324,
            "peak_price": 0.1324,
            "size": 1.0,
            "size_remaining": 1.0,
            "entryTime": "2026-06-02T17:35:00Z",
            "stopPrice": 0.1289,
            "tp1Price": 0.1360,
            "realMode": True,
            "exchange": "coinbase",
            "symbol_pair": "OCEAN-USDC",
            "qty_purchased": 7.6,
            "manual": True,
        }
        state["positions"].append(pos)

        async def fake_load_keys(user_id):
            return "api-key", "api-secret"

        async def fake_fetch_accounts(api_key, api_secret):
            return [{"currency": "OCEAN", "available": 0.0}]

        async def fail_coinbase_request(*args, **kwargs):
            raise AssertionError("Should not place Coinbase sell when available balance is zero")

        async def fake_notify(*args, **kwargs):
            return None

        original_load = main.load_coinbase_keys_for_user
        original_fetch = main.fetch_coinbase_accounts
        original_request = main.coinbase_request
        original_notify = main.notify
        main.load_coinbase_keys_for_user = fake_load_keys
        main.fetch_coinbase_accounts = fake_fetch_accounts
        main.coinbase_request = fail_coinbase_request
        main.notify = fake_notify
        try:
            asyncio.run(main.exit_position(state, pos, "TAKE PROFIT", user_id=123))
        finally:
            main.load_coinbase_keys_for_user = original_load
            main.fetch_coinbase_accounts = original_fetch
            main.coinbase_request = original_request
            main.notify = original_notify

        self.assertIn(pos, state["positions"])
        self.assertTrue(pos.get("_manual_action_required"))
        self.assertFalse(state["trades"])

    def test_parse_revx_balances_accepts_known_shapes(self):
        parse = self.main.parse_revx_balances

        direct = [{"currency": "USD", "available": "1"}]
        wrapped = {"balances": direct}
        data_wrapped = {"data": direct}

        self.assertEqual(parse(direct), direct)
        self.assertEqual(parse(wrapped), direct)
        self.assertEqual(parse(data_wrapped), direct)

    def test_parse_revx_balances_rejects_unknown_shape(self):
        with self.assertRaises(ValueError):
            self.main.parse_revx_balances({"error": "unauthorized"})

    def test_wait_revx_order_fill_requires_price_and_quantity(self):
        calls = []

        async def fake_details(order_id, key_id, private_key):
            calls.append(order_id)
            if len(calls) == 1:
                return {"state": "pending", "average_fill_price": 0.0, "filled_quantity": 0.0}
            return {"state": "filled", "average_fill_price": 10.0, "filled_quantity": 2.0}

        original = self.main.get_revx_order_details
        self.main.get_revx_order_details = fake_details
        try:
            result = asyncio.run(self.main.wait_revx_order_fill("ord_1", "key", "pem", attempts=3, delay=0))
        finally:
            self.main.get_revx_order_details = original

        self.assertEqual(result["average_fill_price"], 10.0)
        self.assertEqual(result["filled_quantity"], 2.0)
        self.assertEqual(len(calls), 2)

    def test_revx_request_raises_on_client_error(self):
        main = self.main

        class FakeResponse:
            status_code = 401
            content = b'{"error":"bad key"}'
            text = '{"error":"bad key"}'
            headers = {}

            def json(self):
                return {"error": "bad key"}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, *args, **kwargs):
                return FakeResponse()

        original_client = main.httpx.AsyncClient
        original_sig = main.make_revx_signature
        main.httpx.AsyncClient = FakeClient
        main.make_revx_signature = lambda *args, **kwargs: {}
        try:
            with self.assertRaisesRegex(Exception, "HTTP 401"):
                asyncio.run(main.revx_request("GET", "/api/1.0/balances", key_id="k", private_key="p"))
        finally:
            main.httpx.AsyncClient = original_client
            main.make_revx_signature = original_sig

    def test_failed_real_sell_keeps_position_visible_after_three_failures(self):
        main = self.main
        state = {
            "positions": [],
            "currentCapital": 100.0,
            "capital": 100.0,
            "config": {"cooldown": 0},
            "revx_key_id": "key",
            "revx_private_key": "pem",
            "log": [],
        }
        pos = {
            "symbol": "BTC",
            "currentPrice": 10.0,
            "entryPrice": 10.0,
            "size": 10.0,
            "size_remaining": 10.0,
            "entryTime": "2026-01-01T00:00:00Z",
            "realMode": True,
            "exchange": "revx",
            "qty_purchased": 1.0,
            "symbol_pair": "BTC-USD",
        }
        state["positions"].append(pos)

        async def fake_revx_request(method, path, body=None, key_id=None, private_key=None, params=None):
            if method == "GET" and path == "/api/1.0/balances":
                return {"balances": [{"currency": "BTC", "available": "1"}]}
            if method == "POST" and path == "/api/1.0/orders":
                return {"error": "insufficient balance"}
            raise AssertionError((method, path))

        async def fake_notify(*args, **kwargs):
            return None

        original_revx = main.revx_request
        original_notify = main.notify
        main.revx_request = fake_revx_request
        main.notify = fake_notify
        try:
            for _ in range(3):
                asyncio.run(main.exit_position(state, pos, "TEST", user_id=None))
        finally:
            main.revx_request = original_revx
            main.notify = original_notify

        self.assertIn(pos, state["positions"])
        self.assertTrue(pos.get("_manual_action_required"))
        self.assertEqual(pos.get("_sell_failures"), 3)

    def test_redirect_urls_require_exact_allowed_origin(self):
        main = self.main
        original_any = main._ORIGINS_ANY
        original_set = set(main._ORIGIN_SET)
        main._ORIGINS_ANY = False
        main._ORIGIN_SET = {"https://zentra.trading"}
        try:
            self.assertTrue(main.is_allowed_redirect_url("https://zentra.trading/account?tab=billing"))
            self.assertFalse(main.is_allowed_redirect_url("https://zentra.trading.evil.example/account"))
            self.assertFalse(main.is_allowed_redirect_url("http://zentra.trading/account"))
            self.assertFalse(main.is_allowed_redirect_url("javascript:alert(1)"))
        finally:
            main._ORIGINS_ANY = original_any
            main._ORIGIN_SET = original_set

    def test_with_query_param_preserves_existing_query(self):
        url = self.main.with_query_param("https://zentra.trading/account?tab=billing", "upgraded", "1")
        self.assertEqual(url, "https://zentra.trading/account?tab=billing&upgraded=1")

    def test_verify_token_accepts_valid_token(self):
        token = self.main.create_token(42)
        self.assertEqual(self.main.verify_token(token), 42)

    def test_verify_token_rejects_revoked_token(self):
        token = self.main.create_token(42)
        self.main._revoked_tokens.add(token)
        try:
            with self.assertRaises(self.main.HTTPException) as ctx:
                self.main.verify_token(token)
            self.assertEqual(ctx.exception.status_code, 401)
        finally:
            self.main._revoked_tokens.discard(token)

    def test_verify_token_rejects_malformed_tokens(self):
        for token in ("not-base64!", "abc", "MToy"):
            with self.subTest(token=token):
                with self.assertRaises(self.main.HTTPException) as ctx:
                    self.main.verify_token(token)
                self.assertEqual(ctx.exception.status_code, 401)

    def test_close_symbol_reports_unconfirmed_close(self):
        main = self.main
        pos = {"symbol": "BTC", "_manual_action_required": True}
        state = {"positions": [pos], "config": {}, "log": []}

        async def fake_exit_position(close_state, close_pos, reason, user_id=None):
            self.assertEqual(close_state, state)
            self.assertEqual(close_pos, pos)
            self.assertEqual(reason, "CHIUSURA MANUALE")

        original_get_session = main.get_session
        original_exit_position = main.exit_position
        original_rate_limit = main.check_rate_limit
        main.get_session = lambda user_id: state
        main.exit_position = fake_exit_position
        main.check_rate_limit = lambda *args, **kwargs: None
        try:
            result = asyncio.run(main.close_symbol("btc", request=object(), user_id=123))
        finally:
            main.get_session = original_get_session
            main.exit_position = original_exit_position
            main.check_rate_limit = original_rate_limit

        self.assertIn("error", result)
        self.assertTrue(result["manual_action_required"])

    def test_public_error_redacts_secrets_and_truncates(self):
        secret = "A" * 64
        pem = "-----BEGIN PRIVATE KEY-----\nvery-secret\n-----END PRIVATE KEY-----"
        err = Exception(f"RevX failed api_key: {secret} pem={pem} " + ("x" * 500))

        msg = self.main.public_error(err, secret, max_len=120)

        self.assertNotIn(secret, msg)
        self.assertNotIn("very-secret", msg)
        self.assertIn("[REDACTED]", msg)
        self.assertLessEqual(len(msg), 123)

    def test_persist_sessions_keeps_stopped_sessions_with_open_positions(self):
        main = self.main

        class Conn:
            def __init__(self):
                self.calls = []

            async def execute(self, sql, *args):
                self.calls.append((sql, args))

        conn = Conn()
        original_pool = main.db_pool
        original_sessions = main.user_sessions
        main.db_pool = FakePool(conn)
        main.user_sessions = {
            7: {
                "running": False,
                "positions": [{"symbol": "BTC", "size": 10.0}],
                "revx_key_id": "secret-key",
                "revx_private_key": "secret-pem",
                "log": [{"desc": "not persisted"}],
            }
        }
        try:
            asyncio.run(main.persist_sessions())
        finally:
            main.db_pool = original_pool
            main.user_sessions = original_sessions

        self.assertEqual(len(conn.calls), 1)
        sql, args = conn.calls[0]
        self.assertIn("INSERT INTO active_sessions", sql)
        self.assertEqual(args[0], 7)
        saved_json = args[1]
        self.assertIn("BTC", saved_json)
        self.assertNotIn("secret-key", saved_json)
        self.assertNotIn("secret-pem", saved_json)
        self.assertNotIn("not persisted", saved_json)

    def test_restore_running_session_sets_paused_and_rehydrates_keys(self):
        main = self.main

        class Row(dict):
            def __getitem__(self, key):
                return self.get(key)

        class Conn:
            async def fetch(self, sql):
                return [
                    Row({
                        "user_id": 9,
                        "state_json": (
                            '{"running": true, "paused": false, "positions": '
                            '[{"symbol": "ETH", "size": 25.0, "entryPrice": 100.0, '
                            '"currentPrice": 100.0, "stopPrice": 95.0, "tp1Price": 110.0}]}'
                        ),
                        "updated_at": "2026-06-02T00:00:00",
                        "revx_key_id": "enc-key",
                        "revx_private_key": "enc-pem",
                    })
                ]

            async def execute(self, sql, *args):
                raise AssertionError("restore should not delete a row with positions")

        sent_messages = []

        async def fake_send(*args):
            sent_messages.append(args)

        original_sessions = main.user_sessions
        original_decrypt = main.decrypt_key
        original_send_to = main.send_telegram_to
        original_send = main.send_telegram
        main.user_sessions = {}
        main.decrypt_key = lambda value: f"dec:{value}"
        main.send_telegram_to = fake_send
        main.send_telegram = fake_send
        try:
            asyncio.run(main.restore_sessions_from_db(FakePool(Conn())))
            restored = main.user_sessions[9]
        finally:
            main.user_sessions = original_sessions
            main.decrypt_key = original_decrypt
            main.send_telegram_to = original_send_to
            main.send_telegram = original_send

        self.assertTrue(restored["running"])
        self.assertTrue(restored["paused"])
        self.assertEqual(restored["positions"][0]["symbol"], "ETH")
        self.assertEqual(restored["revx_key_id"], "dec:enc-key")
        self.assertEqual(restored["revx_private_key"], "dec:enc-pem")
        self.assertEqual(restored["config"], {})
        self.assertEqual(restored["cooldowns"], {})
        self.assertEqual(restored["tradeCount"], 0)
        self.assertEqual(restored["log"], [])
        self.assertTrue(sent_messages)


if __name__ == "__main__":
    unittest.main()
