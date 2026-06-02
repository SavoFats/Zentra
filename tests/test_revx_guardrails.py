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
