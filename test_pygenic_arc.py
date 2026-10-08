"""Run with: python3 -m unittest -v test_pygenic_arc.py"""
import csv
import io
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from pygenic_arc import (GuardrailEngine, SCENARIOS, CUSTOMERS, INVENTORY,
                         ACCOUNTS, DASHBOARD, AppServer)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.engine = GuardrailEngine(seed=False)

    def act(self, agent, tool, params, **extra):
        return self.engine.analyze({"agent": agent, "tool": tool, "params": params, **extra})

    def test_safe_file(self):
        r = self.act("Agent-A", "read_file", {"path": "/public/report.txt"})
        self.assertEqual(r["decision"], "ALLOW")
        self.assertFalse(r["executed"])

    def test_safe_customer(self):
        self.assertEqual(self.act("Agent-A", "fetch_customer", {"customer_id": "C102"})["decision"], "ALLOW")

    def test_safe_inventory(self):
        self.assertEqual(self.act("Agent-A", "check_inventory", {"sku": "SKU100"})["decision"], "ALLOW")

    def test_duplicate_file(self):
        req = {"path": "/public/report.txt"}
        self.act("Agent-A", "read_file", req)
        self.assertEqual(self.act("Agent-A", "read_file", req)["decision"], "SKIP")

    def test_duplicate_inventory(self):
        req = {"sku": "SKU100"}
        self.act("Agent-A", "check_inventory", req)
        self.assertEqual(self.act("Agent-A", "check_inventory", req)["decision"], "SKIP")

    def test_block_permission(self):
        self.assertEqual(self.act("Agent-B", "delete_file", {"path": "/public/report.txt"})["decision"], "BLOCK")

    def test_untrusted_request_permissions(self):
        self.assertEqual(self.act("Agent-B", "delete_file", {"path": "/public/report.txt"},
                                  permissions=["admin"])["decision"], "BLOCK")

    def test_unregistered_agent(self):
        self.assertEqual(self.act("Intruder", "read_file", {"path": "/public/report.txt"})["decision"], "BLOCK")

    def test_unknown_tool(self):
        self.assertEqual(self.act("Agent-A", "run_shell", {"command": "ls"})["decision"], "BLOCK")

    def test_protected_path(self):
        self.assertEqual(self.act("Agent-D", "delete_file", {"path": "/system/config.json"})["decision"], "BLOCK")

    def test_path_traversal(self):
        self.assertEqual(self.act("Agent-A", "read_file", {"path": "/public/../system/config.json"})["decision"], "BLOCK")

    def test_unknown_file(self):
        self.assertEqual(self.act("Agent-A", "read_file", {"path": "/public/guess.txt"})["decision"], "BLOCK")

    def test_customer_hallucination(self):
        self.assertEqual(self.act("Agent-A", "fetch_customer", {"customer_id": "C999"})["decision"], "BLOCK")

    def test_customer_bad_type(self):
        self.assertEqual(self.act("Agent-A", "fetch_customer", {"customer_id": []})["decision"], "BLOCK")

    def test_missing_param(self):
        self.assertEqual(self.act("Agent-A", "fetch_customer", {})["decision"], "BLOCK")

    def test_extra_param(self):
        self.assertEqual(self.act("Agent-A", "fetch_customer", {"customer_id": "C101", "admin_override": True})["decision"], "BLOCK")

    def test_read_only_restricted_duplicate_not_skipped(self):
        self.act("Agent-A", "read_file", {"path": "/public/report.txt"})
        # Wrong agent is blocked rather than able to reuse cached data.
        self.assertEqual(self.act("Agent-F", "read_file", {"path": "/public/report.txt"})["decision"], "BLOCK")

    def test_approved_public_export(self):
        self.assertEqual(self.act("Agent-B", "export_data", {"dataset": "sales_summary"})["decision"], "ALLOW")

    def test_private_export(self):
        self.assertEqual(self.act("Agent-B", "export_data", {"dataset": "private_records"})["decision"], "BLOCK")

    def test_unknown_dataset(self):
        self.assertEqual(self.act("Agent-B", "export_data", {"dataset": "bogus"})["decision"], "BLOCK")

    def test_small_transfer(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": 1000})["decision"], "ALLOW")

    def test_transfer_review(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": 80000})["decision"], "REVIEW")

    def test_transfer_rejected_insufficient_funds(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1002", "amount": 26000})["decision"], "BLOCK")

    def test_inactive_account(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1004", "amount": 100})["decision"], "BLOCK")

    def test_invalid_account(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC9999", "amount": 100})["decision"], "BLOCK")

    def test_invalid_negative_amount(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": -2})["decision"], "BLOCK")

    def test_invalid_amount_bool(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": True})["decision"], "BLOCK")

    def test_large_numeric_amount(self):
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": 1000001})["decision"], "BLOCK")

    def test_valid_admin_inventory_update(self):
        self.assertEqual(self.act("Agent-D", "update_inventory", {"sku": "SKU100", "quantity": 16})["decision"], "ALLOW")

    def test_reject_negative_inventory(self):
        self.assertEqual(self.act("Agent-D", "update_inventory", {"sku": "SKU100", "quantity": -20})["decision"], "BLOCK")

    def test_reject_fractional_inventory(self):
        self.assertEqual(self.act("Agent-D", "update_inventory", {"sku": "SKU100", "quantity": 1.5})["decision"], "BLOCK")

    def test_reject_missing_request(self):
        self.assertEqual(self.engine.analyze(None)["decision"], "BLOCK")

    def test_invalid_param_container(self):
        self.assertEqual(self.engine.analyze({"agent": "Agent-A", "tool": "read_file", "params": []})["decision"], "BLOCK")

    def test_custom_policy_threshold(self):
        self.engine.update_policy(30, 100000)
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": 70000})["decision"], "REVIEW")

    def test_custom_policy_limit(self):
        self.engine.update_policy(50, 100000)
        self.assertEqual(self.act("Agent-C", "transfer_funds", {"account_id": "ACC1001", "amount": 70000})["decision"], "ALLOW")

    def test_cannot_weaken_critical_rule(self):
        self.engine.update_policy(80, 1000000)
        self.assertEqual(self.act("Agent-B", "export_data", {"dataset": "private_records"})["decision"], "BLOCK")

    def test_invalid_policy_bool(self):
        with self.assertRaises(ValueError):
            self.engine.update_policy(True, 50000)

    def test_adaptive_penalty(self):
        self.act("Agent-A", "fetch_customer", {"customer_id": "C999"})
        r = self.act("Agent-A", "fetch_customer", {"customer_id": "C888"})
        self.assertEqual(r["risk_score"], 100)

    def test_clean_request_does_not_inherit_penalty(self):
        self.act("Agent-A", "fetch_customer", {"customer_id": "C999"})
        r = self.act("Agent-A", "fetch_customer", {"customer_id": "C101"})
        self.assertEqual(r["risk_score"], 0)

    def test_samples_seeded_by_default(self):
        seeded = GuardrailEngine().snapshot()
        self.assertEqual(seeded["total"], len(SCENARIOS))
        self.assertTrue(all(seeded["counts"][k] > 0 for k in ("ALLOW", "BLOCK", "REVIEW", "SKIP")))

    def test_reset_and_reload(self):
        self.engine.load_samples()
        self.engine.reset()
        self.assertEqual(self.engine.snapshot()["total"], 0)
        self.assertEqual(len(self.engine.load_samples()), len(SCENARIOS))

    def test_reference_values(self):
        r = self.engine.reference()
        self.assertEqual(r["customers"], CUSTOMERS)
        self.assertEqual(r["inventory"], INVENTORY)
        self.assertEqual(r["accounts"], ACCOUNTS)

    def test_csv_export_and_injection_protection(self):
        self.engine.analyze({"agent": "=SUM(1,2)", "tool": "read_file", "params": {"path": "/public/report.txt"}})
        output = self.engine.export_csv()
        self.assertEqual(len(list(csv.DictReader(io.StringIO(output)))), 1)
        self.assertIn("AUTH_000", output)
        self.assertIn("'=SUM(1,2)", output)

    def test_dashboard_includes_custom_values(self):
        self.assertIn("Example simulated account balances", DASHBOARD)
        self.assertIn("Inventory quantities", DASHBOARD)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = AppServer(("127.0.0.1", 0), GuardrailEngine())
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def fetch(self, path, data=None):
        body = None if data is None else json.dumps(data).encode("utf-8")
        req = Request(self.base + path, data=body,
                      headers={"Content-Type": "application/json"} if data is not None else {})
        with urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers.get("Content-Type"), resp.read()

    def test_homepage(self):
        status, content_type, body = self.fetch("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Pygenic Arc", body)
        self.assertIn("text/html", content_type)

    def test_seeded_status(self):
        # Reload samples so the result is independent of other HTTP tests.
        self.fetch("/api/demo", {})
        status, _, body = self.fetch("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 27)

    def test_scenarios_endpoint(self):
        _, _, body = self.fetch("/api/scenarios")
        self.assertEqual(len(json.loads(body)["scenarios"]), 27)

    def test_reference_endpoint(self):
        _, _, body = self.fetch("/api/reference")
        self.assertEqual(len(json.loads(body)["reference"]["accounts"]), 4)

    def test_analyze_endpoint(self):
        _, _, body = self.fetch("/api/analyze", {"request": SCENARIOS["25 Unknown tool"]})
        self.assertEqual(json.loads(body)["result"]["decision"], "BLOCK")

    def test_policy_endpoint(self):
        _, _, body = self.fetch("/api/policy", {"review_threshold": 55, "transfer_review_limit": 65000})
        self.assertEqual(json.loads(body)["policy"]["transfer_review_limit"], 65000)

    def test_demo_endpoint(self):
        _, _, body = self.fetch("/api/demo", {})
        self.assertEqual(len(json.loads(body)["results"]), 27)

    def test_csv_endpoint(self):
        status, typ, body = self.fetch("/api/export.csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", typ)
        self.assertIn(b"risk_score", body)

    def test_bad_input_returns_400(self):
        try:
            self.fetch("/api/policy", {"review_threshold": True, "transfer_review_limit": 50000})
        except HTTPError as exc:
            self.assertEqual(exc.code, 400)
        else:
            self.fail("Expected HTTP 400")

    def test_reset_endpoint(self):
        _, _, body = self.fetch("/api/reset", {})
        self.assertEqual(json.loads(body)["message"], "History cleared")
        _, _, status = self.fetch("/api/status")
        self.assertEqual(json.loads(status)["total"], 0)


if __name__ == "__main__":
    unittest.main()
