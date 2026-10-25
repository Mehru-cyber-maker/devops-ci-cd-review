from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from evidencegate.cli import main
from evidencegate.demo import demo_bundle, write_demo
from evidencegate.server import make_server


class CommandTests(unittest.TestCase):
    def test_cli_pass_block_and_invalid_input_exit_codes(self):
        now = datetime(2026, 10, 25, 9, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            root = Path(tmp)
            write_demo(root, now)
            common = ["check", "--artifact", str(root/"artifact.txt"), "--policy", str(root/"policy.json"),
                      "--provenance", str(root/"provenance.json"), "--sbom", str(root/"sbom.json"),
                      "--at", "2026-10-25T09:00:00Z", "--output-dir", str(root/"result")]
            self.assertEqual(main(common+["--scan", str(root/"scan.json")]), 0)
            self.assertEqual(main(common), 1)
            (root/"scan.json").write_text('{"x":1,"x":2}')
            self.assertEqual(main(common+["--scan", str(root/"scan.json")]), 2)


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        status = response.status
        connection.close()
        return status, data

    def test_local_demo_can_be_evaluated(self):
        status, raw = self.request("GET", "/api/demo")
        self.assertEqual(status, 200)
        status, raw = self.request("POST", "/api/check", raw, {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["decision"], "PASS")

    def test_cross_origin_request_is_rejected(self):
        status, _ = self.request("GET", "/api/demo", headers={"Origin": "https://attacker.invalid"})
        self.assertEqual(status, 403)

    def test_unexpected_host_is_rejected(self):
        status, _ = self.request("GET", "/", headers={"Host": "attacker.invalid"})
        self.assertEqual(status, 421)

    def test_duplicate_keys_in_uploaded_file_remain_detectable(self):
        b = demo_bundle()
        b["sbom"] = '{"bomFormat":"CycloneDX","bomFormat":"other"}'
        status, raw = self.request("POST", "/api/check", json.dumps(b), {"Content-Type": "application/json"})
        self.assertEqual(status, 422)
        self.assertIn("Duplicate JSON key", json.loads(raw)["error"])

    def test_path_traversal_is_not_served(self):
        status, _ = self.request("GET", "/../../README.md")
        self.assertEqual(status, 404)

    def test_malformed_json_and_media_type(self):
        self.assertEqual(self.request("POST", "/api/check", "{", {"Content-Type": "application/json"})[0], 422)
        self.assertEqual(self.request("POST", "/api/check", "{}")[0], 415)


if __name__ == "__main__":
    unittest.main()
