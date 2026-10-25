"""Optional real-browser checks of the unchanged dashboard."""

import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from threading import Thread

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent/"evidencegate"))

from evidencegate.server import make_server
from evidencegate.demo import ARTIFACT, DEMO_DIGEST
from playwright.sync_api import sync_playwright, expect


def main():
    observed = []
    server = make_server(0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    address = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path="/usr/bin/chromium", headless=True, args=["--no-sandbox"])
            version = browser.version
            page = browser.new_page(viewport={"width": 1440, "height": 1100}, timezone_id="Asia/Karachi")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            assert page.goto(address).status == 200
            for scenario, expected, failed_rule in [("clean", "PASS", None), ("mismatch", "BLOCK", "EG008"),
                                                     ("stale", "BLOCK", "EG009"), ("vulnerable", "BLOCK", "EG010")]:
                page.locator("#scenario").select_option(scenario)
                page.get_by_role("button", name="Load example").click()
                expect(page.locator("#results")).to_be_hidden()
                page.get_by_role("button", name="Check evidence").click()
                expect(page.locator("#results")).to_be_visible()
                expect(page.locator("#decision")).to_have_text(expected)
                if failed_rule:
                    page.locator("#failed-only").check()
                    assert page.locator("#findings tr").count() == 1
                    assert page.locator("#findings").inner_text().startswith(failed_rule)
                    page.locator("#failed-only").uncheck()
                observed.append({"test": scenario+"_decision", "result": "PASS", "expected_decision": expected})
            page.locator("#failed-only").check()
            assert page.locator("#findings tr").count() == 1
            page.locator("#failed-only").uncheck()
            assert page.locator("#findings tr").count() == 10
            observed.append({"test": "failed_check_filter", "result": "PASS"})
            with tempfile.TemporaryDirectory() as tmp:
                for kind in ["json", "csv"]:
                    with page.expect_download() as event:
                        page.locator("#download-"+kind).click()
                    target = Path(tmp)/("report."+kind)
                    event.value.save_as(target)
                    if kind == "json":
                        assert json.loads(target.read_text())["decision"] == "BLOCK"
                    else:
                        assert len(list(csv.DictReader(target.open()))) == 10
                    observed.append({"test": kind+"_download", "result": "PASS"})
            page.locator("#scenario").select_option("mismatch")
            page.get_by_role("button", name="Load example").click()
            page.get_by_role("button", name="Check evidence").click()
            expect(page.locator("#results")).to_be_visible()
            (ROOT/"figures").mkdir(exist_ok=True)
            page.screenshot(path=str(ROOT/"figures"/"supplement_dashboard.png"), full_page=True)
            page.locator("#scan-file").set_input_files({"name": "duplicate.json", "mimeType": "application/json", "buffer": b'{"x":1,"x":2}'})
            expect(page.locator("#scan-name")).to_have_text("duplicate.json")
            page.get_by_role("button", name="Check evidence").click()
            expect(page.locator("#error")).to_contain_text("Duplicate JSON key")
            observed.append({"test": "duplicate_key_upload_rejected", "result": "PASS"})
            page.locator("#artifact-file").set_input_files({"name": "artifact.txt", "mimeType": "text/plain", "buffer": ARTIFACT})
            expect(page.locator("#digest")).to_have_value(DEMO_DIGEST)
            observed.append({"test": "browser_artifact_hash", "result": "PASS"})
            mobile = browser.new_page(viewport={"width": 390, "height": 844}, timezone_id="Asia/Karachi")
            mobile.goto(address)
            mobile.get_by_role("button", name="Load example").click()
            expect(mobile.locator("#scan-name")).to_have_text("synthetic-scan.json")
            mobile.get_by_role("button", name="Check evidence").click()
            expect(mobile.locator("#results")).to_be_visible()
            expect(mobile.locator("#decision")).to_have_text("PASS")
            assert mobile.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            observed.append({"test": "mobile_layout_and_clean_check", "result": "PASS"})
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    result = {"browser": "Chromium "+version, "desktop_width": 1440, "mobile_width": 390,
              "tests": observed, "passed": len(observed), "javascript_errors": errors,
              "interpretation": "Automated interface checks, not a user study or production deployment."}
    (ROOT/"results"/"browser_tests.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(f"{len(observed)} browser checks passed; no JavaScript errors.")


if __name__ == "__main__":
    main()
