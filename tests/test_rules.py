"""
Tests for the detection rules (SQLi and XSS).

Testing two things for each:
1. Detection rate — what percentage of known payloads do we catch?
   Target is >= 90%.
2. False positive rate — how many legitimate inputs get wrongly flagged?
   Should be as close to 0% as possible.

The payloads come from files in tests/payloads/.
"""

import pytest
import os
import requests

from rules.sqli import check_sqli, scan_request as sqli_scan
from rules.xss import check_xss, scan_request as xss_scan

# load test payloads from files
PAYLOAD_DIR = os.path.join(os.path.dirname(__file__), "payloads")


def load_payloads(filename):
    """Read payloads from a file, one per line, skip blanks."""
    filepath = os.path.join(PAYLOAD_DIR, filename)
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]


SQLI_PAYLOADS = load_payloads("sqli_payloads.txt")
XSS_PAYLOADS = load_payloads("xss_payloads.txt")
LEGIT_INPUTS = load_payloads("legitimate_inputs.txt")

PROXY_URL = "http://localhost:5000"
TARGET_URL = "http://localhost:8080"


def is_service_running(url):
    try:
        requests.get(url, timeout=3)
        return True
    except requests.exceptions.ConnectionError:
        return False


class TestSQLiDetection:
    """Test that known SQLi payloads are detected."""

    def test_detection_rate_above_90_percent(self):
        """The main test: do we catch at least 90% of known SQLi?"""
        detected = 0
        missed = []

        for payload in SQLI_PAYLOADS:
            result = check_sqli(payload)
            if result:
                detected += 1
            else:
                missed.append(payload)

        rate = (detected / len(SQLI_PAYLOADS)) * 100
        print(f"\nSQLi Detection Rate: {detected}/{len(SQLI_PAYLOADS)} = {rate:.1f}%")
        if missed:
            print(f"Missed payloads:")
            for m in missed:
                print(f"  - {m}")

        assert rate >= 90.0, f"Detection rate {rate:.1f}% is below 90% target"

    def test_union_based_detected(self):
        """UNION SELECT should always be caught."""
        assert check_sqli("' UNION SELECT null,null --") is not None
        assert check_sqli("' UNION ALL SELECT username FROM users") is not None

    def test_time_based_detected(self):
        """SLEEP and WAITFOR should be caught."""
        assert check_sqli("' OR SLEEP(5) --") is not None
        assert check_sqli("'; WAITFOR DELAY '0:0:5' --") is not None

    def test_boolean_based_detected(self):
        """OR 1=1 type tautologies should be caught."""
        assert check_sqli("' OR '1'='1") is not None
        assert check_sqli("1 OR 1=1") is not None

    def test_stacked_queries_detected(self):
        """Semicolon followed by dangerous commands should be caught."""
        assert check_sqli("1; DROP TABLE users --") is not None
        assert check_sqli("1; SELECT * FROM users --") is not None

    def test_error_based_detected(self):
        """EXTRACTVALUE and UPDATEXML should be caught."""
        assert check_sqli("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))") is not None
        assert check_sqli("' AND UPDATEXML(1,CONCAT(0x7e,user()),1)") is not None

    def test_result_contains_match_details(self):
        """When something is detected, the result should tell me what matched."""
        result = check_sqli("' UNION SELECT null --")
        assert result is not None
        assert "category" in result
        assert "description" in result
        assert "matched" in result
        assert result["category"] == "union"


class TestFalsePositives:
    """Make sure normal inputs don't trigger the rules."""

    def test_false_positive_rate(self):
        """Legitimate inputs should NOT trigger SQLi detection."""
        false_positives = []

        for text in LEGIT_INPUTS:
            result = check_sqli(text)
            if result:
                false_positives.append((text, result))

        fp_rate = (len(false_positives) / len(LEGIT_INPUTS)) * 100
        print(f"\nFalse Positive Rate: {len(false_positives)}/{len(LEGIT_INPUTS)} = {fp_rate:.1f}%")
        if false_positives:
            print("False positives:")
            for text, result in false_positives:
                print(f"  - '{text}' triggered: {result['description']}")

        # allow up to 10% false positives (ideally 0)
        assert fp_rate <= 10.0, f"False positive rate {fp_rate:.1f}% is too high"

    def test_normal_name_with_apostrophe(self):
        """Names like O'Brien shouldn't be flagged."""
        assert check_sqli("My name is O'Brien") is None

    def test_normal_sentence_with_or(self):
        """Normal use of the word 'or' shouldn't trigger."""
        assert check_sqli("Tea or coffee?") is None

    def test_normal_number(self):
        """Plain numbers shouldn't trigger."""
        assert check_sqli("12345") is None


class TestScanRequest:
    """Test the combined query+body scanning function."""

    def test_detects_sqli_in_query_string(self):
        result = sqli_scan("id=1' OR 1=1--&Submit=Submit", "")
        assert result is not None
        assert result["source"] == "query_string"

    def test_detects_sqli_in_body(self):
        result = sqli_scan("", "username=admin' OR 1=1 --&password=x")
        assert result is not None
        assert result["source"] == "body"

    def test_clean_request_passes(self):
        result = sqli_scan("page=home&lang=en", "username=admin&password=secret")
        assert result is None


class TestIntegration:
    """Test that the proxy actually blocks SQLi through HTTP."""

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running on port 5000"
    )
    def test_sqli_in_url_gets_blocked(self):
        """A request with SQLi in the query string should get a 403."""
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            params={"id": "1' OR 1=1 --", "Submit": "Submit"},
            allow_redirects=False,
        )
        assert resp.status_code == 403
        assert "SQL Injection" in resp.text

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running on port 5000"
    )
    def test_sqli_in_post_body_gets_blocked(self):
        """A POST with SQLi in the body should get a 403."""
        resp = requests.post(
            f"{PROXY_URL}/vulnerabilities/sqli/",
            data={"id": "' UNION SELECT null,null --", "Submit": "Submit"},
            allow_redirects=False,
        )
        assert resp.status_code == 403

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running on port 5000"
    )
    def test_legitimate_request_passes_through(self):
        """Normal requests should still get forwarded."""
        resp = requests.get(
            f"{PROXY_URL}/login.php",
            allow_redirects=False,
        )
        assert resp.status_code == 200


# =============================================
# XSS DETECTION TESTS (Sprint 6)
# =============================================


class TestXSSDetection:
    """Test that known XSS payloads are detected."""

    def test_detection_rate_above_90_percent(self):
        """Do we catch at least 90% of known XSS payloads?"""
        detected = 0
        missed = []

        for payload in XSS_PAYLOADS:
            result = check_xss(payload)
            if result:
                detected += 1
            else:
                missed.append(payload)

        rate = (detected / len(XSS_PAYLOADS)) * 100
        print(f"\nXSS Detection Rate: {detected}/{len(XSS_PAYLOADS)} = {rate:.1f}%")
        if missed:
            print(f"Missed payloads:")
            for m in missed:
                print(f"  - {m}")

        assert rate >= 90.0, f"Detection rate {rate:.1f}% is below 90% target"

    def test_script_tag_detected(self):
        assert check_xss("<script>alert(1)</script>") is not None
        assert check_xss("<SCRIPT>alert(1)</SCRIPT>") is not None

    def test_event_handlers_detected(self):
        assert check_xss('<img src=x onerror=alert(1)>') is not None
        assert check_xss('<body onload=alert(1)>') is not None
        assert check_xss('<div onmouseover="alert(1)">') is not None

    def test_javascript_protocol_detected(self):
        assert check_xss('<a href="javascript:alert(1)">') is not None
        assert check_xss('javascript:alert(1)') is not None

    def test_dom_access_detected(self):
        assert check_xss('document.cookie') is not None
        assert check_xss('document.write("hacked")') is not None

    def test_dangerous_tags_detected(self):
        assert check_xss('<iframe src="http://evil.com">') is not None
        assert check_xss('<object data="javascript:alert(1)">') is not None
        assert check_xss('<embed src="javascript:alert(1)">') is not None

    def test_result_contains_details(self):
        result = check_xss("<script>alert(1)</script>")
        assert result is not None
        assert "category" in result
        assert "description" in result
        assert "matched" in result
        assert result["category"] == "script_tag"


class TestXSSFalsePositives:
    """Make sure normal inputs don't trigger XSS rules."""

    def test_false_positive_rate(self):
        """Legitimate inputs should NOT trigger XSS detection."""
        false_positives = []

        for text in LEGIT_INPUTS:
            result = check_xss(text)
            if result:
                false_positives.append((text, result))

        fp_rate = (len(false_positives) / len(LEGIT_INPUTS)) * 100
        print(f"\nXSS False Positive Rate: {len(false_positives)}/{len(LEGIT_INPUTS)} = {fp_rate:.1f}%")
        if false_positives:
            print("False positives:")
            for text, result in false_positives:
                print(f"  - '{text}' triggered: {result['description']}")

        assert fp_rate <= 10.0, f"False positive rate {fp_rate:.1f}% is too high"

    def test_normal_html_discussion(self):
        """Talking about HTML shouldn't trigger."""
        assert check_xss("I'm learning about the script element in class") is None

    def test_normal_javascript_mention(self):
        """Mentioning JavaScript as a word shouldn't trigger."""
        assert check_xss("I prefer Python over JavaScript for backend work") is None


class TestXSSScanRequest:
    """Test combined query+body scanning for XSS."""

    def test_detects_xss_in_query_string(self):
        result = xss_scan("search=<script>alert(1)</script>", "")
        assert result is not None
        assert result["source"] == "query_string"

    def test_detects_xss_in_body(self):
        result = xss_scan("", "comment=<img src=x onerror=alert(1)>")
        assert result is not None
        assert result["source"] == "body"

    def test_clean_request_passes(self):
        result = xss_scan("page=about&lang=en", "name=Maria&message=Hello")
        assert result is None


class TestXSSIntegration:
    """Test that the proxy actually blocks XSS through HTTP."""

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running"
    )
    def test_xss_in_url_gets_blocked(self):
        resp = requests.get(
            f"{PROXY_URL}/vulnerabilities/xss_r/",
            params={"name": "<script>alert(1)</script>"},
            allow_redirects=False,
        )
        assert resp.status_code == 403
        assert "XSS" in resp.text

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running"
    )
    def test_xss_in_post_body_gets_blocked(self):
        resp = requests.post(
            f"{PROXY_URL}/vulnerabilities/xss_s/",
            data={"txtName": "hacker", "mtxMessage": "<script>alert(1)</script>"},
            allow_redirects=False,
        )
        assert resp.status_code == 403

    @pytest.mark.skipif(
        not is_service_running(PROXY_URL),
        reason="SecureShield proxy not running"
    )
    def test_legitimate_request_still_passes(self):
        resp = requests.get(f"{PROXY_URL}/login.php", allow_redirects=False)
        assert resp.status_code == 200
