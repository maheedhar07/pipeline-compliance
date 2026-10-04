from datetime import datetime, timedelta

from typer.testing import CliRunner

from pch.cli import app
from pch.store import repository as store
from pch.store.db import session_scope
from pch.timeutil import utcnow
from pch.web import queries as Q


def _scan(url, sid, status, started, mode="live", **kw):
    with session_scope(url) as s:
        row = store.create_scan(s, sid, mode, started)
        row.status = status
        row.finished_at = started + timedelta(minutes=5)
        for k, v in kw.items():
            setattr(row, k, v)


def test_humanize_age():
    h = Q.humanize_age
    assert h(timedelta(seconds=10)) == "just now" and h(timedelta(minutes=-5)) == "just now"
    assert h(timedelta(minutes=30)) == "30 min ago" and h(timedelta(hours=5)) == "5 h ago" and h(timedelta(days=3)) == "3 d ago"


def test_freshness_states(tmp_path):
    url = f"sqlite:///{tmp_path}/f.db"
    now = utcnow()
    with session_scope(url) as s:
        assert Q.freshness(s, 36, now) == {"state": "none"}
    _scan(url, "a", "complete", now - timedelta(hours=3))
    with session_scope(url) as s:
        f = Q.freshness(s, 36, now)
        assert f["state"] == "ok" and f["mode"] == "live" and f["age_text"].endswith("h ago")
        assert Q.freshness(s, 2, now)["state"] == "stale"  # older than the limit
    _scan(url, "b", "failed", now - timedelta(hours=1), summary={"error": "timeout: exceeded 240 minutes"})
    with session_scope(url) as s:
        f = Q.freshness(s, 36, now)
        assert f["state"] == "failed" and "timeout" in f["failed_reason"] and f["scan_id"] == "a"
    _scan(url, "c", "complete", now - timedelta(minutes=20))  # a later success clears the failure
    with session_scope(url) as s:
        assert Q.freshness(s, 36, now)["state"] == "ok"


def test_freshness_with_only_failed_scans(tmp_path):
    url = f"sqlite:///{tmp_path}/f2.db"
    _scan(url, "x", "failed", utcnow() - timedelta(hours=1))
    with session_scope(url) as s:
        f = Q.freshness(s, 36)
        assert f["state"] == "failed" and f["scan_id"] is None


def test_banner_and_header_rendered(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from pch.web.app import create_app

    url = f"sqlite:///{tmp_path}/f3.db"
    _scan(url, "old", "complete", datetime(2026, 1, 1, 12, 0, 0), mode="demo", repos_total=0)
    c = TestClient(create_app(url))
    t = c.get("/").text
    assert 'id="freshness-banner"' in t and "out of date" in t and "SCAN_STALE_HOURS" in t
    assert "Last scan:" in t and "(demo)" in t
    _scan(url, "new", "complete", utcnow() - timedelta(minutes=10), mode="live")
    t = c.get("/").text
    assert 'id="freshness-banner"' not in t and "Last scan: 5 min ago (live)" in t
    _scan(url, "bad", "failed", utcnow() - timedelta(minutes=2), summary={"error": "<script>alert(1)</script>"})
    t = c.get("/").text
    assert "The latest scan failed" in t and "<script>alert(1)" not in t and "&lt;script&gt;" in t


def test_scans_summary_cli(tmp_path):
    url = f"sqlite:///{tmp_path}/s.db"
    r = CliRunner().invoke(app, ["scans", "summary", "--exit-code", "4", "--db", url])
    assert r.exit_code == 0 and "lock" in r.output and "No scan was recorded" in r.output
    _scan(url, "s1", "complete", utcnow(), repos_total=10, repos_failed=1, findings_total=42, duration_s=12.5,
          summary={"status_counts": {"COMPLIANT": 6, "AT_RISK": 2, "NON_COMPLIANT": 1, "NOT_SCANNED": 1}})
    out = CliRunner().invoke(app, ["scans", "summary", "--exit-code", "0", "--since", (utcnow() - timedelta(minutes=5)).isoformat(), "--db", url]).output
    assert "succeeded" in out and "6 compliant, 2 at risk, 1 non-compliant, 1 not scanned" in out and "Findings | 42" in out
    old = CliRunner().invoke(app, ["scans", "summary", "--exit-code", "2", "--since", "2999-01-01T00:00:00Z", "--db", url]).output
    assert "No scan was recorded by this run" in old and "Configuration error" in old
    assert CliRunner().invoke(app, ["scans", "summary", "--since", "garbage", "--db", url]).exit_code == 2
    bad = CliRunner().invoke(app, ["scans", "summary", "--exit-code", "3", "--db", "sqlite:////nonexistent-dir/x.db"])
    assert bad.exit_code == 0 and "unavailable" in bad.output
