from __future__ import annotations

import json
from email.message import Message
from http.client import IncompleteRead
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from bounty_core import SafetyIncidentStore
from bounty_core import safety_incidents as incidents


def sample(store, **overrides):
    fields = dict(
        producer="hunter-1", run_id="run-1", category="non-owned-mutation",
        outcome="uncertain", action="POST changed a record", subject="owned? /records/3",
        impact="May have changed another user's record", containment="Stopped; no further writes",
    )
    fields.update(overrides)
    return store.record(**fields)


def test_persists_redacted_incident_before_notification_and_keeps_failure_receipt(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", lane="api", root_override=tmp_path)
    webhook = "https://discord.com/api/webhooks/123456/abc-SECRET_7"
    monkeypatch.setenv(incidents.WEBHOOK_ENV, webhook)

    # Capture the persisted ID from the record only when transport is called.
    original_get = store.get
    def check_then_fail(req, timeout):
        incident_id = json.loads(store.events_path.read_text())["incident_id"]
        assert original_get(incident_id)
        assert timeout == 5
        raise URLError("failed: " + webhook)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=check_then_fail))
    result = sample(store, subject="https://site.test/path?token=private " + webhook)
    assert result["notification"]["state"] == "delivery-unknown"
    assert result["incident"]["subject"] == "https://site.test/path?token=REDACTED [REDACTED WEBHOOK]"
    assert webhook not in store.events_path.read_text()
    assert webhook not in store.notifications_path.read_text()
    assert json.loads(store.notifications_path.read_text().splitlines()[-1])["incident_id"] == result["incident"]["incident_id"]
    assert store.events_path.stat().st_mode & 0o777 == 0o600


def test_sends_fixed_context_only_without_mentions_or_raw_subject(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/abc-SECRET_7")
    sent = []
    sent_user_agents = []
    sent_urls = []
    def deliver(req, timeout):
        sent.append(json.loads(req.data))
        sent_user_agents.append(req.get_header("User-agent"))
        sent_urls.append(req.full_url)
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    result = sample(store, subject="@everyone private person's record", impact="password is SECRET")
    assert result["notification"]["state"] == "sent"
    assert sent_user_agents and sent_user_agents[0].startswith("Mozilla/5.0")
    assert sent_urls[0].endswith("?wait=true")
    assert sent[0]["allowed_mentions"] == {"parse": []}
    assert "@everyone" not in sent[0]["content"]
    assert "password" not in sent[0]["content"]
    assert result["incident"]["incident_id"] in sent[0]["content"]
    assert len(store.events_path.read_text().splitlines()) == 1


def test_waited_delivery_records_discord_message_id(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    response = Mock(status=200, read=Mock(return_value=b'{"id":"123456789"}'))
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=lambda req, timeout: Mock(__enter__=lambda self: response, __exit__=lambda *args: None)))
    result = sample(store)
    assert result["notification"]["state"] == "sent"
    assert result["notification"]["message_id"] == "123456789"
    assert json.loads(store.notifications_path.read_text().splitlines()[-1])["message_id"] == "123456789"


def test_accepted_delivery_with_truncated_body_keeps_final_receipt(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    response = Mock(status=200, read=Mock(side_effect=IncompleteRead(b'{"id":', 4)))
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=lambda req, timeout: Mock(__enter__=lambda self: response, __exit__=lambda *args: None)))
    result = sample(store)
    assert result["notification"]["state"] == "sent"
    assert "message_id" not in result["notification"]
    assert json.loads(store.notifications_path.read_text().splitlines()[-1])["state"] == "sent"
    assert store.get(result["incident"]["incident_id"])


def test_unconfigured_and_invalid_webhooks_never_send_and_can_retry(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.delenv(incidents.WEBHOOK_ENV, raising=False)
    result = sample(store)
    incident_id = result["incident"]["incident_id"]
    assert result["notification"]["state"] == "not-configured"
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "http://example.test/api/webhooks/123/token")
    assert store.notify(incident_id)["state"] == "invalid-configuration"
    assert len(store.notifications_path.read_text().splitlines()) == 4
    assert store.get("absent") is None
    with pytest.raises(ValueError):
        store.notify("absent")


def test_http_failure_is_receipted_without_response_body_or_url(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=Mock(side_effect=HTTPError("secret-url", 429, "secret", Message(), None))))
    result = sample(store)
    assert result["notification"]["state"] == "http-429"
    assert "secret" not in store.notifications_path.read_text()


def test_invalid_record_does_not_write_or_notify(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setattr(store, "notify", Mock())
    with pytest.raises(ValueError):
        sample(store, action="")
    assert not store.events_path.exists()
    store.notify.assert_not_called()


def test_cli_reports_missing_notification_as_nonzero_after_persistence(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv(incidents.WEBHOOK_ENV, raising=False)
    code = incidents.main([
        "--program", "sample", "--lane", "web", "--root", str(tmp_path),
        "record", "--producer", "hunter", "--run-id", "run", "--category", "production-risk",
        "--action", "dangerous POST", "--subject", "server", "--impact", "uncertain",
        "--containment", "stopped",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["notification"]["state"] == "not-configured"
    assert SafetyIncidentStore("sample", root_override=tmp_path).get(result["incident"]["incident_id"])


def test_interrupted_tail_is_separated_before_next_incident(tmp_path):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    first = sample(store, notify=False)["incident"]["incident_id"]
    with store.events_path.open("ab") as handle:
        handle.write(b'{"partial":\xe2')  # interrupted in the middle of UTF-8
    second = sample(store, notify=False)["incident"]["incident_id"]
    assert store.get(first) is not None
    assert store.get(second) is not None
    assert len(store.events_path.read_text(errors="replace").splitlines()) == 3


def test_receipt_append_failure_keeps_id_visible_and_does_not_send(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    real_append = incidents._append
    def fail_receipt(path, row):
        if path == store.notifications_path:
            raise OSError("receipt unavailable")
        real_append(path, row)
    monkeypatch.setattr(incidents, "_append", fail_receipt)
    monkeypatch.setattr(incidents, "build_opener", Mock(side_effect=AssertionError("must not send")))
    result = sample(store)
    assert result["notification"]["state"] == "receipt-write-failed"
    assert store.get(result["incident"]["incident_id"])


def test_post_delivery_receipt_failure_has_pending_receipt_and_id(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    sent = []
    def deliver(req, timeout):
        sent.append(req)
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    real_append = incidents._append
    def fail_final(path, row):
        if path == store.notifications_path and row["state"] != "pending":
            raise OSError("receipt unavailable")
        real_append(path, row)
    monkeypatch.setattr(incidents, "_append", fail_final)
    result = sample(store)
    assert len(sent) == 1
    assert result["notification"]["state"] == "receipt-write-failed"
    assert json.loads(store.notifications_path.read_text())["state"] == "pending"
    assert store.get(result["incident"]["incident_id"])


@pytest.mark.parametrize("webhook", [
    "discord.com/api/webhooks/123456/fake-secret",
    "https://discord.com/api/v10/webhooks/123456/fake-secret",
    "https://canary.discord.com/api/webhooks/123456/fake-secret",
])
def test_webhook_path_variants_never_persist(tmp_path, webhook):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    sample(store, subject="Saw " + webhook, notify=False)
    assert "fake-secret" not in store.events_path.read_text()


def test_existing_permissive_event_file_is_tightened(tmp_path):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    store.root.mkdir(parents=True)
    store.events_path.write_text("")
    store.events_path.chmod(0o644)
    sample(store, notify=False)
    assert store.events_path.stat().st_mode & 0o777 == 0o600


def test_invalid_cli_family_has_safe_error(tmp_path, capsys):
    code = incidents.main(["--program", "sample", "--lane", "web", "--family", "bad", "--root", str(tmp_path), "notify", "SI-unknown"])
    assert code == 2
    assert "traceback" not in capsys.readouterr().err.lower()


@pytest.mark.parametrize("severity,color", [
    ("unknown", 0x95A5A6), ("low", 0x3498DB), ("medium", 0xF1C40F),
    ("high", 0xE67E22), ("critical", 0xE74C3C),
])
def test_severity_is_stored_and_colors_discord_embed(tmp_path, monkeypatch, severity, color):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    payloads = []
    def deliver(req, timeout):
        payloads.append(json.loads(req.data))
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    result = sample(store, severity=severity)
    assert result["incident"]["severity"] == severity
    payload = payloads[0]
    assert payload["allowed_mentions"] == {"parse": []}
    assert severity.upper() in payload["content"]
    assert result["incident"]["incident_id"] in payload["content"]
    embed = payload["embeds"][0]
    assert embed["color"] == color
    assert {f["name"]: f["value"] for f in embed["fields"]} == {
        "Action": "POST changed a record", "Impact": "May have changed another user's record",
        "Containment": "Stopped; no further writes",
    }


def test_embed_uses_redacted_bounded_single_line_fields(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    secret_url = "https://discord.com/api/webhooks/123456/abc-SECRET_7"
    monkeypatch.setenv(incidents.WEBHOOK_ENV, secret_url)
    payloads = []
    def deliver(req, timeout):
        payloads.append(json.loads(req.data))
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    result = sample(store, action="POST\n@everyone \x1b[31m" + secret_url + " " + "x" * 2000,
                    impact="token=private\r\n@here", containment="stopped\nthen investigated")
    blob = json.dumps(payloads[0])
    assert secret_url not in blob and "private" not in blob
    assert "@everyone" not in blob and "@here" not in blob
    assert "\\u001b" not in blob
    fields = payloads[0]["embeds"][0]["fields"]
    assert all("\n" not in field["value"] and len(field["value"]) <= 1024 for field in fields)
    assert "[REDACTED WEBHOOK]" in fields[0]["value"]
    assert fields[0]["value"].endswith("…")
    assert result["notification"]["state"] == "sent"


def test_cli_reports_fsynced_incident_on_stderr_before_network(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    def deliver(req, timeout):
        rows = (tmp_path / "web_bounty/sample/web/safety_incidents/events.jsonl").read_text().splitlines()
        assert len(rows) == 1
        assert rows[0] and "SI-" in capsys.readouterr().err
        raise URLError("offline")
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    code = incidents.main([
        "--program", "sample", "--lane", "web", "--root", str(tmp_path), "record",
        "--producer", "hunter", "--run-id", "run", "--category", "production-risk",
        "--severity", "high", "--action", "dangerous POST", "--subject", "server",
        "--impact", "uncertain", "--containment", "stopped",
    ])
    output = capsys.readouterr()
    assert code == 1
    assert output.out.startswith('{"incident":')
    assert json.loads(output.out)["incident"]["severity"] == "high"


def test_broken_terminal_does_not_suppress_notification(tmp_path, monkeypatch, capsys):
    calls = []
    def notify(self, incident_id):
        assert self.get(incident_id) is not None
        calls.append(incident_id)
        return {"incident_id": incident_id, "state": "sent"}
    class BrokenTerminal:
        def write(self, text):
            raise BrokenPipeError("terminal closed")
    monkeypatch.setattr(SafetyIncidentStore, "notify", notify)
    monkeypatch.setattr(incidents.sys, "stderr", BrokenTerminal())
    code = incidents.main([
        "--program", "sample", "--lane", "web", "--root", str(tmp_path), "record",
        "--producer", "hunter", "--run-id", "run", "--category", "production-risk",
        "--action", "dangerous POST", "--subject", "server", "--impact", "uncertain",
        "--containment", "stopped",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert calls == [result["incident"]["incident_id"]]
    assert result["notification"]["state"] == "sent"


def test_old_caller_defaults_unknown_and_invalid_severity_writes_nothing(tmp_path):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    assert sample(store, notify=False)["incident"]["severity"] == "unknown"
    with pytest.raises(ValueError):
        sample(store, severity="emergency", notify=False)
    assert len(store.events_path.read_text().splitlines()) == 1


def test_cli_fsyncs_before_console_and_network_even_if_receipt_fails(tmp_path, monkeypatch, capsys):
    fsynced = []
    original_fsync = incidents.os.fsync
    def sync(fd):
        original_fsync(fd)
        fsynced.append(fd)
    monkeypatch.setattr(incidents.os, "fsync", sync)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    real_append = incidents._append
    def fail_receipt(path, row):
        if path.name == "notifications.jsonl":
            assert fsynced
            assert "SI-" in capsys.readouterr().err
            raise OSError("receipt failed")
        real_append(path, row)
    monkeypatch.setattr(incidents, "_append", fail_receipt)
    monkeypatch.setattr(incidents, "build_opener", Mock(side_effect=AssertionError("no network")))
    code = incidents.main([
        "--program", "sample", "--lane", "web", "--root", str(tmp_path), "record",
        "--producer", "hunter", "--run-id", "run", "--category", "production-risk",
        "--action", "dangerous POST", "--subject", "server", "--impact", "uncertain",
        "--containment", "stopped",
    ])
    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["notification"]["state"] == "receipt-write-failed"
    assert result["incident"]["incident_id"] in (tmp_path / "web_bounty/sample/web/safety_incidents/events.jsonl").read_text()


def test_legacy_incident_without_severity_can_still_be_notified(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    row = sample(store, notify=False)["incident"]
    del row["severity"]
    store.events_path.write_text(json.dumps(row) + "\n")
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    payloads = []
    def deliver(req, timeout):
        payloads.append(json.loads(req.data))
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    assert store.notify(row["incident_id"])["state"] == "sent"
    assert payloads[0]["embeds"][0]["color"] == 0x95A5A6


def test_control_only_embed_field_has_discord_valid_fallback(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setenv(incidents.WEBHOOK_ENV, "https://discord.com/api/webhooks/123456/token")
    payloads = []
    def deliver(req, timeout):
        payloads.append(json.loads(req.data))
        return Mock(__enter__=lambda self: Mock(status=204), __exit__=lambda *args: None)
    monkeypatch.setattr(incidents, "build_opener", lambda *args: Mock(open=deliver))
    sample(store, action="\x1b", impact="\x1b")
    assert all(field["value"] for field in payloads[0]["embeds"][0]["fields"])
