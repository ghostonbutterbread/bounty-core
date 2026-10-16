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


def test_status_history_appends_without_editing_original_report(tmp_path, monkeypatch):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    monkeypatch.setattr(store, "notify", Mock(side_effect=AssertionError("status changes must not send")))
    original = sample(store, notify=False)["incident"]
    original_bytes = store.events_path.read_bytes()

    first = store.append_status(original["incident_id"], status="investigating", producer="operator", note="Review begun")
    second = store.append_status(original["incident_id"], status="contained", producer="operator", note="Credential rotated")
    history = store.history(original["incident_id"])

    assert store.events_path.read_bytes().startswith(original_bytes)
    assert store.get(original["incident_id"]) == original
    assert history == [original, first, second]
    assert first["record_type"] == second["record_type"] == "status"
    assert first["event_id"] != second["event_id"]
    assert first["incident_id"] == second["incident_id"] == original["incident_id"]
    assert [row["status"] for row in history[1:]] == ["investigating", "contained"]
    history[0]["action"] = "tampered"
    reopened = SafetyIncidentStore("sample", root_override=tmp_path)
    assert reopened.get(original["incident_id"]) == original
    assert reopened.history(original["incident_id"]) == [original, first, second]
    assert not hasattr(store, "update") and not hasattr(store, "delete")


def test_status_validation_and_redaction_do_not_mutate_report(tmp_path):
    store = SafetyIncidentStore("sample", root_override=tmp_path)
    original = sample(store, notify=False)["incident"]
    original_bytes = store.events_path.read_bytes()
    with pytest.raises(ValueError):
        store.append_status("SI-missing", status="resolved", producer="operator", note="checked")
    with pytest.raises(ValueError):
        store.append_status(original["incident_id"], status="", producer="operator", note="checked")
    assert store.events_path.read_bytes() == original_bytes
    assert store.history("SI-missing") == []

    status = store.append_status(
        original["incident_id"], status="investigating", producer="operator",
        note="Review https://site.test/?token=private",
    )
    assert "private" not in store.events_path.read_text()
    assert status["note"] == "Review https://site.test/?token=REDACTED"
    assert store.get(original["incident_id"]) == original
