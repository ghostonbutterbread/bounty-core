import json

from bounty_core import append_event, read_events, validate_event


def test_append_event_accepts_novel_vulnerability_class(tmp_path):
    path = tmp_path / "attempts.jsonl"

    event = append_event(
        path,
        {
            "producer": "focused-test",
            "subject": {"kind": "url", "origin": "https://example.test", "path": "/probe"},
            "outcome": "observed",
            "reason": "record a newly named experimental class",
            "vuln_class": "newly-invented-boundary",
        },
    )

    assert event["vuln_class"] == "newly-invented-boundary"
    assert event["schema_version"] == 1
    assert event["attempt_id"].startswith("A-")
    assert json.loads(path.read_text(encoding="utf-8")) == event


def test_append_event_accepts_bbh_style_generic_attribution_aliases(tmp_path):
    event = append_event(
        tmp_path / "attempts.jsonl",
        {
            "tool": "existing-writer",
            "target": "https://example.test/login",
            "outcome": "stopped",
            "stop_reason": "safe stop",
        },
    )

    assert event["producer"] == "existing-writer"
    assert event["subject"] == "https://example.test/login"
    assert event["reason"] == "safe stop"


def test_append_event_recursively_redacts_secret_keys_and_sensitive_text(tmp_path):
    event = append_event(
        tmp_path / "attempts.jsonl",
        {
            "producer": "focused-test",
            "subject": "https://example.test/?token=do-not-store",
            "outcome": "observed",
            "reason": "cookie=do-not-store",
            "details": {
                "headers": {"Authorization": "Bearer do-not-store"},
                "nested": [{"password": "do-not-store"}],
            },
        },
    )

    assert event["subject"] == "https://example.test/?token=REDACTED"
    assert event["reason"] == "cookie=REDACTED"
    assert event["details"]["headers"]["Authorization"] == "REDACTED"
    assert event["details"]["nested"][0]["password"] == "REDACTED"


def test_read_events_filters_a_bounded_number_of_records_by_generic_field(tmp_path):
    path = tmp_path / "attempts.jsonl"
    for outcome in ("observed", "stopped", "observed"):
        append_event(
            path,
            {
                "producer": "focused-test",
                "subject": "https://example.test/",
                "outcome": outcome,
                "reason": "bounded query fixture",
            },
        )

    events = read_events(path, where={"outcome": "observed"}, limit=1)

    assert len(events) == 1
    assert events[0]["outcome"] == "observed"


def test_validate_event_rejects_missing_generic_attribution():
    try:
        validate_event(
            {
                "producer": "focused-test",
                "subject": "https://example.test/",
                "outcome": "observed",
            }
        )
    except ValueError as error:
        assert "reason" in str(error)
    else:
        raise AssertionError("missing reason must be rejected")


def test_read_events_skips_blank_malformed_and_invalid_jsonl_records(tmp_path):
    path = tmp_path / "attempts.jsonl"
    path.write_text(
        "\nnot-json\n{}\n" + json.dumps(
            {
                "timestamp": "2026-08-06T00:00:00Z",
                "producer": "focused-test",
                "subject": "https://example.test/",
                "outcome": "observed",
                "reason": "valid record after damaged input",
            }
        ) + "\n",
        encoding="utf-8",
    )

    events = read_events(path)

    assert len(events) == 1
    assert events[0]["reason"] == "valid record after damaged input"


def test_append_event_redacts_api_key_and_authorization_query_values(tmp_path):
    event = append_event(
        tmp_path / "attempts.jsonl",
        {
            "producer": "focused-test",
            "subject": "https://example.test/?api_key=do-not-store&authorization=bearer-secret&secret=also-private",
            "outcome": "observed",
            "reason": "api_key=do-not-store",
            "details": {"api_key": "do-not-store"},
        },
    )

    serialized = json.dumps(event)
    for secret in ("do-not-store", "bearer-secret", "also-private"):
        assert secret not in serialized
    assert "api_key=REDACTED" in event["subject"]
    assert "authorization=REDACTED" in event["subject"]
    assert "secret=REDACTED" in event["subject"]
    assert event["details"]["api_key"] == "REDACTED"


def test_read_events_normalizes_legacy_aliases_before_filtering(tmp_path):
    path = tmp_path / "attempts.jsonl"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-06T00:00:00Z",
                "tool": "legacy-xss",
                "target": "https://example.test/search?q=marker",
                "outcome": "observed",
                "stop_reason": "legacy observation",
            }
        ) + "\n",
        encoding="utf-8",
    )

    events = read_events(path, where={"producer": "legacy-xss"})

    assert len(events) == 1
    assert events[0]["producer"] == "legacy-xss"
    assert events[0]["subject"] == "https://example.test/search?q=marker"
    assert events[0]["reason"] == "legacy observation"
