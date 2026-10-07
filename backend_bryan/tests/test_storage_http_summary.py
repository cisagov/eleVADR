from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend_bryan.auth.models import AuthPrincipal
from backend_bryan.integration import http_reference_server as server


class FakeCaptureStore:
    def usage_all(self):
        return [
            {
                "ownerId": "user-1",
                "username": "bryan",
                "captureCount": 2,
                "captureBytes": 10_000,
                "limitBytes": 0,
                "remainingBytes": None,
                "retentionDays": 0,
            },
            {
                "ownerId": "user-2",
                "username": "mina",
                "captureCount": 1,
                "captureBytes": 5_000,
                "limitBytes": 0,
                "remainingBytes": None,
                "retentionDays": 0,
            },
        ]

    def find_orphans(self):
        return []


class FakeReportStore:
    def usage_all(self):
        return {
            "user-1": {"reportCount": 3, "reportBytes": 2_000},
            "user-2": {"reportCount": 1, "reportBytes": 1_000},
            "user-3": {"reportCount": 2, "reportBytes": 4_000},
        }


def make_handler(role: str):
    handler = object.__new__(server.Handler)
    handler.path = f"{server.STORAGE_PATH}?scope=all"
    handler.headers = {}

    principal = AuthPrincipal(
        "user-1",
        "bryan",
        True,
        role,
    )

    handler._require_authenticated_request = lambda: True
    handler._current_principal = lambda: principal

    responses = []
    handler._json = lambda status, payload: responses.append(
        (status, payload)
    )

    return handler, responses


@pytest.fixture
def storage_services(monkeypatch):
    monkeypatch.setattr(
        server,
        "_AUTH_SERVICE",
        SimpleNamespace(
            config=SimpleNamespace(
                pcap_storage_limit_bytes=0,
                pcap_retention_days=0,
            )
        ),
    )
    monkeypatch.setattr(server, "_CAPTURE_STORE", FakeCaptureStore())
    monkeypatch.setattr(server, "_REPORT_STORE", FakeReportStore())


def test_admin_storage_summary_aggregates_all_users(storage_services):
    handler, responses = make_handler("admin")

    handler.do_GET()

    status, response = responses[-1]

    assert status == 200
    assert response["scope"] == "all"

    assert response["captureCount"] == 3
    assert response["captureBytes"] == 15_000

    assert response["reportCount"] == 6
    assert response["reportBytes"] == 7_000

    assert response["totalBytes"] == 22_000

    assert len(response["users"]) == 3


def test_admin_storage_summary_matches_per_user_totals(storage_services):
    handler, responses = make_handler("admin")

    handler.do_GET()

    status, response = responses[-1]

    assert status == 200

    for field in (
        "captureCount",
        "captureBytes",
        "reportCount",
        "reportBytes",
        "totalBytes",
    ):
        assert response[field] == sum(
            user[field] for user in response["users"]
        )

    assert response["totalBytes"] == (
        response["captureBytes"] + response["reportBytes"]
    )


def test_report_only_user_is_included(storage_services):
    handler, responses = make_handler("admin")

    handler.do_GET()

    status, response = responses[-1]

    assert status == 200

    report_only = next(
        user for user in response["users"]
        if user["ownerId"] == "user-3"
    )

    assert report_only["captureCount"] == 0
    assert report_only["captureBytes"] == 0
    assert report_only["reportCount"] == 2
    assert report_only["reportBytes"] == 4_000
    assert report_only["totalBytes"] == 4_000


def test_analyst_cannot_request_all_user_storage(storage_services):
    handler, responses = make_handler("analyst")

    handler.do_GET()

    status, response = responses[-1]

    assert status == 403
    assert response["error"] == "admin_required"
