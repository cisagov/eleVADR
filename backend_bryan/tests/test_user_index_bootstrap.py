from __future__ import annotations

from pathlib import Path

from backend_bryan.auth.database import ensure_user_indexes

ROOT = Path(__file__).resolve().parents[2]


class FakeUsers:
    def __init__(self, email_index=None):
        self.email_index = email_index
        self.dropped = []
        self.created = []

    def index_information(self):
        info = {}
        if self.email_index is not None:
            info["users_email_unique"] = self.email_index
        return info

    def drop_index(self, name):
        self.dropped.append(name)
        self.email_index = None

    def create_index(self, keys, **kwargs):
        self.created.append((keys, kwargs))
        if kwargs.get("name") == "users_email_unique":
            self.email_index = {"partialFilterExpression": kwargs.get("partialFilterExpression")}


def test_email_index_migrates_legacy_sparse_unique_index():
    users = FakeUsers({"sparse": True})
    ensure_user_indexes(users)
    assert users.dropped == ["users_email_unique"]
    email = [entry for entry in users.created if entry[1].get("name") == "users_email_unique"][-1]
    assert email[1]["unique"] is True
    assert email[1]["partialFilterExpression"] == {"email_normalized": {"$type": "string"}}


def test_email_index_keeps_current_partial_unique_index():
    partial = {"email_normalized": {"$type": "string"}}
    users = FakeUsers({"partialFilterExpression": partial})
    ensure_user_indexes(users)
    assert users.dropped == []


def test_first_run_skips_admin_bootstrap_when_users_exist():
    text = (ROOT / "first_run_elevadr.bat").read_text(encoding="utf-8")
    assert "backend_bryan.auth.has_users" in text
    assert "existing eleVADR user account detected" not in text
    assert 'if "%USER_CHECK_RC%"=="0" goto users_ready' in text
