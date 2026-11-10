"""Create the first admin user from environment variables, optionally keeping its password in sync."""
from __future__ import annotations

import os
import sys
from datetime import UTC, datetime

from backend.auth.config import load_auth_config
from backend.auth.database import ensure_user_indexes
from backend.auth.security import hash_password, verify_password


def sync_password(users, username: str, password: str) -> None:
    record = users.find_one({"username_normalized": username.lower()})
    if not record:
        print(f"Admin password sync skipped: user '{username}' does not exist.")
        return
    if verify_password(password, str(record.get("password_hash", ""))):
        print(f"Admin password sync: '{username}' already matches.")
        return
    # Bumping session_version signs out tokens issued under the old password.
    users.update_one(
        {"_id": record["_id"]},
        {
            "$set": {"password_hash": hash_password(password), "updated": datetime.now(UTC)},
            "$inc": {"session_version": 1},
        },
    )
    print(f"Admin password sync: updated the password for '{username}'.")


def main() -> int:
    username = os.environ.get("ELEVADR_BOOTSTRAP_ADMIN_USERNAME", "admin").strip()
    password = os.environ.get("ELEVADR_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        print("Admin bootstrap skipped: username or password not set.")
        return 0
    sync = os.environ.get("ELEVADR_BOOTSTRAP_ADMIN_SYNC", "").strip().lower() in {"1", "true", "yes"}

    config = load_auth_config()
    from pymongo import MongoClient

    client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=30000)
    try:
        client.admin.command("ping")
        users = client[config.mongodb_database]["users"]
        ensure_user_indexes(users)
        if users.count_documents({}, limit=1):
            if sync:
                sync_password(users, username, password)
            else:
                print("Admin bootstrap skipped: users already exist.")
            return 0
        now = datetime.now(UTC)
        users.insert_one({
            "username": username,
            "username_normalized": username.lower(),
            "password_hash": hash_password(password),
            "role": "admin",
            "disabled": False,
            "session_version": 0,
            "created": now,
            "updated": now,
        })
    finally:
        client.close()
    print(f"Created initial administrator '{username}'.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Admin bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)
