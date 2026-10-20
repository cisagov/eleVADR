"""Create the first admin user from environment variables when the users collection is empty."""
from __future__ import annotations

import os
import sys
from datetime import UTC, datetime

from backend_bryan.auth.config import load_auth_config
from backend_bryan.auth.database import ensure_user_indexes
from backend_bryan.auth.security import hash_password


def main() -> int:
    username = os.environ.get("ELEVADR_BOOTSTRAP_ADMIN_USERNAME", "admin").strip()
    password = os.environ.get("ELEVADR_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        print("Admin bootstrap skipped: username or password not set.")
        return 0

    config = load_auth_config()
    from pymongo import MongoClient

    client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=30000)
    try:
        client.admin.command("ping")
        users = client[config.mongodb_database]["users"]
        ensure_user_indexes(users)
        if users.count_documents({}, limit=1):
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
