"""Return whether the configured eleVADR database already has user accounts."""
from __future__ import annotations

from .config import load_auth_config
from .database import ensure_user_indexes


def main() -> int:
    config = load_auth_config()
    try:
        from pymongo import MongoClient
    except ImportError:
        print("ERROR: pymongo is not installed. Install backend_bryan/requirements-platform.txt first.")
        return 2
    client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        client.admin.command("ping")
        users = client[config.mongodb_database]["users"]
        ensure_user_indexes(users)
        count = users.count_documents({}, limit=1)
    except Exception as exc:
        print(f"ERROR: unable to inspect eleVADR users: {exc}")
        return 2
    finally:
        client.close()
    if count:
        print("INFO: existing eleVADR user account detected; first-admin bootstrap is not required.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
