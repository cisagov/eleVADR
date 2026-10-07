"""Create or update a local eleVADR MongoDB user account."""
from __future__ import annotations

import argparse
import getpass
from datetime import UTC, datetime

from .config import load_auth_config
from .database import ensure_user_indexes
from .security import hash_password


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an eleVADR user in MongoDB")
    parser.add_argument("username")
    parser.add_argument("--email", default="")
    parser.add_argument("--role", choices=("admin", "analyst", "read_only"), default="analyst")
    args = parser.parse_args()
    config = load_auth_config()
    try:
        from pymongo import MongoClient
    except ImportError:
        print("ERROR: pymongo is not installed. Install backend_bryan/requirements-platform.txt first.")
        return 2
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("ERROR: passwords do not match")
        return 2
    username = args.username.strip()
    if not username:
        print("ERROR: username is required")
        return 2
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 2
    client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=3000)
    try:
        client.admin.command("ping")
        users = client[config.mongodb_database]["users"]
        ensure_user_indexes(users)
        now = datetime.now(UTC)
        email = args.email.strip()
        set_values = {
            "username": username,
            "username_normalized": username.lower(),
            "password_hash": password_hash,
            "role": args.role,
            "disabled": False,
            "updated": now,
        }
        update: dict[str, object] = {"$set": set_values, "$setOnInsert": {"created": now}}
        if email:
            set_values["email"] = email
            set_values["email_normalized"] = email.lower()
        else:
            update["$unset"] = {"email": "", "email_normalized": ""}
        try:
            users.update_one(
                {"username_normalized": username.lower()},
                update,
                upsert=True,
            )
        except Exception as exc:
            if exc.__class__.__name__ == "DuplicateKeyError":
                print("ERROR: username or email already exists")
                return 2
            raise
    finally:
        client.close()
    print(f"User '{username}' is ready in MongoDB database '{config.mongodb_database}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
