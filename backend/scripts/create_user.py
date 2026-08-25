"""
Create a SentinelX user (e.g. the first admin account).

There is intentionally no public self-service signup endpoint — that would
let anyone mint themselves an 'admin' account, the exact vulnerability this
script replaces. Run this from an operator shell instead:

    python -m scripts.create_user --username admin --role admin

You will be prompted for a password (input hidden). Run inside the backend
container/venv with the same SENTINELX_DATABASE_URL as the running app, e.g.:

    docker compose exec backend python -m scripts.create_user --username admin --role admin
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid
from datetime import datetime, timezone

from auth.models import User
from core.config import get_settings
from core.errors import ValidationError
from core.security import hash_password
from db.repositories.user_repository import PostgresUserRepository
from db.session import DatabaseSessionManager

VALID_ROLES = {"reader", "analyst", "admin"}


async def _create_user(username: str, password: str, role: str) -> None:
    settings = get_settings()
    db_manager = DatabaseSessionManager(database_url=settings.DATABASE_URL)
    db_manager.init()
    repository = PostgresUserRepository(db_manager.sessionmaker)

    existing = await repository.get_by_username(username)
    if existing is not None:
        print(f"Error: username '{username}' already exists.", file=sys.stderr)
        await db_manager.close()
        sys.exit(1)

    user = User(
        user_id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    try:
        await repository.create(user)
    except ValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        await db_manager.close()
        sys.exit(1)

    await db_manager.close()
    print(f"Created user '{username}' with role '{role}'.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a SentinelX user.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=sorted(VALID_ROLES))
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: passwords do not match.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 8:
        print("Error: password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(_create_user(args.username, password, args.role))


if __name__ == "__main__":
    main()
