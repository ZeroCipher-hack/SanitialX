"""
Reset an existing SanitialX user password.

Operator-only utility. Run from the backend container/venv.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import update

from core.config import get_settings
from core.security import hash_password
from db.models.user import UserORM
from db.session import DatabaseSessionManager


async def _reset_password(username: str, password: str) -> None:
    settings = get_settings()

    db_manager = DatabaseSessionManager(
        database_url=settings.DATABASE_URL
    )
    db_manager.init()

    try:
        async with db_manager.sessionmaker() as session:
            result = await session.execute(
                update(UserORM)
                .where(UserORM.username == username)
                .values(password_hash=hash_password(password))
            )

            if result.rowcount == 0:
                await session.rollback()
                print(
                    f"Error: username '{username}' does not exist.",
                    file=sys.stderr,
                )
                sys.exit(1)

            await session.commit()

        print(f"Password reset successfully for '{username}'.")

    finally:
        await db_manager.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset a SanitialX user's password."
    )
    parser.add_argument("--username", required=True)
    args = parser.parse_args()

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")

    if password != confirm:
        print("Error: passwords do not match.", file=sys.stderr)
        sys.exit(1)

    if len(password) < 8:
        print(
            "Error: password must be at least 8 characters.",
            file=sys.stderr,
        )
        sys.exit(1)

    asyncio.run(_reset_password(args.username, password))


if __name__ == "__main__":
    main()
