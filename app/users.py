"""Administrator CLI for local users and per-user archive jobs."""

import argparse
import getpass
import os
from pathlib import Path
import sqlite3
import sys

import accounts
import runtime

SCRIPTS = ("coop_archive.py", "provider_archive.py", "rema_client.py", "trumf_client.py", "trumf_images.py")


def password():
    first = getpass.getpass("Nytt passord (minst 12 tegn): ")
    if first != getpass.getpass("Gjenta passordet: "):
        raise ValueError("Passordene er ikke like.")
    return first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "password", "disable", "enable", "path", "run"):
        p = sub.add_parser(command)
        p.add_argument("username")
        if command == "run":
            p.add_argument("script", choices=SCRIPTS)
            p.add_argument("arguments", nargs=argparse.REMAINDER)
    sub.add_parser("list")
    args = parser.parse_args()
    try:
        if args.command == "create":
            identity = accounts.create_user(args.username, password())
            print("Bruker opprettet:", accounts.normalize(args.username))
            print("Privat datamappe:", runtime.user_dir(identity))
            return
        if args.command == "list":
            with accounts.database() as db:
                for row in db.execute("SELECT username, active FROM users ORDER BY username"):
                    print(row["username"], "aktiv" if row["active"] else "deaktivert")
            return
        user = accounts.find_user(args.username)
        if not user:
            raise ValueError("Brukeren finnes ikke.")
        if args.command == "password":
            accounts.change_password(user["id"], password())
        elif args.command in ("enable", "disable"):
            accounts.set_active(user["id"], args.command == "enable")
        elif args.command == "path":
            print(runtime.user_dir(user["id"]))
        elif args.command == "run":
            if not user["active"]:
                raise ValueError("Brukeren er deaktivert.")
            env = dict(os.environ, GROCIOUS_MULTIUSER="1", GROCIOUS_USER_ID=user["id"], GROCIOUS_DEMO="0")
            script = str(Path(__file__).resolve().parent / args.script)
            os.execve(sys.executable, [sys.executable, script, *args.arguments], env)
    except (ValueError, sqlite3.IntegrityError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
