"""Local operator commands. Never load .env, credentials, or provider modules."""

import argparse
import json
import os
from pathlib import Path

from src.usage import UsageDenied, UsageLedger
from src.identity import identity_key, identity_key_tag


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("command", choices=("init", "status", "disable", "enable", "clear-inflight",
                                           "migrate-v2", "cleanup-sessions", "migrate-v3",
                                           "disable-issuance", "enable-issuance", "issuance-status", "migrate-v4",
                                           "migrate-v5", "migrate-v6", "fail-pending-verifications"))
    parser.add_argument("--confirm-workers-stopped", action="store_true")
    parser.add_argument("--retention-seconds", type=int, default=86400)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        ledger = UsageLedger(args.database)
        if args.command == "init":
            ledger.initialize()
        elif args.command in ("disable", "enable"):
            ledger.set_disabled(args.command == "disable")
        elif args.command == "clear-inflight":
            ledger.recover(workers_stopped=args.confirm_workers_stopped)
        elif args.command == "migrate-v2":
            ledger.migrate(workers_stopped=args.confirm_workers_stopped)
        elif args.command == 'migrate-v3':
            ledger.migrate_issuance(workers_stopped=args.confirm_workers_stopped)
        elif args.command == 'migrate-v4':
            key = identity_key(os.environ.get('IP_RATE_HMAC_KEY', ''))
            ledger.migrate_identity(identity_key_tag(key), workers_stopped=args.confirm_workers_stopped)
        elif args.command == 'migrate-v6':
            ledger.migrate_gateway_replay(workers_stopped=args.confirm_workers_stopped)
        elif args.command == 'migrate-v5':
            ledger.migrate_verification(workers_stopped=args.confirm_workers_stopped)
        elif args.command == 'fail-pending-verifications':
            ledger.recover_verifications(workers_stopped=args.confirm_workers_stopped)
        elif args.command in ('disable-issuance', 'enable-issuance'):
            ledger.set_issuance_disabled(args.command == 'disable-issuance')
        elif args.command == 'issuance-status':
            print(json.dumps(ledger.issuance_status()))
            return 0
        elif args.command == "cleanup-sessions":
            ledger.cleanup_sessions(workers_stopped=args.confirm_workers_stopped,
                                    retention_seconds=args.retention_seconds, limit=args.limit)
        print(json.dumps(ledger.status()))
        return 0
    except (UsageDenied, ValueError):
        print("Usage control unavailable. Verify storage, schema, and operator prerequisites.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
