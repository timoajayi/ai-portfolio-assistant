"""Durable consume-once boundary, deliberately unused by HTTP/paid admission.

No network, environment configuration, TrustedIP conversion or execution occurs.
A successful return consumes a nonce; it is NOT authorization to call Gemini.
"""
import sqlite3

from src.gateway_assertions import (AssertionError as InvalidAssertion, GatewayAssertionVerifier,
                                    PROTOCOL, _replay_binding)
from src.usage import GATEWAY_REPLAY_SCHEMA_VERSION, UsageDenied, UsageLedger


class GatewayReplayService:
    def __init__(self, ledger, verifier=None):
        if type(ledger) is not UsageLedger or type(verifier) is not GatewayAssertionVerifier:
            raise UsageDenied('assertion_storage')
        self._ledger = ledger
        self._verifier = verifier

    def claim(self, verified):
        """Commit exactly one claim or raise a generic, fail-closed UsageDenied.

        Only sealed results from this process's verifier are accepted. A result
        must be reverified from the original assertion after process restart.
        No refund, release or delete operation exists, even after expiration.
        """
        try:
            # Reject untrusted inputs before opening storage. Recheck inside the
            # write lock: lock/validation waiting must not extend proof lifetime.
            _replay_binding(verified, self._ledger._now(), verifier=self._verifier)
            with self._ledger._transaction(version=GATEWAY_REPLAY_SCHEMA_VERSION) as db:
                self._ledger._enabled(db)
                now = self._ledger._now()
                digest, expires = _replay_binding(verified, now, verifier=self._verifier)
                high_water, = db.execute('SELECT high_water FROM gateway_replay_control WHERE id=1').fetchone()
                if now < high_water:
                    raise UsageDenied('assertion_clock')
                # A PK constraint, not a read-before-write test, chooses the winner.
                # A conflicting insert changes nothing; downstream work never runs.
                inserted = db.execute('INSERT INTO gateway_replay_claims VALUES(?,?,?,?) '
                                      'ON CONFLICT(replay_digest) DO NOTHING',
                                      (digest, expires, now, PROTOCOL)).rowcount
                if inserted != 1:
                    raise UsageDenied('assertion_replay', 403)
                db.execute('UPDATE gateway_replay_control SET high_water=? WHERE id=1', (now,))
                # If local processing consumed the remaining lifetime, roll back.
                final = self._ledger._now()
                _replay_binding(verified, final, verifier=self._verifier)
                if final < now:
                    raise UsageDenied('assertion_clock')
                db.execute('UPDATE gateway_replay_control SET high_water=? WHERE id=1', (final,))
            # COMMIT itself may wait/fsync. If it spent the remaining lifetime,
            # deny execution but KEEP the committed claim (no refund).
            returned_at = self._ledger._now()
            _replay_binding(verified, returned_at, verifier=self._verifier)
            if returned_at < final:
                raise UsageDenied('assertion_clock')
        except InvalidAssertion:
            raise UsageDenied('assertion_invalid', 403) from None
        except (sqlite3.Error, OSError):
            raise UsageDenied('assertion_storage') from None
