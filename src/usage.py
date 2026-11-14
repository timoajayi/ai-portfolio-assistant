"""Fail-closed, local-disk usage admission. No provider or dotenv imports."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date, datetime, timezone
import os
import hmac
from pathlib import Path
import re
import sqlite3
import stat
from uuid import UUID, uuid4


class UsageDenied(Exception):
    def __init__(self, category="usage_storage", status=503):
        super().__init__("Paid operation unavailable.")
        self.category = category
        self.status = status


SCHEMA_VERSION = 1
# Initialization remains version 1 for compatibility. Only an explicit operator
# migration installs newer schemas; runtime validates complete versions 1–6.
SESSION_SCHEMA_VERSION = 2
ISSUANCE_SCHEMA_VERSION = 3
IDENTITY_SCHEMA_VERSION = 4
VERIFICATION_SCHEMA_VERSION = 5
GATEWAY_REPLAY_SCHEMA_VERSION = 6
SCHEMA = (
    """CREATE TABLE control (
        id INTEGER PRIMARY KEY CHECK(id=1),
        disabled INTEGER NOT NULL CHECK(disabled IN (0,1)),
        last_day TEXT NOT NULL)""",
    """CREATE TABLE periods (
        kind TEXT NOT NULL CHECK(kind IN ('day','month')),
        period TEXT NOT NULL,
        admitted INTEGER NOT NULL CHECK(admitted>=0),
        embedding_ops INTEGER NOT NULL CHECK(embedding_ops>=0 AND embedding_ops<=admitted),
        generation_ops INTEGER NOT NULL CHECK(generation_ops>=0 AND generation_ops<=admitted),
        PRIMARY KEY(kind,period))""",
    """CREATE TABLE active (
        id TEXT PRIMARY KEY NOT NULL,
        day TEXT NOT NULL, month TEXT NOT NULL,
        embedding_ops INTEGER NOT NULL DEFAULT 0 CHECK(embedding_ops IN (0,1)),
        generation_ops INTEGER NOT NULL DEFAULT 0 CHECK(generation_ops IN (0,1)))""",
)
EXPECTED_COLUMNS = {
    "control": ["id", "disabled", "last_day"],
    "periods": ["kind", "period", "admitted", "embedding_ops", "generation_ops"],
    "active": ["id", "day", "month", "embedding_ops", "generation_ops"],
}
SESSION_SCHEMA = (
    """CREATE TABLE sessions (
        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
        token_digest BLOB NOT NULL UNIQUE CHECK(typeof(token_digest)='blob' AND length(token_digest)=32),
        created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer' AND created_at>=0 AND created_at<=253402300799),
        expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at>created_at AND expires_at<=253402300799),
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(typeof(revoked)='integer' AND revoked IN (0,1)),
        verified INTEGER NOT NULL DEFAULT 0 CHECK(typeof(verified)='integer' AND verified IN (0,1)))""",
    """CREATE TABLE session_events (
        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        admitted_at INTEGER NOT NULL CHECK(typeof(admitted_at)='integer' AND admitted_at>=0 AND admitted_at<=253402300799))""",
    'CREATE INDEX sessions_expiry ON sessions(expires_at,id)',
    'CREATE INDEX session_events_recent ON session_events(session_id,admitted_at,id)',
)
SESSION_COLUMNS = {
    'sessions': ['id', 'token_digest', 'created_at', 'expires_at', 'revoked', 'verified'],
    'session_events': ['id', 'session_id', 'admitted_at'],
}
ISSUANCE_SCHEMA = (
    """CREATE TABLE issuance_control (
        id INTEGER PRIMARY KEY CHECK(id=1),
        disabled INTEGER NOT NULL CHECK(typeof(disabled)='integer' AND disabled IN (0,1)),
        last_issued_at INTEGER NOT NULL CHECK(typeof(last_issued_at)='integer' AND last_issued_at>=0 AND last_issued_at<=253402300799))""",
    """CREATE TABLE issuance_events (
        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
        created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer' AND created_at>=0 AND created_at<=253402300799))""",
    'CREATE INDEX issuance_recent ON issuance_events(created_at,id)',
)
IDENTITY_SCHEMA = (
    """CREATE TABLE ip_control (
        id INTEGER PRIMARY KEY CHECK(id=1),
        key_tag BLOB NOT NULL CHECK(typeof(key_tag)='blob' AND length(key_tag)=32),
        last_admitted_at INTEGER NOT NULL CHECK(typeof(last_admitted_at)='integer' AND last_admitted_at>=0 AND last_admitted_at<=253402300799))""",
    """CREATE TABLE ip_events (
        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
        identity BLOB NOT NULL CHECK(typeof(identity)='blob' AND length(identity)=32),
        admitted_at INTEGER NOT NULL CHECK(typeof(admitted_at)='integer' AND admitted_at>=0 AND admitted_at<=253402300799))""",
    'CREATE INDEX ip_events_recent ON ip_events(identity,admitted_at,id)',
)
VERIFICATION_SCHEMA = (
    """CREATE TABLE verification_claims (
        proof_digest BLOB PRIMARY KEY NOT NULL CHECK(typeof(proof_digest)='blob' AND length(proof_digest)=32),
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id)=32 AND request_id NOT GLOB '*[^0-9a-f]*'),
        binding BLOB NOT NULL CHECK(typeof(binding)='blob' AND length(binding)=32),
        created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer' AND created_at>=0 AND created_at<=253402300799),
        state TEXT NOT NULL CHECK(state IN ('pending','failed','issued')),
        session_digest BLOB CHECK(session_digest IS NULL OR (typeof(session_digest)='blob' AND length(session_digest)=32)),
        CHECK((state='issued' AND session_digest IS NOT NULL) OR (state IN ('pending','failed') AND session_digest IS NULL)))""",
    'CREATE INDEX verification_recent ON verification_claims(created_at,proof_digest)',
)

GATEWAY_REPLAY_SCHEMA = (
    """CREATE TABLE gateway_replay_control (
        id INTEGER PRIMARY KEY CHECK(id=1),
        high_water INTEGER NOT NULL CHECK(typeof(high_water)='integer' AND high_water>=0 AND high_water<=253402300799))""",
    """CREATE TABLE gateway_replay_claims (
        replay_digest BLOB PRIMARY KEY NOT NULL CHECK(typeof(replay_digest)='blob' AND length(replay_digest)=32),
        expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at>=0 AND expires_at<=253402300799),
        claimed_at INTEGER NOT NULL CHECK(typeof(claimed_at)='integer' AND claimed_at>=0 AND claimed_at<=253402300799),
        protocol TEXT NOT NULL CHECK(protocol='portfolio-gateway-assertion-v1'),
        CHECK(expires_at>claimed_at AND expires_at<=claimed_at+35))""",
)

# Bound *all* SQL work in one validation/admission transaction. This is a
# resource guard, not an accounting limit: exhaustion denies without mutation.
VALIDATION_MAX_STEPS = 1_000_000
SQL_PROGRESS_INTERVAL = 1000
_SQL_TOKEN = re.compile(
    r"\s+|--[^\n]*(?:\n|$)|/\*.*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|"
    r"`(?:``|[^`])*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|<=|>=|!=|<>|[(),=<>+;-]",
    re.DOTALL,
)


def _sql_tokens(sql):
    """Compare supported DDL syntax, not irrelevant formatting/comments/case."""
    if not isinstance(sql, str) or len(sql) > 16_384:
        raise UsageDenied()
    tokens = []
    position = 0
    for match in _SQL_TOKEN.finditer(sql):
        if match.start() != position:
            raise UsageDenied()
        position = match.end()
        token = match.group()
        if token.isspace() or token.startswith(('--', '/*')):
            continue
        if token.startswith(('"', '`', '[')):
            token = token[1:-1].replace('""', '"').replace('``', '`')
            if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', token) is None:
                raise UsageDenied()
        tokens.append(token if token.startswith("'") else token.lower())
    if position != len(sql):
        raise UsageDenied()
    if tokens and tokens[-1] == ';':
        tokens.pop()
    return tuple(tokens)


SUPPORTED_SQL = {name: _sql_tokens(sql) for name, sql in zip(EXPECTED_COLUMNS, SCHEMA)}
SESSION_SQL = dict(zip(('sessions', 'session_events', 'sessions_expiry', 'session_events_recent'),
                       map(_sql_tokens, SESSION_SCHEMA)))
ISSUANCE_SQL = dict(zip(('issuance_control', 'issuance_events', 'issuance_recent'), map(_sql_tokens, ISSUANCE_SCHEMA)))
IDENTITY_SQL = dict(zip(('ip_control', 'ip_events', 'ip_events_recent'), map(_sql_tokens, IDENTITY_SCHEMA)))
VERIFICATION_SQL = dict(zip(('verification_claims', 'verification_recent'), map(_sql_tokens, VERIFICATION_SCHEMA)))
GATEWAY_REPLAY_SQL = dict(zip(('gateway_replay_control', 'gateway_replay_claims'),
                              map(_sql_tokens, GATEWAY_REPLAY_SCHEMA)))
EXPECTED_KEYS = {'control': (), 'periods': ('kind', 'period'), 'active': ('id',)}


def _day(value):
    try:
        valid = type(value) is str and len(value) == 10 and date.fromisoformat(value).isoformat() == value
    except ValueError:
        valid = False
    if not valid:
        raise UsageDenied()
    return value


def _month(value):
    if type(value) is not str or len(value) != 7:
        raise UsageDenied()
    _day(value + '-01')
    return value


def _validate_schema(db, version=None):
    actual = db.execute('PRAGMA user_version').fetchone()[0]
    versions = version if isinstance(version, tuple) else (version,)
    if actual not in (SCHEMA_VERSION, SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION) or (version is not None and actual not in versions):
        raise UsageDenied()
    # No triggers/views/extra indexes or hidden auxiliary tables are supported.
    expected = {('table', name, name) for name in EXPECTED_COLUMNS}
    expected |= {('index', 'sqlite_autoindex_' + name + '_1', name) for name in ('periods', 'active')}
    supported = dict(SUPPORTED_SQL)
    if actual >= SESSION_SCHEMA_VERSION:
        supported.update(SESSION_SQL)
        expected |= {('table', name, name) for name in SESSION_COLUMNS}
        expected |= {('index', name, table) for name, table in (
            ('sqlite_autoindex_sessions_1', 'sessions'), ('sqlite_autoindex_sessions_2', 'sessions'),
            ('sqlite_autoindex_session_events_1', 'session_events'),
            ('sessions_expiry', 'sessions'), ('session_events_recent', 'session_events'))}
    if actual >= ISSUANCE_SCHEMA_VERSION:
        supported.update(ISSUANCE_SQL)
        expected |= {('table', name, name) for name in ('issuance_control', 'issuance_events')}
        expected |= {('index', name, 'issuance_events') for name in ('sqlite_autoindex_issuance_events_1', 'issuance_recent')}
    if actual >= IDENTITY_SCHEMA_VERSION:
        supported.update(IDENTITY_SQL)
        expected |= {('table', name, name) for name in ('ip_control', 'ip_events')}
        expected |= {('index', name, 'ip_events') for name in ('sqlite_autoindex_ip_events_1', 'ip_events_recent')}
    if actual >= VERIFICATION_SCHEMA_VERSION:
        supported.update(VERIFICATION_SQL)
        expected.add(('table', 'verification_claims', 'verification_claims'))
        expected |= {('index', name, 'verification_claims') for name in (
            'sqlite_autoindex_verification_claims_1', 'sqlite_autoindex_verification_claims_2', 'verification_recent')}
    if actual >= GATEWAY_REPLAY_SCHEMA_VERSION:
        supported.update(GATEWAY_REPLAY_SQL)
        expected |= {('table', name, name) for name in GATEWAY_REPLAY_SQL}
        expected.add(('index', 'sqlite_autoindex_gateway_replay_claims_1', 'gateway_replay_claims'))
    objects = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema LIMIT ?', (len(expected) + 1,)).fetchall()
    if len(objects) != len(expected) or {(row[0], row[1], row[2]) for row in objects} != expected:
        raise UsageDenied()
    for kind, name, _, sql in objects:
        if name in supported and _sql_tokens(sql) != supported[name]:
            raise UsageDenied()
        if kind == 'index' and name not in supported and sql is not None:
            raise UsageDenied()
    for name, columns in EXPECTED_COLUMNS.items():
        info = db.execute(f'PRAGMA table_xinfo({name})').fetchall()
        primary = ('id',) if name == 'control' else EXPECTED_KEYS[name]
        for position, column in enumerate(columns):
            integer = column in ('id', 'disabled') if name == 'control' else column in ('admitted', 'embedding_ops', 'generation_ops')
            expected_row = (position, column, 'INTEGER' if integer else 'TEXT',
                            0 if name == 'control' and column == 'id' else 1,
                            '0' if name == 'active' and column.endswith('_ops') else None,
                            primary.index(column) + 1 if column in primary else 0, 0)
            if position >= len(info) or tuple(info[position]) != expected_row:
                raise UsageDenied()
        if len(info) != len(columns) or db.execute(f'PRAGMA foreign_key_list({name})').fetchall():
            raise UsageDenied()  # Version 1 has no declared foreign keys.
        indexes = db.execute(f'PRAGMA index_list({name})').fetchall()
        keys = EXPECTED_KEYS[name]
        if len(indexes) != int(bool(keys)):
            raise UsageDenied()
        if keys:
            index = indexes[0]
            if index[1:] != ('sqlite_autoindex_' + name + '_1', 1, 'pk', 0):
                raise UsageDenied()
            indexed = db.execute(f'PRAGMA index_xinfo({index[1]})').fetchall()
            if tuple(row[2] for row in indexed if row[5]) != keys or any(row[3] != 0 or row[4] != 'BINARY' for row in indexed):
                raise UsageDenied()
    if actual >= SESSION_SCHEMA_VERSION:
        _validate_session_schema(db)
    if actual >= ISSUANCE_SCHEMA_VERSION:
        _validate_issuance_schema(db)
    if actual >= IDENTITY_SCHEMA_VERSION:
        _validate_identity_schema(db)
    if actual >= VERIFICATION_SCHEMA_VERSION:
        _validate_verification_schema(db)
    if actual >= GATEWAY_REPLAY_SCHEMA_VERSION:
        _validate_gateway_replay_schema(db)
    return actual


def _validate_gateway_replay_schema(db):
    metadata = {
        'gateway_replay_control': [(0, 'id', 'INTEGER', 0, None, 1, 0),
                                   (1, 'high_water', 'INTEGER', 1, None, 0, 0)],
        'gateway_replay_claims': [(0, 'replay_digest', 'BLOB', 1, None, 1, 0),
                                 (1, 'expires_at', 'INTEGER', 1, None, 0, 0),
                                 (2, 'claimed_at', 'INTEGER', 1, None, 0, 0),
                                 (3, 'protocol', 'TEXT', 1, None, 0, 0)],
    }
    for table, wanted in metadata.items():
        if (db.execute(f'PRAGMA table_xinfo({table})').fetchall() != wanted
                or db.execute(f'PRAGMA foreign_key_list({table})').fetchall()):
            raise UsageDenied()
        found = db.execute(f'PRAGMA index_list({table})').fetchall()
        if table == 'gateway_replay_control':
            if found:
                raise UsageDenied()
            continue
        if len(found) != 1 or found[0][1:] != ('sqlite_autoindex_gateway_replay_claims_1', 1, 'pk', 0):
            raise UsageDenied()
        info = db.execute('PRAGMA index_xinfo(sqlite_autoindex_gateway_replay_claims_1)').fetchall()
        if (tuple(row[2] for row in info if row[5]) != ('replay_digest',)
                or any(row[3] or row[4] != 'BINARY' for row in info)):
            raise UsageDenied()


def _validate_gateway_replay_state(db):
    rows = db.execute('SELECT id,high_water FROM gateway_replay_control LIMIT 2').fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] != 1:
        raise UsageDenied()
    high_water = _timestamp(rows[0][1])
    for digest, expires, claimed, protocol in db.execute('SELECT * FROM gateway_replay_claims'):
        _digest(digest)
        if (not _timestamp(claimed) < _timestamp(expires) <= claimed + 35
                or claimed > high_water or protocol != 'portfolio-gateway-assertion-v1'):
            raise UsageDenied()


def _validate_verification_schema(db):
    expected = [(0, 'proof_digest', 'BLOB', 1, None, 1, 0), (1, 'request_id', 'TEXT', 1, None, 0, 0),
                (2, 'binding', 'BLOB', 1, None, 0, 0), (3, 'created_at', 'INTEGER', 1, None, 0, 0),
                (4, 'state', 'TEXT', 1, None, 0, 0), (5, 'session_digest', 'BLOB', 0, None, 0, 0)]
    if db.execute('PRAGMA table_xinfo(verification_claims)').fetchall() != expected:
        raise UsageDenied()
    if db.execute('PRAGMA foreign_key_list(verification_claims)').fetchall():
        raise UsageDenied()  # Claims must survive session cleanup.
    indexes = {'sqlite_autoindex_verification_claims_1': (1, 'pk', ('proof_digest',)),
               'sqlite_autoindex_verification_claims_2': (1, 'u', ('request_id',)),
               'verification_recent': (0, 'c', ('created_at', 'proof_digest'))}
    found = db.execute('PRAGMA index_list(verification_claims)').fetchall()
    if {row[1] for row in found} != set(indexes):
        raise UsageDenied()
    for _, name, unique, origin, partial in found:
        info = db.execute(f'PRAGMA index_xinfo({name})').fetchall()
        if ((unique, origin, tuple(row[2] for row in info if row[5])) != indexes[name]
                or partial or any(row[3] or row[4] != 'BINARY' for row in info)):
            raise UsageDenied()


def _validate_verification_state(db):
    for proof, request, binding, created, state, session in db.execute('SELECT * FROM verification_claims'):
        _digest(proof)
        _identifier(request)
        _digest(binding)
        _timestamp(created)
        if state not in ('pending', 'failed', 'issued') or (state == 'issued') != (session is not None):
            raise UsageDenied()
        if session is not None:
            _digest(session)
            row = db.execute('SELECT created_at,verified FROM sessions WHERE token_digest=?', (session,)).fetchone()
            if row is not None and (row[0] < created or row[1] != 1):
                raise UsageDenied()


def _validate_identity_schema(db):
    metadata = {
        'ip_control': [(0, 'id', 'INTEGER', 0, None, 1, 0), (1, 'key_tag', 'BLOB', 1, None, 0, 0),
                       (2, 'last_admitted_at', 'INTEGER', 1, None, 0, 0)],
        'ip_events': [(0, 'id', 'TEXT', 1, None, 1, 0), (1, 'identity', 'BLOB', 1, None, 0, 0),
                      (2, 'admitted_at', 'INTEGER', 1, None, 0, 0)],
    }
    for table, wanted in metadata.items():
        if db.execute(f'PRAGMA table_xinfo({table})').fetchall() != wanted or db.execute(f'PRAGMA foreign_key_list({table})').fetchall():
            raise UsageDenied()
        indexes = db.execute(f'PRAGMA index_list({table})').fetchall()
        expected = {} if table == 'ip_control' else {
            'sqlite_autoindex_ip_events_1': (1, 'pk', ('id',)),
            'ip_events_recent': (0, 'c', ('identity', 'admitted_at', 'id'))}
        if {row[1] for row in indexes} != set(expected):
            raise UsageDenied()
        for _, name, unique, origin, partial in indexes:
            info = db.execute(f'PRAGMA index_xinfo({name})').fetchall()
            if ((unique, origin, tuple(row[2] for row in info if row[5])) != expected[name]
                    or partial or any(row[3] or row[4] != 'BINARY' for row in info)):
                raise UsageDenied()


def _validate_identity_state(db):
    control = db.execute('SELECT id,key_tag,last_admitted_at FROM ip_control LIMIT 2').fetchall()
    if len(control) != 1 or control[0][0] != 1:
        raise UsageDenied()
    _digest(control[0][1])
    watermark = _timestamp(control[0][2])
    latest = 0
    for identifier, identity, admitted, session_admitted in db.execute(
            'SELECT i.id,i.identity,i.admitted_at,s.admitted_at FROM ip_events i '
            'LEFT JOIN session_events s ON s.id=i.id'):
        _identifier(identifier)
        _digest(identity)
        latest = max(latest, _timestamp(admitted))
        if session_admitted is not None and admitted != session_admitted:
            raise UsageDenied()
    if latest != watermark:
        raise UsageDenied()


def _validate_issuance_schema(db):
    metadata = {
        'issuance_control': [(0, 'id', 'INTEGER', 0, None, 1, 0),
                             (1, 'disabled', 'INTEGER', 1, None, 0, 0),
                             (2, 'last_issued_at', 'INTEGER', 1, None, 0, 0)],
        'issuance_events': [(0, 'id', 'TEXT', 1, None, 1, 0),
                            (1, 'created_at', 'INTEGER', 1, None, 0, 0)],
    }
    for table, expected in metadata.items():
        if db.execute(f'PRAGMA table_xinfo({table})').fetchall() != expected:
            raise UsageDenied()
        if db.execute(f'PRAGMA foreign_key_list({table})').fetchall():
            raise UsageDenied()  # Audit rows intentionally survive session cleanup.
        indexes = db.execute(f'PRAGMA index_list({table})').fetchall()
        if table == 'issuance_control':
            if indexes:
                raise UsageDenied()
            continue
        expected_indexes = {'sqlite_autoindex_issuance_events_1': (1, 'pk', ('id',)),
                            'issuance_recent': (0, 'c', ('created_at', 'id'))}
        if {row[1] for row in indexes} != set(expected_indexes):
            raise UsageDenied()
        for _, name, unique, origin, partial in indexes:
            wanted_unique, wanted_origin, keys = expected_indexes[name]
            info = db.execute(f'PRAGMA index_xinfo({name})').fetchall()
            if ((unique, origin, partial) != (wanted_unique, wanted_origin, 0)
                    or tuple(row[2] for row in info if row[5]) != keys
                    or any(row[3] or row[4] != 'BINARY' for row in info)):
                raise UsageDenied()


def _validate_issuance_state(db):
    control = db.execute('SELECT id,disabled,last_issued_at FROM issuance_control LIMIT 2').fetchall()
    if (len(control) != 1 or control[0][0] != 1 or type(control[0][1]) is not int
            or control[0][1] not in (0, 1)):
        raise UsageDenied()
    watermark = _timestamp(control[0][2])
    latest = 0
    for identifier, created, session_created in db.execute(
            'SELECT e.id,e.created_at,s.created_at FROM issuance_events e LEFT JOIN sessions s ON s.id=e.id'):
        _identifier(identifier)
        latest = max(latest, _timestamp(created))
        if session_created is not None and session_created != created:
            raise UsageDenied()
    if watermark != latest:
        raise UsageDenied()


def _validate_session_schema(db):
    indexes = {
        'sessions': {'sqlite_autoindex_sessions_1': (1, 'pk', ('id',)),
                     'sqlite_autoindex_sessions_2': (1, 'u', ('token_digest',)),
                     'sessions_expiry': (0, 'c', ('expires_at', 'id'))},
        'session_events': {'sqlite_autoindex_session_events_1': (1, 'pk', ('id',)),
                           'session_events_recent': (0, 'c', ('session_id', 'admitted_at', 'id'))},
    }
    for table, columns in SESSION_COLUMNS.items():
        rows = db.execute(f'PRAGMA table_xinfo({table})').fetchall()
        expected = []
        for position, name in enumerate(columns):
            kind = 'BLOB' if name == 'token_digest' else ('TEXT' if name in ('id', 'session_id') else 'INTEGER')
            expected.append((position, name, kind, 1, '0' if name in ('revoked', 'verified') else None,
                             int(name == 'id'), 0))
        if rows != expected:
            raise UsageDenied()
        foreign = db.execute(f'PRAGMA foreign_key_list({table})').fetchall()
        if foreign != ([] if table == 'sessions' else [(0, 0, 'sessions', 'session_id', 'id', 'NO ACTION', 'CASCADE', 'NONE')]):
            raise UsageDenied()
        found = db.execute(f'PRAGMA index_list({table})').fetchall()
        if {row[1] for row in found} != set(indexes[table]):
            raise UsageDenied()
        for _, name, unique, origin, partial in found:
            wanted_unique, wanted_origin, keys = indexes[table][name]
            if (unique, origin, partial) != (wanted_unique, wanted_origin, 0):
                raise UsageDenied()
            info = db.execute(f'PRAGMA index_xinfo({name})').fetchall()
            if tuple(row[2] for row in info if row[5]) != keys or any(row[3] or row[4] != 'BINARY' for row in info):
                raise UsageDenied()


def _identifier(value):
    try:
        valid = type(value) is str and UUID(value).hex == value and UUID(value).version == 4
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise UsageDenied()
    return value


def _timestamp(value):
    if type(value) is not int or not 0 <= value <= 253402300799:
        raise UsageDenied()
    return value


def _digest(value):
    if type(value) is not bytes or len(value) != 32:
        raise UsageDenied()
    return value


def _validate_sessions(db):
    if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise UsageDenied()
    for identifier, digest, created, expires, revoked, verified in db.execute('SELECT * FROM sessions'):
        _identifier(identifier)
        _digest(digest)
        if (_timestamp(expires) <= _timestamp(created)
                or any(type(v) is not int or v not in (0, 1) for v in (revoked, verified))):
            raise UsageDenied()
    for identifier, session, admitted, created, expires in db.execute(
            'SELECT e.id,e.session_id,e.admitted_at,s.created_at,s.expires_at '
            'FROM session_events e JOIN sessions s ON s.id=e.session_id'):
        _identifier(identifier)
        _identifier(session)
        if not created <= _timestamp(admitted) < expires:
            raise UsageDenied()


def _validate_state(db):
    controls = db.execute('SELECT id,disabled,last_day FROM control LIMIT 2').fetchall()
    if (len(controls) != 1 or type(controls[0][0]) is not int or controls[0][0] != 1
            or type(controls[0][1]) is not int or controls[0][1] not in (0, 1)):
        raise UsageDenied()
    watermark = _day(controls[0][2])
    periods = {'day': {}, 'month': {}}
    sums = {}
    for kind, period, admitted, embedding, generation in db.execute(
            'SELECT kind,period,admitted,embedding_ops,generation_ops FROM periods'):
        if kind not in periods or any(type(v) is not int or v < 0 for v in (admitted, embedding, generation)):
            raise UsageDenied()
        if embedding > admitted or generation > admitted or period in periods[kind]:
            raise UsageDenied()
        (_day if kind == 'day' else _month)(period)
        periods[kind][period] = (admitted, embedding, generation)
        if kind == 'day':
            totals = sums.setdefault(period[:7], [0, 0, 0])
            for position, count in enumerate((admitted, embedding, generation)):
                totals[position] += count
    if watermark != max(periods['day'], default='0001-01-01'):
        raise UsageDenied()
    if any(month not in periods['month'] for month in sums):
        raise UsageDenied()
    if any(counts != tuple(sums.get(month, (0, 0, 0))) for month, counts in periods['month'].items()):
        raise UsageDenied()
    active_totals = {}
    identifiers = set()
    for identifier, day, month, embedding, generation in db.execute(
            'SELECT id,day,month,embedding_ops,generation_ops FROM active'):
        try:
            valid_id = type(identifier) is str and UUID(identifier).hex == identifier and UUID(identifier).version == 4
        except (ValueError, AttributeError):
            valid_id = False
        if not valid_id or identifier in identifiers:
            raise UsageDenied()
        identifiers.add(identifier)
        if (_day(day)[:7] != _month(month) or any(type(v) is not int or v not in (0, 1) for v in (embedding, generation))):
            raise UsageDenied()
        for kind, period in (('day', day), ('month', month)):
            if period not in periods[kind]:
                raise UsageDenied()
            totals = active_totals.setdefault((kind, period), [0, 0, 0])
            for position, count in enumerate((1, embedding, generation)):
                totals[position] += count
            if any(a > b for a, b in zip(totals, periods[kind][period])):
                raise UsageDenied()


def _validate_database(db, version=None):
    actual = _validate_schema(db, version)
    if db.execute('PRAGMA integrity_check(1)').fetchone()[0] != 'ok':
        raise UsageDenied()
    _validate_state(db)
    if actual >= SESSION_SCHEMA_VERSION:
        _validate_sessions(db)
    if actual >= ISSUANCE_SCHEMA_VERSION:
        _validate_issuance_state(db)
    if actual >= IDENTITY_SCHEMA_VERSION:
        _validate_identity_state(db)
    if actual >= VERIFICATION_SCHEMA_VERSION:
        _validate_verification_state(db)
    if actual >= GATEWAY_REPLAY_SCHEMA_VERSION:
        _validate_gateway_replay_state(db)


class UsageLedger:
    def __init__(self, path: Path, daily=100, monthly=1000, concurrent=2, busy_ms=250, clock=None):
        from src.config import validate_usage_path
        self.path = validate_usage_path(path)
        if any(type(v) is not int or v < 1 for v in (daily, monthly, concurrent, busy_ms)) or busy_ms > 2000:
            raise ValueError("Invalid usage limits.")
        self.daily, self.monthly, self.concurrent = daily, monthly, concurrent
        self.busy_ms = busy_ms
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def from_settings(cls, settings):
        return cls(settings.usage_path, settings.usage_daily_limit, settings.usage_monthly_limit,
                   min(settings.usage_max_concurrent, settings.max_concurrent), settings.usage_busy_ms)

    def initialize(self):
        """Operator-only, exclusive creation. Never overwrite or silently repair."""
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            with self._transaction(validate=False) as db:
                for statement in SCHEMA:
                    db.execute(statement)
                db.execute("INSERT INTO control VALUES(1,1,'0001-01-01')")
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        except (OSError, sqlite3.Error):
            raise UsageDenied() from None

    @contextmanager
    def _transaction(self, validate=True, version=None):
        db = None
        try:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o222:
                raise UsageDenied()
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                 timeout=self.busy_ms / 1000, isolation_level=None)
            steps = 0
            def progress():
                nonlocal steps
                steps += SQL_PROGRESS_INTERVAL
                return int(steps >= VALIDATION_MAX_STEPS)
            db.set_progress_handler(progress, SQL_PROGRESS_INTERVAL)
            db.execute('PRAGMA foreign_keys=ON')
            if db.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
                raise UsageDenied()
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            if validate:
                _validate_database(db, version)
            yield db
            db.execute("COMMIT")
        except (sqlite3.Error, OSError):
            raise UsageDenied() from None
        finally:
            if db is not None:
                db.close()  # Rolls back any uncommitted transaction.

    def migrate(self, *, workers_stopped=False):
        """Operator-only v1 -> v2. Confirmation cannot prove worker shutdown."""
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=SCHEMA_VERSION) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            for statement in SESSION_SCHEMA:
                db.execute(statement)
            db.execute(f'PRAGMA user_version={SESSION_SCHEMA_VERSION}')
            _validate_database(db, SESSION_SCHEMA_VERSION)

    def migrate_gateway_replay(self, *, workers_stopped=False):
        """Operator-only v5 -> v6; never clears claims, reservations or budgets."""
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=VERIFICATION_SCHEMA_VERSION) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            for statement in GATEWAY_REPLAY_SCHEMA:
                db.execute(statement)
            db.execute('INSERT INTO gateway_replay_control VALUES(1,?)', (self._now(),))
            db.execute(f'PRAGMA user_version={GATEWAY_REPLAY_SCHEMA_VERSION}')
            _validate_database(db, GATEWAY_REPLAY_SCHEMA_VERSION)

    def migrate_verification(self, *, workers_stopped=False):
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=IDENTITY_SCHEMA_VERSION) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            for statement in VERIFICATION_SCHEMA:
                db.execute(statement)
            db.execute(f'PRAGMA user_version={VERIFICATION_SCHEMA_VERSION}')
            _validate_database(db, VERIFICATION_SCHEMA_VERSION)

    def claim_verification(self, proof, request, binding, *, minute_limit=10, day_limit=100, concurrent=2,
                           issuance_minute_limit=10, issuance_day_limit=100, live_limit=500):
        _digest(proof)
        _identifier(request)
        _digest(binding)
        if any(type(v) is not int or not 1 <= v <= 1000 for v in (minute_limit, day_limit, concurrent)):
            raise UsageDenied()
        if any(type(v) is not int or not 1 <= v <= 10000 for v in (issuance_minute_limit, issuance_day_limit, live_limit)):
            raise UsageDenied()
        with self._transaction(version=(VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            self._enabled(db)
            if db.execute('SELECT disabled FROM issuance_control WHERE id=1').fetchone()[0] != 0:
                raise UsageDenied('usage_issuance_disabled')
            now = self._now()
            self._check_issuance(db, now, issuance_minute_limit, issuance_day_limit, live_limit)
            latest, = db.execute('SELECT max(created_at) FROM verification_claims').fetchone()
            if latest is not None and now < latest:
                raise UsageDenied('usage_clock')
            if db.execute('SELECT 1 FROM verification_claims WHERE proof_digest=?', (proof,)).fetchone():
                raise UsageDenied('verification_replay', 403)
            for seconds, limit in ((60, minute_limit), (86400, day_limit)):
                count, = db.execute('SELECT count(*) FROM verification_claims WHERE created_at>?', (now - seconds,)).fetchone()
                if count >= limit:
                    raise UsageDenied('verification_budget', 429)
            pending, = db.execute("SELECT count(*) FROM verification_claims WHERE state='pending'").fetchone()
            if pending >= concurrent:
                raise UsageDenied('verification_capacity')
            db.execute("INSERT INTO verification_claims VALUES(?,?,?,?,'pending',NULL)", (proof, request, binding, now))

    def fail_verification(self, proof, request, binding):
        with self._transaction(version=(VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            db.execute("UPDATE verification_claims SET state='failed' WHERE proof_digest=? AND request_id=? "
                       "AND binding=? AND state='pending'", (proof, request, binding))

    def recover_verifications(self, *, workers_stopped=False):
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=(VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            db.execute("UPDATE verification_claims SET state='failed' WHERE state='pending'")

    def finalize_verification(self, proof, request, binding, session_digest, *, lifetime=14400,
                              minute_limit=10, day_limit=100, live_limit=500, verified_until):
        """Trusted service only, after provider validation; not a public flag."""
        for value in (proof, binding, session_digest):
            _digest(value)
        _identifier(request)
        _timestamp(verified_until)
        for value, maximum in ((lifetime, 86400), (minute_limit, 10000), (day_limit, 10000), (live_limit, 10000)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise UsageDenied()
        with self._transaction(version=(VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            row = db.execute('SELECT state,created_at FROM verification_claims WHERE proof_digest=? AND request_id=? AND binding=?',
                             (proof, request, binding)).fetchone()
            now = self._now()
            if row is None or row[0] != 'pending' or not row[1] <= now <= verified_until:
                raise UsageDenied('verification_replay', 403)
            expires = self._issue_session(db, session_digest, lifetime, minute_limit, day_limit, live_limit, verified=True, now=now)
            db.execute("UPDATE verification_claims SET state='issued',session_digest=? WHERE proof_digest=?", (session_digest, proof))
            return expires

    def _now(self):
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise UsageDenied()
        return _timestamp(int(now.astimezone(timezone.utc).timestamp()))

    def migrate_issuance(self, *, workers_stopped=False):
        """Explicit v2 -> v3 maintenance migration, with issuance disabled."""
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=SESSION_SCHEMA_VERSION) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            for statement in ISSUANCE_SCHEMA:
                db.execute(statement)
            db.execute('INSERT INTO issuance_control VALUES(1,1,0)')
            db.execute(f'PRAGMA user_version={ISSUANCE_SCHEMA_VERSION}')
            _validate_database(db, ISSUANCE_SCHEMA_VERSION)

    def migrate_identity(self, key_tag, *, workers_stopped=False):
        """Explicit v3 -> v4, no change to counters or either shutdown state."""
        _digest(key_tag)
        if workers_stopped is not True:
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=ISSUANCE_SCHEMA_VERSION) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            for statement in IDENTITY_SCHEMA:
                db.execute(statement)
            db.execute('INSERT INTO ip_control VALUES(1,?,0)', (key_tag,))
            db.execute(f'PRAGMA user_version={IDENTITY_SCHEMA_VERSION}')
            _validate_database(db, IDENTITY_SCHEMA_VERSION)

    def set_issuance_disabled(self, disabled):
        if type(disabled) is not bool:
            raise UsageDenied()
        with self._transaction(version=(ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            if not disabled:
                self._enabled(db)
            db.execute('UPDATE issuance_control SET disabled=? WHERE id=1', (int(disabled),))

    def issuance_status(self):
        with self._transaction(version=(ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            disabled, = db.execute('SELECT disabled FROM issuance_control WHERE id=1').fetchone()
            return {'issuance_disabled': bool(disabled)}

    def issue_session(self, token_digest, *, lifetime=14400, minute_limit=10, day_limit=100, live_limit=500):
        """Atomic, durable issuance admission; never reserves paid usage."""
        _digest(token_digest)
        for value, maximum in ((lifetime, 86400), (minute_limit, 10000), (day_limit, 10000), (live_limit, 10000)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise UsageDenied()
        with self._transaction(version=(ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            return self._issue_session(db, token_digest, lifetime, minute_limit, day_limit, live_limit)

    def _check_issuance(self, db, now, minute_limit, day_limit, live_limit):
        self._enabled(db)
        disabled, last = db.execute('SELECT disabled,last_issued_at FROM issuance_control WHERE id=1').fetchone()
        if disabled:
            raise UsageDenied('usage_issuance_disabled')
        if now < last:
            raise UsageDenied('usage_clock')
        for window, limit in ((60, minute_limit), (86400, day_limit)):
            count, = db.execute('SELECT count(*) FROM issuance_events WHERE created_at>?', (now - window,)).fetchone()
            if count >= limit:
                raise UsageDenied('usage_issuance_budget', 429)
        live, = db.execute('SELECT count(*) FROM sessions WHERE revoked=0 AND expires_at>?', (now,)).fetchone()
        if live >= live_limit:
            raise UsageDenied('usage_issuance_budget', 429)

    def _issue_session(self, db, token_digest, lifetime, minute_limit, day_limit, live_limit, *, verified=False, now=None):
        now = self._now() if now is None else now
        self._check_issuance(db, now, minute_limit, day_limit, live_limit)
        expires = _timestamp(now + lifetime)
        identifier = uuid4().hex
        db.execute('INSERT INTO sessions(id,token_digest,created_at,expires_at,verified) VALUES(?,?,?,?,?)',
                   (identifier, token_digest, now, expires, int(verified)))
        db.execute('INSERT INTO issuance_events VALUES(?,?)', (identifier, now))
        db.execute('UPDATE issuance_control SET last_issued_at=? WHERE id=1', (now,))
        return expires

    def create_session(self, token_digest, expires_at, *, verified=False):
        """Store a caller-supplied SHA-256 digest, never issue a bearer token."""
        _digest(token_digest)
        _timestamp(expires_at)
        if type(verified) is not bool:
            raise UsageDenied()
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            now = self._now()
            if expires_at <= now:
                raise UsageDenied('usage_session')
            identifier = uuid4().hex
            db.execute('INSERT INTO sessions(id,token_digest,created_at,expires_at,verified) VALUES(?,?,?,?,?)',
                       (identifier, token_digest, now, expires_at, int(verified)))
            return identifier

    def lookup_session(self, token_digest):
        """Return active storage metadata only; this never authorizes Gemini."""
        _digest(token_digest)
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            now = self._now()
            row = db.execute('SELECT id,created_at,expires_at,revoked,verified FROM sessions '
                             'WHERE token_digest=? AND revoked=0 AND created_at<=? AND expires_at>?',
                             (token_digest, now, now)).fetchone()
            return None if row is None else dict(zip(('id', 'created_at', 'expires_at', 'revoked', 'verified'), row))

    def revoke_session(self, identifier):
        _identifier(identifier)
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            return db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (identifier,)).rowcount == 1

    def record_session_usage(self, identifier):
        """Storage event only, independent of paid admission/counters for now."""
        _identifier(identifier)
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            now = self._now()
            row = db.execute('SELECT 1 FROM sessions WHERE id=? AND revoked=0 AND verified=1 '
                             'AND created_at<=? AND expires_at>?', (identifier, now, now)).fetchone()
            if row is None:
                raise UsageDenied('usage_session')
            event = uuid4().hex
            db.execute('INSERT INTO session_events VALUES(?,?,?)', (event, identifier, now))
            return event

    def recent_session_usage(self, identifier, since, *, limit=1000):
        """Bounded inspection, not a rolling-window limit or admission check."""
        _identifier(identifier)
        _timestamp(since)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise UsageDenied()
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            now = self._now()
            if since > now:
                raise UsageDenied('usage_session')
            return db.execute('SELECT id,admitted_at FROM session_events WHERE session_id=? '
                              'AND admitted_at>=? AND admitted_at<=? ORDER BY admitted_at,id LIMIT ?',
                              (identifier, since, now, limit)).fetchall()

    def cleanup_sessions(self, *, workers_stopped=False, retention_seconds=86400, limit=100):
        """Explicit disabled-maintenance cleanup; never touches paid accounting."""
        if (workers_stopped is not True or type(retention_seconds) is not int
                or not 0 <= retention_seconds <= 31_536_000 or type(limit) is not int or not 1 <= limit <= 1000):
            raise UsageDenied('usage_maintenance')
        with self._transaction(version=(SESSION_SCHEMA_VERSION, ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)) as db:
            if db.execute('SELECT disabled FROM control WHERE id=1').fetchone()[0] != 1:
                raise UsageDenied('usage_maintenance')
            cutoff = self._now() - retention_seconds
            return db.execute('DELETE FROM sessions WHERE id IN '
                              '(SELECT id FROM sessions WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)',
                              (cutoff, limit)).rowcount

    def _periods(self):
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise UsageDenied()
        now = now.astimezone(timezone.utc)
        return now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")

    @staticmethod
    def _enabled(db):
        if db.execute("SELECT disabled FROM control WHERE id=1").fetchone()[0] != 0:
            raise UsageDenied("usage_disabled")

    def reserve(self):
        with self._transaction() as db:
            self._enabled(db)
            day, month = self._periods()
            identifier = self._reserve(db, day, month)
        return identifier

    def _reserve(self, db, day, month):
        """Shared global accounting; caller owns the write transaction."""
        self._enabled(db)
        if day < db.execute("SELECT last_day FROM control WHERE id=1").fetchone()[0]:
            raise UsageDenied("usage_clock")
        if db.execute("SELECT count(*) FROM active").fetchone()[0] >= self.concurrent:
            raise UsageDenied("usage_capacity")
        for kind, period, limit in (("day", day, self.daily), ("month", month, self.monthly)):
            row = db.execute("SELECT admitted FROM periods WHERE kind=? AND period=?", (kind, period)).fetchone()
            if row is not None and row[0] >= limit:
                raise UsageDenied("usage_budget", 429)
            db.execute("INSERT INTO periods VALUES(?,?,1,0,0) ON CONFLICT(kind,period) DO UPDATE SET admitted=admitted+1",
                       (kind, period))
        identifier = uuid4().hex
        db.execute("INSERT INTO active(id,day,month) VALUES(?,?,?)", (identifier, day, month))
        db.execute("UPDATE control SET last_day=? WHERE id=1", (day,))
        return identifier

    def reserve_session(self, token_digest, *, minute_limit=3, hour_limit=12,
                        identity_digest=None, identity_key_tag=None, identity_minute_limit=10, identity_day_limit=60):
        """Atomically admit session AND global usage. No provider work here."""
        _digest(token_digest)
        if any(type(value) is not int or not 1 <= value <= 10000 for value in (minute_limit, hour_limit)):
            raise UsageDenied()
        identity_aware = identity_digest is not None or identity_key_tag is not None
        if identity_aware:
            _digest(identity_digest)
            _digest(identity_key_tag)
            if any(type(value) is not int or not 1 <= value <= 10000 for value in (identity_minute_limit, identity_day_limit)):
                raise UsageDenied()
        version = (IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION) if identity_aware else (ISSUANCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, VERIFICATION_SCHEMA_VERSION, GATEWAY_REPLAY_SCHEMA_VERSION)
        with self._transaction(version=version) as db:
            self._enabled(db)
            now = self._now()
            row = db.execute('SELECT id FROM sessions WHERE token_digest=? AND verified=1 AND revoked=0 '
                             'AND created_at<=? AND expires_at>?', (token_digest, now, now)).fetchone()
            if row is None:
                raise UsageDenied('usage_session', 401)
            session, = row
            latest, = db.execute('SELECT max(admitted_at) FROM session_events WHERE session_id=?', (session,)).fetchone()
            if latest is not None and latest > now:
                raise UsageDenied('usage_clock')
            for seconds, limit in ((60, minute_limit), (3600, hour_limit)):
                count, = db.execute('SELECT count(*) FROM session_events WHERE session_id=? AND admitted_at>?',
                                    (session, now - seconds)).fetchone()
                if count >= limit:
                    raise UsageDenied('usage_session_budget', 429)
            if identity_aware:
                stored_tag, last = db.execute('SELECT key_tag,last_admitted_at FROM ip_control WHERE id=1').fetchone()
                if not hmac.compare_digest(stored_tag, identity_key_tag):
                    raise UsageDenied('usage_identity_key')
                if now < last:
                    raise UsageDenied('usage_clock')
                for seconds, limit in ((60, identity_minute_limit), (86400, identity_day_limit)):
                    count, = db.execute('SELECT count(*) FROM ip_events WHERE identity=? AND admitted_at>?',
                                        (identity_digest, now - seconds)).fetchone()
                    if count >= limit:
                        raise UsageDenied('usage_identity_budget', 429)
            instant = datetime.fromtimestamp(now, timezone.utc)
            identifier = self._reserve(db, instant.strftime('%Y-%m-%d'), instant.strftime('%Y-%m'))
            db.execute('INSERT INTO session_events VALUES(?,?,?)', (identifier, session, now))
            if identity_aware:
                db.execute('INSERT INTO ip_events VALUES(?,?,?)', (identifier, identity_digest, now))
                db.execute('UPDATE ip_control SET last_admitted_at=? WHERE id=1', (now,))
        return identifier

    def operation(self, identifier, kind):
        if kind not in ("embedding", "generation"):
            raise UsageDenied("usage_operation")
        column = kind + "_ops"  # Strict allowlist above; never visitor input.
        with self._transaction() as db:
            self._enabled(db)
            row = db.execute(f"SELECT day,month,{column} FROM active WHERE id=?", (identifier,)).fetchone()
            if row is None or row[2] != 0:
                raise UsageDenied("usage_operation")
            db.execute(f"UPDATE active SET {column}=1 WHERE id=?", (identifier,))
            for period_kind, period in zip(("day", "month"), row[:2]):
                cursor = db.execute(f"UPDATE periods SET {column}={column}+1 WHERE kind=? AND period=?",
                                    (period_kind, period))
                if cursor.rowcount != 1:
                    raise UsageDenied()

    def release(self, identifier):
        # Release only concurrency; period counters are never refunded.
        with self._transaction() as db:
            db.execute("DELETE FROM active WHERE id=?", (identifier,))

    def set_disabled(self, disabled):
        if type(disabled) is not bool:
            raise ValueError("Disabled state must be boolean.")
        with self._transaction() as db:
            db.execute("UPDATE control SET disabled=? WHERE id=1", (int(disabled),))

    def recover(self, *, workers_stopped=False):
        if not workers_stopped:
            raise UsageDenied("usage_recovery")
        with self._transaction() as db:
            if db.execute("SELECT disabled FROM control WHERE id=1").fetchone()[0] != 1:
                raise UsageDenied("usage_recovery")
            db.execute("DELETE FROM active")

    def status(self):
        with self._transaction() as db:
            day, month = self._periods()
            return {"disabled": bool(db.execute("SELECT disabled FROM control WHERE id=1").fetchone()[0]),
                    "active": db.execute("SELECT count(*) FROM active").fetchone()[0],
                    "periods": {kind: dict(zip(("admitted", "embedding_ops", "generation_ops"),
                        db.execute("SELECT admitted,embedding_ops,generation_ops FROM periods WHERE kind=? AND period=?",
                                   (kind, period)).fetchone() or (0, 0, 0)))
                        for kind, period in (("day", day), ("month", month))}}


current_reservation = ContextVar("paid_usage_reservation", default=None)


@contextmanager
def chat_usage(ledger, *, session_digest=None, minute_limit=3, hour_limit=12, identity_accounting=None):
    if current_reservation.get() is not None:
        raise UsageDenied("usage_operation")
    if identity_accounting is not None and session_digest is None:
        raise UsageDenied('usage_identity')
    if identity_accounting is not None:
        if type(identity_accounting) is not dict or set(identity_accounting) != {
                'identity_digest', 'identity_key_tag', 'identity_minute_limit', 'identity_day_limit'}:
            raise UsageDenied('usage_identity')
        _digest(identity_accounting['identity_digest'])
        _digest(identity_accounting['identity_key_tag'])
    identifier = (ledger.reserve() if session_digest is None else
                  ledger.reserve_session(session_digest, minute_limit=minute_limit, hour_limit=hour_limit,
                                         **(identity_accounting or {})))
    token = current_reservation.set((ledger, identifier))
    try:
        yield
    finally:
        current_reservation.reset(token)
        ledger.release(identifier)


def paid_call(kind, operation):
    """Guard every production SDK call, including CLI/evaluation/ingestion."""
    reservation = current_reservation.get()
    if reservation is None:
        from src.config import Settings
        with chat_usage(UsageLedger.from_settings(Settings.from_env())):
            return paid_call(kind, operation)
    ledger, identifier = reservation
    ledger.operation(identifier, kind)
    from src.diagnostics import current_diagnostics
    diagnostics = current_diagnostics.get()
    if diagnostics is not None:
        diagnostics.check()
    return operation()
