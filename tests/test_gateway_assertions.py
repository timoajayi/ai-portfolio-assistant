"""Offline protocol tests; all keys/vectors are public test data."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.gateway_assertions import (AssertionError as InvalidAssertion, GatewayAssertionVerifier,
                                    VerificationKey, canonical_ip)

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/gateway_assertions_v1.json').read_text())
KEY_DATA = FIXTURE['policy']['currentKey']
KEY = VerificationKey(KEY_DATA['kid'], bytes.fromhex(KEY_DATA['secret_hex']),
                      KEY_DATA['notBefore'], KEY_DATA['notAfter'])
NOW = FIXTURE['now']


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def verifier(**kwargs):
    return GatewayAssertionVerifier(issuer='portfolio-gateway', audience='portfolio-backend',
                                    ip_source='offline-ingress-v1', current_key=KEY, **kwargs)


def signed(header=None, payload=None, *, header_raw=None, payload_raw=None, key=KEY):
    vector = FIXTURE['vectors'][0]
    h = header_raw if header_raw is not None else json.dumps(header or vector['header'], separators=(',', ':')).encode()
    p = payload_raw if payload_raw is not None else json.dumps(payload or vector['payload'], separators=(',', ':')).encode()
    message = b64(h) + '.' + b64(p)
    return message + '.' + b64(hmac.digest(key.secret, message.encode('ascii'), 'sha256'))


def verify(value=None, instance=None, **kwargs):
    vector = FIXTURE['vectors'][0]
    options = dict(session_token=FIXTURE['session_token'], body=base64.b64decode(vector['body_base64']), now=NOW)
    options.update(kwargs)
    return (instance or verifier()).verify(value or vector['assertion'], **options)


class GatewayAssertionTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.socket.connect', 'socket.socket.connect_ex',
                       'socket.create_connection', 'socket.getaddrinfo'):
            guard = patch(target, side_effect=RuntimeError('Offline protocol test'))
            guard.start()
            self.addCleanup(guard.stop)

    def test_verification_emits_no_sensitive_logs(self):
        with patch('logging.Logger._log') as log:
            verify()
            with self.assertRaises(InvalidAssertion):
                verify(body=b'private input marker')
        log.assert_not_called()

    def test_node_vectors_verify_and_independently_match_python_mac(self):
        for vector in FIXTURE['vectors']:
            with self.subTest(vector=vector['name']):
                h, p, signature = vector['assertion'].split('.')
                digest = hmac.new(KEY.secret, (h + '.' + p).encode('ascii'), hashlib.sha256).digest()
                self.assertEqual(b64(digest), signature)
                self.assertEqual(digest.hex(), vector['signature_hex'])
                result = verify(vector['assertion'], body=base64.b64decode(vector['body_base64']))
                self.assertEqual(result.visitor_ip, canonical_ip(vector['visitor_ip_input']))
                self.assertEqual(result.issued_at, NOW)
                self.assertTrue(result.replay_protection_required)
                self.assertFalse(result.ingress_trust_verified)

    def test_original_encoded_input_not_json_reserialization(self):
        vector = FIXTURE['vectors'][0]
        self.assertNotEqual(signed(), signed(payload_raw=json.dumps(vector['payload'], indent=2).encode()))
        verify(signed(header_raw=json.dumps(vector['header'], indent=2).encode(),
                      payload_raw=json.dumps(dict(reversed(list(vector['payload'].items()))), indent=1).encode()))

    def test_every_unsigned_field_tamper_rejected(self):
        vector = FIXTURE['vectors'][0]
        for group in ('header', 'payload'):
            for name in vector[group]:
                with self.subTest(group=group, field=name):
                    item = {**vector[group], name: 'tampered'}
                    h, p, signature = vector['assertion'].split('.')
                    changed = b64(json.dumps(item).encode())
                    assertion = '.'.join([changed if group == 'header' else h,
                                          changed if group == 'payload' else p, signature])
                    with self.assertRaises(InvalidAssertion):
                        verify(assertion)

    def test_missing_wrong_truncated_oversized_signatures(self):
        h, p, _ = FIXTURE['vectors'][0]['assertion'].split('.')
        for signature in ('', b64(b'X' * 31), b64(b'X' * 32), b64(b'X' * 33), '___!', 'a', '===='):
            with self.subTest(signature_length=len(signature)), self.assertRaises(InvalidAssertion):
                verify(h + '.' + p + '.' + signature)
        for value in (h + '.' + p, 'x.y.z.more', '.', 'a' * 2049, 'é', [], None):
            with self.subTest(value_type=type(value)), self.assertRaises(InvalidAssertion):
                verifier().verify(value, session_token=FIXTURE['session_token'], body=b'', now=NOW)

    def test_canonical_base64url_required_on_all_parts(self):
        parts = FIXTURE['vectors'][0]['assertion'].split('.')
        for index in range(3):
            for suffix in ('=', '\n', ' ', '+', '/'):
                item = list(parts)
                item[index] += suffix
                with self.subTest(index=index, suffix=suffix), self.assertRaises(InvalidAssertion):
                    verify('.'.join(item))
        # Same decoded MAC, different nonzero unused pad bits must be rejected.
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        item = list(parts)
        last = alphabet.index(item[2][-1])
        item[2] = item[2][:-1] + alphabet[last + 1]
        with self.assertRaises(InvalidAssertion):
            verify('.'.join(item))

    def test_header_exact_policy(self):
        original = FIXTURE['vectors'][0]['header']
        cases = [{**original, name: value} for name, value in [
            ('typ', 'JWT'), ('alg', 'none'), ('alg', 'HS512'), ('kid', 'unknown'),
            ('kid', 'gateway-key-1\n'), ('kid', None), ('kid', []), ('kid', 'x' * 33),
            ('jku', 'https://invalid.test'), ('jwk', {}), ('crit', []), ('extra', True)]]
        cases += [{k: v for k, v in original.items() if k != name} for name in original]
        for header in cases:
            with self.subTest(header_fields=list(header)), self.assertRaises(InvalidAssertion):
                verify(signed(header=header))

    def test_duplicate_keys_even_escaped_and_malformed_json(self):
        vector = FIXTURE['vectors'][0]
        for side in ('header', 'payload'):
            raw = json.dumps(vector[side], separators=(',', ':')).encode()
            field = b'"alg":"HS256"' if side == 'header' else b'"v":1'
            for duplicate in (field, b'"\\u0061lg":"HS256"' if side == 'header' else b'"\\u0076":1'):
                args = {side + '_raw': raw[:-1] + b',' + duplicate + b'}'}
                with self.subTest(side=side), self.assertRaises(InvalidAssertion):
                    verify(signed(**args))
        for raw in (b'[]', b'null', b'{', b'{"x":NaN}', b'{"x":1e2}', b'\xff', b'{}{}'):
            for side in ('header_raw', 'payload_raw'):
                with self.subTest(raw=raw, side=side), self.assertRaises(InvalidAssertion):
                    verify(signed(**{side: raw}))

    def test_exact_payload_types_and_fields(self):
        original = FIXTURE['vectors'][0]['payload']
        for field in original:
            for replacement in (None, [], {}, False, '', 'é'):
                with self.subTest(field=field, replacement=replacement), self.assertRaises(InvalidAssertion):
                    verify(signed(payload={**original, field: replacement}))
            with self.subTest(missing=field), self.assertRaises(InvalidAssertion):
                verify(signed(payload={k: v for k, v in original.items() if k != field}))
        with self.assertRaises(InvalidAssertion):
            verify(signed(payload={**original, 'verified': True}))
        for field, value in (('v', 1.0), ('v', True), ('iat', True), ('exp', NOW + 30.0)):
            with self.subTest(field=field, value=value), self.assertRaises(InvalidAssertion):
                verify(signed(payload={**original, field: value}))

    def test_identifiers_no_normalization_or_coercion(self):
        original = FIXTURE['vectors'][0]['payload']
        for name in ('iss', 'aud', 'ip_source'):
            for value in ('other', ' portfolio-gateway', 'x\n', 'x' * 65, 'e\u0301', 42):
                with self.subTest(name=name, value=value), self.assertRaises(InvalidAssertion):
                    verify(signed(payload={**original, name: value}))

    def test_timestamp_boundaries(self):
        original = FIXTURE['vectors'][0]['payload']
        verify(now=NOW + 29)
        verify(now=NOW - 5)
        for now in (NOW + 30, NOW - 6, True, 1.5, -1, '1800000000'):
            with self.subTest(now=now), self.assertRaises(InvalidAssertion):
                verify(now=now)
        for iat, exp in ((NOW, NOW), (NOW, NOW - 1), (NOW, NOW + 31), (-1, 20),
                         (NOW + 6, NOW + 7), (NOW - 60, NOW - 30), (True, NOW), (NOW, 253402300800)):
            with self.subTest(iat=iat, exp=exp), self.assertRaises(InvalidAssertion):
                verify(signed(payload={**original, 'iat': iat, 'exp': exp}))
        verify(signed(payload={**original, 'iat': NOW + 5, 'exp': NOW + 30}))

    def test_nonce_requires_256_bit_canonical_shape_but_cannot_prove_entropy(self):
        original = FIXTURE['vectors'][0]['payload']
        for nonce in ('', '1234567890', b64(bytes(31)), b64(bytes(33)), b64(bytes(32)), b64(b'X' * 32), b64(bytes(32)) + '=', 'é' * 43):
            with self.subTest(length=len(nonce)), self.assertRaises(InvalidAssertion):
                verify(signed(payload={**original, 'jti': nonce}))
        # Format verification cannot prove randomness or freshness.
        result = verify()
        self.assertEqual(result, verify())
        self.assertTrue(result.replay_protection_required)

    def test_exact_request_binding(self):
        for kwargs in ({'session_token': b64(b'X' * 32)}, {'body': b'{ "message":"What is BundesHost?"}'},
                       {'body': b''}, {'body': bytearray(b'x')}, {'body': b'X' * 8193},
                       {'method': 'GET'}, {'method': 'post'}, {'path': '/internal/session-chat/'},
                       {'path': '/internal/session-chat?q=1'}, {'path': '/internal/%73ession-chat'},
                       {'session_token': FIXTURE['session_token'] + '='}):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(InvalidAssertion):
                verify(**kwargs)
        original = FIXTURE['vectors'][0]['payload']
        for name in ('session_sha256', 'body_sha256'):
            for value in ('A' * 64, '0' * 63, '0' * 64, b64(bytes(32)), 'x' * 64):
                with self.subTest(name=name, value=value), self.assertRaises(InvalidAssertion):
                    verify(signed(payload={**original, name: value}))

    def test_ip_canonical_and_invalid_literals(self):
        original = FIXTURE['vectors'][0]['payload']
        for address in ('192.000.2.42', '192.0.2.42:80', ' 192.0.2.42', '192.0.2.42/32',
                        'example.test', '192.0.2.42,192.0.2.43', 'fe80::1%eth0', '[::1]',
                        '::ffff:192.0.2.42', '2001:DB8::1', '2001:0db8::1', 'invalid'):
            with self.subTest(address=address), self.assertRaises(InvalidAssertion):
                verify(signed(payload={**original, 'visitor_ip': address}))
        self.assertEqual(canonical_ip('::ffff:c000:22a'), '192.0.2.42')
        self.assertEqual(canonical_ip('2001:DB8::1'), '2001:db8::1')

    def test_key_configuration_and_rotation(self):
        previous = VerificationKey('previous-key', b'P' * 32, NOW - 60, NOW + 31)
        rotated = verifier(previous_key=previous)
        header = {**FIXTURE['vectors'][0]['header'], 'kid': previous.kid}
        old_assertion = signed(header=header, key=previous)
        verify(old_assertion, instance=rotated)
        verify(instance=rotated)
        with self.assertRaises(InvalidAssertion):
            verify(old_assertion)  # removing previous key revokes it immediately
        for key in (VerificationKey('previous-key', b'P' * 32, NOW + 1, NOW + 100),
                    VerificationKey('previous-key', b'P' * 32, NOW - 60, NOW + 29)):
            with self.subTest(window=key.not_after), self.assertRaises(InvalidAssertion):
                verify(signed(header=header, key=key), instance=verifier(previous_key=key))
        for kwargs in ({'kid': 'x\n'}, {'secret': b'x' * 31}, {'secret': b'x' * 65},
                       {'secret': bytearray(32)}, {'not_before': True}, {'not_after': NOW - 101}):
            params = dict(kid='test-key', secret=b'K' * 32, not_before=NOW - 100, not_after=NOW + 100)
            params.update(kwargs)
            with self.subTest(params=list(kwargs)), self.assertRaises(InvalidAssertion):
                VerificationKey(**params)
        for previous in (KEY, VerificationKey('other-key', KEY.secret, KEY.not_before, KEY.not_after), []):
            with self.assertRaises(InvalidAssertion):
                verifier(previous_key=previous)
        for field in ('issuer', 'audience', 'ip_source'):
            params = dict(issuer='gateway', audience='backend', ip_source='ingress', current_key=KEY)
            for value in ('', 'x\n', None, 'é'):
                with self.subTest(field=field), self.assertRaises(InvalidAssertion):
                    GatewayAssertionVerifier(**{**params, field: value})

    def test_constant_time_mac_and_digest_comparison(self):
        original = hmac.compare_digest
        with patch('src.gateway_assertions.hmac.compare_digest', wraps=original) as compare:
            verify()
        self.assertEqual(compare.call_count, 3)
        self.assertEqual(len(compare.call_args_list[0].args[0]), 32)

    def test_bounded_json_and_sanitized_errors_results(self):
        for value in (signed(header_raw=b' ' * 257), signed(payload_raw=b' ' * 1025)):
            with self.assertRaises(InvalidAssertion):
                verify(value)
        with self.assertRaises(InvalidAssertion) as error:
            verify(body=b'private body')
        self.assertEqual(str(error.exception), 'Invalid gateway assertion.')
        self.assertNotIn(KEY.secret.hex(), repr(KEY))
        result = verify()
        for private in (result.visitor_ip, result.nonce, result.session_sha256, result.body_sha256):
            self.assertNotIn(private, repr(result))
        with self.assertRaises(Exception):
            result.visitor_ip = 'other'


if __name__ == '__main__':
    unittest.main()
