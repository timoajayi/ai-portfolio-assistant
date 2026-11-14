"""Server-only failure diagnostics; mocked transports and disposable ledgers only."""
import asyncio
from datetime import timedelta
import json
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from src.bot_verification import verification_diagnostics, verification_stage, VerificationError
from src.reliability import RateLimiter
from src.usage import UsageDenied, UsageLedger
from tests.test_bot_verification import BotFixture


class VerificationDiagnosticTests(BotFixture):
    def setUp(self):
        super().setUp()
        self.api = self.load('src.api')
        self.api.app.state.chat_controls.settings = self.settings
        self.api.app.state.verification_service = self.service
        self.api.app.state.chat_controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.warning = self.stack.enter_context(patch('src.bot_verification.logger.warning'))
        self.info = self.stack.enter_context(patch('src.reliability.logger.info'))
        self.sensitive = 'private-exception-cookie-credential-marker'

    def post(self):
        return self.http.post('/internal/verified-sessions', json={'proof': self.proof},
                              headers={'Authorization': 'Bearer ' + 's' * 43})

    def failure(self, stage, category, exception_class, status):
        sessions_before = self.rows()['sessions']
        response = self.post()
        self.assertEqual(response.status_code, status)
        self.assertEqual(response.json(), {'detail': 'Verification unavailable.'})
        self.assertEqual(response.headers['cache-control'], 'no-store')
        events = [json.loads(call.args[0]) for call in self.warning.call_args_list]
        events = [event for event in events if event['event'] == 'verified_session_failure']
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(set(event), {'event', 'request_id', 'stage', 'category', 'exception_class', 'status'})
        self.assertEqual((event['stage'], event['category'], event['exception_class'], event['status']),
                         (stage, category, exception_class, status))
        self.assertRegex(event['request_id'], r'^[0-9a-f]{32}$')
        serialized = str(self.warning.call_args_list) + str(self.info.call_args_list) + response.text
        for sensitive in (self.proof, self.settings.bot_secret, 's' * 43, self.sensitive):
            self.assertNotIn(sensitive, serialized)
        self.assertEqual(self.rows()['sessions'], sessions_before)
        self.client_factory.assert_not_called()
        return response

    def test_transport_connection_failure_keeps_original_class(self):
        def handler(request):
            raise httpx.ConnectError(self.sensitive, request=request)
        self.handler = handler
        self.failure('cloudflare_transport', 'network', 'ConnectError', 503)
        self.assertEqual(len(self.calls), 1)

    def test_transport_timeout(self):
        def handler(request):
            raise httpx.ReadTimeout(self.sensitive, request=request)
        self.handler = handler
        self.failure('cloudflare_transport', 'timeout', 'ReadTimeout', 504)

    def test_unexpected_transport_exception(self):
        def handler(request):
            raise RuntimeError(self.sensitive)
        self.handler = handler
        self.failure('cloudflare_transport', 'unexpected', 'RuntimeError', 503)

    def test_provider_http_failure(self):
        self.handler = lambda request: httpx.Response(503, text=self.sensitive)
        self.failure('cloudflare_response', 'provider_http_status', 'VerificationError', 503)

    def test_non_identity_compression_has_distinct_sanitized_diagnostic(self):
        # No compressed bytes need be read: this is a response-header rejection.
        self.handler = lambda request: httpx.Response(200, headers={'Content-Encoding': 'gzip'})
        self.failure('cloudflare_response', 'provider_content_encoding', 'VerificationError', 503)
        self.assertEqual(len(self.calls), 1)
        # A server ignoring identity negotiation is still rejected, never retried.
        self.assertEqual(self.calls[0].headers.get_list('accept-encoding'), ['identity'])

    def test_non_200_status_precedes_encoding_rejection_without_body_reads(self):
        class Unreadable(httpx.AsyncByteStream):
            async def __aiter__(self):
                raise AssertionError('Provider body must not be read.')
                yield b''
        self.handler = lambda request: httpx.Response(503, stream=Unreadable(),
            headers={'Content-Encoding': self.sensitive})
        self.failure('cloudflare_response', 'provider_http_status', 'VerificationError', 503)
        self.assertEqual(len(self.calls), 1)

    def test_unsupported_encoding_is_not_logged_or_read(self):
        class Unreadable(httpx.AsyncByteStream):
            async def __aiter__(self):
                raise AssertionError('Provider body must not be read.')
                yield b''
        self.handler = lambda request: httpx.Response(200, stream=Unreadable(),
            headers={'Content-Encoding': self.sensitive})
        self.failure('cloudflare_response', 'provider_content_encoding', 'VerificationError', 503)
        self.assertEqual(len(self.calls), 1)

    def test_provider_error_codes_are_rejections_not_transport_failures(self):
        for code in ('missing-input-secret', 'invalid-input-secret', 'missing-input-response',
                     'invalid-input-response', 'bad-request', 'timeout-or-duplicate', 'internal-error',
                     self.sensitive):
            with self.subTest(code=code):
                self.warning.reset_mock()
                self.proof += 'x'  # Each isolated attempt needs a fresh claim.
                self.handler = lambda request: httpx.Response(200, json={'success': False, 'error-codes': [code]})
                self.failure('verification_validation', 'invalid', 'VerificationError', 403)

    def test_malformed_content_type_is_a_response_failure(self):
        self.handler = lambda request: httpx.Response(200, text=self.sensitive)
        self.failure('cloudflare_response', 'invalid', 'VerificationError', 403)

    def test_metadata_not_logged_on_verification_rejection(self):
        self.handler = lambda request: httpx.Response(200, json=self.success(
            success=False, metadata={'ephemeral_id': self.sensitive}))
        self.failure('verification_validation', 'invalid', 'VerificationError', 403)

    def test_invalid_provider_json(self):
        self.handler = lambda request: httpx.Response(200, content=self.sensitive,
                                                     headers={'content-type': 'application/json'})
        self.failure('cloudflare_response', 'invalid', 'VerificationError', 403)

    def test_verification_rejection(self):
        self.handler = lambda request: httpx.Response(200, json=self.success(success=False, cdata=self.sensitive))
        self.failure('verification_validation', 'invalid', 'VerificationError', 403)

    def test_expired_proof(self):
        self.handler = lambda request: httpx.Response(200, json=self.success(
            challenge_ts=(self.now - timedelta(seconds=301)).isoformat()))
        self.failure('verification_freshness', 'age', 'VerificationError', 403)

    def test_claim_storage_failure_before_transport(self):
        with patch.object(UsageLedger, 'claim_verification', side_effect=UsageDenied('usage_storage')):
            self.failure('claim_reservation', 'usage_storage', 'UsageDenied', 503)
        self.assertEqual(self.calls, [])

    def test_finalization_storage_failure_consumes_claim(self):
        with patch.object(UsageLedger, 'finalize_verification', side_effect=UsageDenied('usage_storage')):
            self.failure('session_finalization', 'usage_storage', 'UsageDenied', 503)
        self.assertEqual(len(self.claims()), 1)
        self.assertEqual(len(self.calls), 1)

    def test_unexpected_finalization_failure(self):
        with patch.object(UsageLedger, 'finalize_verification', side_effect=RuntimeError(self.sensitive)):
            self.failure('session_finalization', 'unexpected', 'RuntimeError', 503)

    def test_quota_status_and_retry_header_preserved(self):
        with patch.object(UsageLedger, 'claim_verification', side_effect=UsageDenied('verification_budget', 429)):
            response = self.failure('claim_reservation', 'verification_budget', 'UsageDenied', 429)
        self.assertEqual(response.headers['retry-after'], '60')

    def test_success_does_not_log_raw_token(self):
        response = self.post()
        self.assertEqual(response.status_code, 201)
        self.warning.assert_not_called()
        self.assertNotIn(response.json()['token'], str(self.info.call_args_list))
        self.client_factory.assert_not_called()

    def test_unknown_exception_class_and_category_cannot_inject_logs(self):
        malicious = type(self.sensitive, (RuntimeError,), {})
        with patch.object(UsageLedger, 'claim_verification', side_effect=malicious(self.proof)):
            self.failure('claim_reservation', 'unexpected', 'Exception', 503)
        self.warning.reset_mock()
        with patch.object(UsageLedger, 'claim_verification', side_effect=UsageDenied(self.sensitive)):
            self.failure('claim_reservation', 'unexpected', 'UsageDenied', 503)

    def test_diagnostic_sink_failure_preserves_response(self):
        self.warning.side_effect = RuntimeError(self.sensitive)
        self.handler = lambda request: httpx.Response(503)
        self.assertEqual(self.post().status_code, 503)

    def test_concurrent_diagnostic_contexts_do_not_mix(self):
        async def fail(request_id, stage):
            try:
                with verification_diagnostics(request_id):
                    verification_stage(stage)
                    await asyncio.sleep(0)
                    raise VerificationError()
            except VerificationError:
                pass
        async def run():
            await asyncio.gather(fail('a' * 32, 'claim_reservation'), fail('b' * 32, 'session_finalization'))
        asyncio.run(run())
        events = [json.loads(call.args[0]) for call in self.warning.call_args_list]
        self.assertEqual({event['request_id']: event['stage'] for event in events},
                         {'a' * 32: 'claim_reservation', 'b' * 32: 'session_finalization'})
        self.warning.reset_mock()
        verification_stage('session_finalization')
        try:
            with verification_diagnostics('c' * 32):
                raise VerificationError()
        except VerificationError:
            pass
        self.assertEqual(json.loads(self.warning.call_args.args[0])['stage'], 'configuration')
