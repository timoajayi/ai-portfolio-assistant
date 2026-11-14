"""Actual SDK serialization with memory-only HTTP; independent client cleanup."""

import asyncio
import json
import os
import traceback
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from google import genai
import httpx

from src.provider import ERROR_DETAIL
from tests.offline import OfflineTestCase


SDK_CLIENT = genai.Client


class SDKGenerationLifecycleTests(OfflineTestCase):
    def exercise(self, reason, *, upstream_status=200, expected_status=200):
        api = self.load("src.api")
        requests = []
        private = "PRIVATE-PROVIDER-CONTENT"

        def handle(request):
            requests.append(request)
            if upstream_status != 200:
                return httpx.Response(upstream_status, json={
                    "error": {"code": upstream_status, "message": private},
                })
            candidate = {
                "content": {"role": "model", "parts": [{"text": private}]},
                "finishReason": reason if len(requests) == 1 else "STOP",
            }
            if reason == "CONTINUATION" and len(requests) == 1:
                candidate["continuationToken"] = "b2ZmbGluZQ=="
            return httpx.Response(200, json={"candidates": [candidate]})

        def factory(**kwargs):
            options = kwargs["http_options"]
            self.assertEqual(options.retry_options.attempts, 1)
            if options.timeout == 10000:
                return self.provider  # Query embedding remains a separate operation.
            self.assertEqual(options.timeout, 20000)
            kwargs["http_options"] = options.model_copy(update={
                "client_args": {"transport": httpx.MockTransport(handle)},
            })
            client = SDK_CLIENT(**kwargs)
            self.stack.callback(client.close)
            self.stack.callback(lambda: asyncio.run(client.aio.aclose()))
            return client

        self.client_factory.side_effect = factory
        with patch("src.reliability.logger.info") as info, TestClient(api.app, headers=self.authorize_legacy_staging(api)) as client:
            response = client.post("/chat", json={"message": "What is BundesHost?"})
        self.assertEqual(response.status_code, expected_status)
        self.assertEqual(response.json(), {"answer": private} if expected_status == 200 else {
            "detail": ERROR_DETAIL,
        })
        # A continuation response includes a valid token: this assertion fails
        # if the SDK silently follows it, even though HTTP retry attempts is one.
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.url.host, "generativelanguage.googleapis.com")
        self.assertTrue(request.url.path.endswith("/models/gemini-3.8-flash:generateContent"))
        config = json.loads(request.content)["generationConfig"]
        self.assertEqual(config["maxOutputTokens"], 1024)
        # This SDK version retains snake_case inside the nested thinking dict.
        self.assertEqual(config["thinkingConfig"]["thinking_level"], "LOW")
        self.assertEqual(request.extensions["timeout"]["connect"], 20)
        self.assertEqual(request.extensions["timeout"]["read"], 20)
        self.assertEqual(api.settings.chat_deadline_seconds, 40)
        self.models.embed_content.assert_called_once()
        self.assertEqual(self.models.embed_content.call_args.kwargs["config"]["task_type"], "RETRIEVAL_QUERY")
        self.assertEqual(self.models.embed_content.call_args.kwargs["config"]["output_dimensionality"], 3072)
        self.models.generate_content.assert_not_called()  # Actual SDK handled generation.
        info.assert_called_once()
        record = json.loads(info.call_args.args[0])
        self.assertEqual(record["status"], expected_status)
        if upstream_status == 200:
            self.assertEqual(record["generation"]["finish_reason"], reason)
        serialized = json.dumps(record)
        for sensitive in (private, "What is BundesHost?", "Retrieved portfolio context",
                          "offline-test-key-not-a-secret", "continuationToken"):
            self.assertNotIn(sensitive, serialized)
        for guard in self.network_guards:
            guard.assert_not_called()
        return record

    def test_continuation_token_does_not_trigger_second_http_request(self):
        record = self.exercise("CONTINUATION", expected_status=502)
        self.assertEqual(record["provider_failure"], "incomplete_response")

    def test_stop_is_successful_with_one_http_request(self):
        self.exercise("STOP")

    def test_max_tokens_is_rejected_with_one_http_request(self):
        record = self.exercise("MAX_TOKENS", expected_status=502)
        self.assertEqual(record["provider_failure"], "incomplete_response")

    def test_quota_response_is_not_retried(self):
        record = self.exercise(None, upstream_status=429, expected_status=503)
        self.assertEqual(record["provider_failure"], "quota")

    def test_server_error_is_not_retried(self):
        record = self.exercise(None, upstream_status=503, expected_status=502)
        self.assertEqual(record["provider_failure"], "provider_error")


class ProviderShutdownTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load("src.api")
        self.embeddings = self.load("src.embeddings")
        self.generation = Mock(spec_set=["close"])
        self.embedding = Mock(spec_set=["close"])
        self.api.client = self.generation
        self.embeddings.client = self.embedding

    def shutdown(self, failed_clients):
        sensitive = "PRIVATE-CLOSE-ERROR-AND-CREDENTIAL"
        for name, client in (("generation", self.generation), ("embedding", self.embedding)):
            if name in failed_clients:
                client.close.side_effect = RuntimeError(sensitive)
        with patch("src.reliability.logger.error") as error_log:
            if failed_clients:
                with self.assertRaises(RuntimeError) as caught:
                    with TestClient(self.api.app):
                        pass
                self.assertEqual(str(caught.exception), "Provider client shutdown failed.")
                formatted = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn(sensitive, formatted)
                self.assertIsNone(caught.exception.__cause__)
                error_log.assert_called_once()
                record = json.loads(error_log.call_args.args[0])
                self.assertEqual(record, {
                    "event": "provider_shutdown", "status": "failed",
                    "failed_clients": failed_clients,
                })
                self.assertNotIn(sensitive, json.dumps(record))
                self.assertNotIn("offline-test-key-not-a-secret", json.dumps(record))
            else:
                with TestClient(self.api.app):
                    pass
                error_log.assert_not_called()
        self.generation.close.assert_called_once_with()
        self.embedding.close.assert_called_once_with()
        self.assertIsNone(self.api.client)
        self.assertIsNone(self.embeddings.client)
        self.assertIsNone(self.api.app.state.rag_index)
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        for guard in self.network_guards:
            guard.assert_not_called()

    def test_both_clients_close_successfully(self):
        self.shutdown([])

    def test_generation_failure_does_not_skip_embedding_cleanup(self):
        self.shutdown(["generation"])

    def test_embedding_failure_does_not_skip_generation_cleanup(self):
        self.shutdown(["embedding"])

    def test_both_failures_are_reported_without_provider_details(self):
        self.shutdown(["generation", "embedding"])

    def test_shutdown_without_initialized_clients_does_not_construct_them(self):
        self.api.client = None
        self.embeddings.client = None
        with TestClient(self.api.app):
            pass
        self.generation.close.assert_not_called()
        self.embedding.close.assert_not_called()
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()


class SDKEmbeddingFailureTests(OfflineTestCase):
    """Exercise the installed SDK serializer/error parser without network access."""

    def exercise_embedding(self, upstream_status, upstream_category=None, *, error_details=None, expected_reason=None):
        api = self.load('src.api')
        requests = []
        sensitive = 'PRIVATE-EMBEDDING-ERROR-MARKER'

        def handle(request):
            requests.append(request)
            if upstream_status != 200:
                return httpx.Response(upstream_status, json={'error': {
                    'code': upstream_status, 'status': upstream_category, 'message': sensitive,
                    **({'details': error_details} if error_details is not None else {})}})
            return httpx.Response(200, json={'embeddings': [{'values': self.vector.copy()}]})

        def factory(**kwargs):
            options = kwargs['http_options']
            if options.timeout != 10000:
                return self.provider  # Generation stays mocked, never networked.
            self.assertEqual(options.retry_options.attempts, 1)
            kwargs['http_options'] = options.model_copy(update={
                'client_args': {'transport': httpx.MockTransport(handle)}})
            return SDK_CLIENT(**kwargs)

        with patch('src.embeddings.genai.Client', side_effect=factory), \
             patch('src.reliability.logger.info') as info, \
             patch('src.reliability.logger.warning') as warning, \
             TestClient(api.app, headers=self.authorize_legacy_staging(api)) as client:
            response = client.post('/chat', json={'message': 'What is BundesHost?'})
        if upstream_status == 200:
            warning.assert_not_called()
        else:
            warning.assert_called_once()
            diagnostic = json.loads(warning.call_args.args[0])
            self.assertEqual(diagnostic, {
                'upstream_http_status': upstream_status,
                'sdk_status': upstream_category,
                'exception_class': 'ServerError' if upstream_status >= 500 else 'ClientError',
                'operation': 'embedding', 'api_mode': 'developer', 'rejection_reason': expected_reason,
            })
            for private in (sensitive, 'offline-test-key-not-a-secret', 'What is BundesHost?'):
                self.assertNotIn(private, json.dumps(diagnostic))
        self.assertEqual(len(requests), 1)  # Including retryable server/quota failures.
        request = requests[0]
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.url.host, 'generativelanguage.googleapis.com')
        self.assertEqual(request.url.path, '/v1beta/models/gemini-embedding-001:batchEmbedContents')
        body = json.loads(request.content)
        self.assertEqual(len(body['requests']), 1)
        item = body['requests'][0]
        self.assertEqual(item['model'], 'models/gemini-embedding-001')
        self.assertEqual(item['taskType'], 'RETRIEVAL_QUERY')
        self.assertEqual(item['outputDimensionality'], 3072)
        self.assertEqual(set(body), {'requests'})
        self.assertEqual(set(item), {'model', 'content', 'taskType', 'outputDimensionality'})
        self.assertEqual(set(item['content']), {'parts', 'role'})
        self.assertEqual(item['content']['role'], 'user')
        self.assertEqual(set(item['content']['parts'][0]), {'text'})
        self.assertEqual(len(item['content']['parts']), 1)
        self.assertIsInstance(item['content']['parts'][0]['text'], str)
        self.assertEqual(request.extensions['timeout']['read'], 10)
        record = json.loads(info.call_args.args[0])
        for private in (sensitive, 'offline-test-key-not-a-secret', 'What is BundesHost?'):
            self.assertNotIn(private, response.text if upstream_status != 200 else '')
            self.assertNotIn(private, json.dumps(record))
        for guard in self.network_guards:
            guard.assert_not_called()
        return response, record

    def test_real_sdk_embedding_serialization_and_mocked_response_are_compatible(self):
        response, record = self.exercise_embedding(200)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(record['provider_failure'])
        self.models.generate_content.assert_called_once()
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1})

    def test_structured_api_key_rejection_is_logged_without_provider_details(self):
        response, record = self.exercise_embedding(400, 'INVALID_ARGUMENT', error_details=[{
            '@type': 'type.googleapis.com/google.rpc.ErrorInfo', 'domain': 'googleapis.com',
            'reason': 'API_KEY_INVALID', 'metadata': {'key': 'PRIVATE-EMBEDDING-ERROR-MARKER'},
        }], expected_reason='API_KEY_INVALID')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(record['provider_failure'], 'provider_error')
        self.models.generate_content.assert_not_called()
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 0})

    def test_embedding_errors_are_sanitized_but_provider_error_is_ambiguous(self):
        for code, upstream, expected_status, category in (
            (400, 'INVALID_ARGUMENT', 502, 'provider_error'),
            (401, 'UNAUTHENTICATED', 502, 'provider_error'),
            (403, 'PERMISSION_DENIED', 502, 'provider_error'),
            (404, 'NOT_FOUND', 502, 'provider_error'),
            (500, 'INTERNAL', 502, 'provider_error'),
            (503, 'UNAVAILABLE', 502, 'provider_error'),
            (429, 'RESOURCE_EXHAUSTED', 503, 'quota'),
            (408, 'DEADLINE_EXCEEDED', 504, 'timeout'),
            (504, 'DEADLINE_EXCEEDED', 504, 'timeout'),
        ):
            with self.subTest(upstream_status=code):
                response, record = self.exercise_embedding(code, upstream)
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(response.json(), {'detail': ERROR_DETAIL})
                self.assertEqual(record['provider_failure'], category)
                if code == 429:
                    self.assertEqual(response.headers['retry-after'], '60')
                self.models.generate_content.assert_not_called()
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 9, 'embedding_ops': 9, 'generation_ops': 0})


class EmbeddingDiagnosticSafetyTests(OfflineTestCase):
    def test_untrusted_status_code_and_exception_class_are_sanitized(self):
        from google.genai import errors
        embeddings = self.load('src.embeddings')
        secret = 'PRIVATE-KEY-BODY-HEADER-MARKER'
        error_type = type(secret, (errors.APIError,), {})
        error = error_type(400, {'error': {'message': secret}})
        for code, status in ((True, secret), ('403', {'private': secret}), (999, [secret]),
                             (None, None), (-1, secret)):
            error.code, error.status = code, status
            with patch('src.reliability.logger.warning') as warning:
                embeddings._log_embedding_failure(error)
            self.assertEqual(json.loads(warning.call_args.args[0]), {
                'upstream_http_status': None, 'sdk_status': None,
                'exception_class': 'Exception', 'operation': 'embedding',
                'api_mode': 'unknown', 'rejection_reason': None})
            self.assertNotIn(secret, str(warning.call_args))
        self.client_factory.assert_not_called()

    def test_structured_reasons_are_narrowly_allowlisted_and_never_read_from_messages(self):
        from google.genai import errors
        embeddings = self.load('src.embeddings')
        private = 'PRIVATE-STRUCTURED-DETAILS-MARKER'
        info = {'@type': 'type.googleapis.com/google.rpc.ErrorInfo',
                'domain': 'googleapis.com', 'reason': 'API_KEY_INVALID'}
        cases = (
            (None, None),
            ([info], 'API_KEY_INVALID'),
            ([{**info, 'reason': 'SERVICE_DISABLED', 'metadata': {'key': private}}], 'SERVICE_DISABLED'),
            ([{**info, 'reason': private}], None),
            ([{**info, 'reason': {'key': private}}], None),
            ([{**info, 'domain': private}], None),
            ([{**info, '@type': private}], None),
            ([{**info, 'reason': 'API_KEY_INVALID ' + private}], None),
            ([info, {**info, 'reason': 'API_KEY_EXPIRED'}], None),
            ([info] * 17, None),
            ({'key': private}, None),
            ([{'@type': 'type.googleapis.com/google.rpc.BadRequest',
               'fieldViolations': [{'field': private, 'description': private}]}], None),
        )
        for details, expected in cases:
            with self.subTest(expected=expected):
                error = errors.ClientError(400, {'error': {'status': 'INVALID_ARGUMENT',
                    'message': 'API_KEY_INVALID ' + private, 'details': details}})
                with patch('src.reliability.logger.warning') as warning:
                    embeddings._log_embedding_failure(error)
                event = json.loads(warning.call_args.args[0])
                self.assertEqual(event['rejection_reason'], expected)
                self.assertEqual(set(event), {'upstream_http_status', 'sdk_status', 'exception_class',
                                              'operation', 'api_mode', 'rejection_reason'})
                self.assertNotIn(private, str(warning.call_args))
        self.client_factory.assert_not_called()

    def test_effective_api_mode_uses_only_boolean_client_mode(self):
        embeddings = self.load('src.embeddings')
        for value, expected in ((False, 'developer'), (True, 'vertex'),
                                (None, 'unknown'), ('PRIVATE-MODE-MARKER', 'unknown')):
            with patch.object(embeddings, 'client', Mock(vertexai=value)), \
                 patch('src.reliability.logger.warning') as warning:
                embeddings._log_embedding_failure(RuntimeError('PRIVATE-ERROR-MARKER'))
            event = json.loads(warning.call_args.args[0])
            self.assertEqual(event['api_mode'], expected)
            self.assertNotIn('PRIVATE', str(warning.call_args))

    def test_transport_error_has_no_invented_upstream_status(self):
        embeddings = self.load('src.embeddings')
        with patch('src.reliability.logger.warning') as warning:
            embeddings._log_embedding_failure(httpx.ReadTimeout('PRIVATE-TRANSPORT-MARKER'))
        self.assertEqual(json.loads(warning.call_args.args[0]), {
            'upstream_http_status': None, 'sdk_status': None,
            'exception_class': 'ReadTimeout', 'operation': 'embedding',
            'api_mode': 'unknown', 'rejection_reason': None})
        self.client_factory.assert_not_called()

    def test_logging_failure_preserves_original_provider_failure(self):
        from google.genai import errors
        api = self.load('src.api')
        original = errors.ClientError(403, {'error': {'status': 'PERMISSION_DENIED', 'message': 'PRIVATE'}})
        self.models.embed_content.side_effect = original
        with patch('src.reliability.logger.warning', side_effect=RuntimeError('PRIVATE-SINK')), \
             TestClient(api.app, headers=self.authorize_legacy_staging(api)) as client:
            response = client.post('/chat', json={'message': 'What is BundesHost?'})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {'detail': ERROR_DETAIL})
        self.models.generate_content.assert_not_called()
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 0})

    def test_usage_denial_does_not_log_a_provider_failure_or_invoke_provider(self):
        api = self.load('src.api')
        self.usage_ledger.set_disabled(True)
        with patch('src.reliability.logger.warning') as warning, \
             TestClient(api.app, headers=self.authorize_legacy_staging(api)) as client:
            response = client.post('/chat', json={'message': 'What is BundesHost?'})
        self.assertEqual(response.status_code, 503)
        warning.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()


class SDKEmbeddingProviderSelectionTests(OfflineTestCase):
    def route(self, overrides):
        from google.genai import errors
        embeddings = self.load('src.embeddings')
        captured = []
        environment = {
            'GOOGLE_GENAI_USE_ENTERPRISE': 'false', 'GOOGLE_GENAI_USE_VERTEXAI': 'false',
            'GOOGLE_CLOUD_PROJECT': '', 'GOOGLE_CLOUD_LOCATION': '',
            'GOOGLE_GEMINI_BASE_URL': '', 'GOOGLE_VERTEX_BASE_URL': '',
        }
        environment.update(overrides)

        def handle(request):
            captured.append(request)
            return httpx.Response(400, json={'error': {
                'code': 400, 'status': 'INVALID_ARGUMENT', 'message': 'PRIVATE-MOCK-ERROR'}})

        def factory(**kwargs):
            options = kwargs['http_options']
            self.assertEqual(options.api_version, 'v1beta')
            self.assertEqual(options.base_url, 'https://generativelanguage.googleapis.com/')
            self.assertIs(kwargs['vertexai'], False)
            self.assertNotIn('enterprise', kwargs)
            kwargs['http_options'] = options.model_copy(update={
                'client_args': {'transport': httpx.MockTransport(handle)}})
            return SDK_CLIENT(**kwargs)

        with patch.dict(os.environ, {key: value for key, value in environment.items() if value is not None}), \
             patch('src.embeddings.genai.Client', side_effect=factory), \
             patch('src.reliability.logger.warning'):
            try:
                for key, value in environment.items():
                    if value is None:
                        os.environ.pop(key, None)
                provider = embeddings.get_client()
                vertex = provider.vertexai
                with self.assertRaises(errors.ClientError):
                    embeddings.create_embedding('Offline query fixture', task_type='RETRIEVAL_QUERY')
            finally:
                embeddings.close_client()
        self.assertEqual(len(captured), 1)
        for guard in self.network_guards:
            guard.assert_not_called()
        return vertex, captured[0]

    def test_controlled_configuration_uses_developer_api_and_expected_request(self):
        vertex, request = self.route({})
        self.assertFalse(vertex)
        self.assertEqual(request.url.host, 'generativelanguage.googleapis.com')
        self.assertEqual(request.url.path, '/v1beta/models/gemini-embedding-001:batchEmbedContents')
        self.assertEqual(json.loads(request.content), {'requests': [{
            'model': 'models/gemini-embedding-001',
            'content': {'parts': [{'text': 'Offline query fixture'}], 'role': 'user'},
            'taskType': 'RETRIEVAL_QUERY', 'outputDimensionality': 3072}]})

    def test_sdk_environment_cannot_override_explicit_developer_mode(self):
        for flag in ('GOOGLE_GENAI_USE_VERTEXAI', 'GOOGLE_GENAI_USE_ENTERPRISE'):
            with self.subTest(flag=flag):
                # Remove the other selector, rather than creating a precedence conflict.
                other = 'GOOGLE_GENAI_USE_ENTERPRISE' if flag == 'GOOGLE_GENAI_USE_VERTEXAI' else 'GOOGLE_GENAI_USE_VERTEXAI'
                environment = {flag: 'true', other: None}
                vertex, request = self.route(environment)
                self.assertFalse(vertex)
                self.assertEqual(request.url.host, 'generativelanguage.googleapis.com')
                self.assertEqual(request.url.path, '/v1beta/models/gemini-embedding-001:batchEmbedContents')

    def test_sdk_environment_cannot_override_developer_api_destination(self):
        vertex, request = self.route({'GOOGLE_GEMINI_BASE_URL': 'https://offline.invalid'})
        self.assertFalse(vertex)
        self.assertEqual(request.url.host, 'generativelanguage.googleapis.com')
        self.assertEqual(request.url.path, '/v1beta/models/gemini-embedding-001:batchEmbedContents')
