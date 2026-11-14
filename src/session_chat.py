"""In-process session chat only. No route or HTTP identity transport exists."""

from dataclasses import dataclass
import json
import math
import time

import anyio
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.diagnostics import ChatDiagnostics, ChatDeadlineExceeded
from src.identity import TrustedIP
from src.ip_admission import admitted_identity
from src.provider import ERROR_DETAIL
from src.reliability import ChatProtectionMiddleware
from src.auth import authenticate, Capability, AuthorizationError


@dataclass(frozen=True)
class SessionChatResult:
    status: int
    body: dict
    headers: dict


def _object(pairs):
    if len(dict(pairs)) != len(pairs):
        raise ValueError()
    return dict(pairs)


def validate_chat_body(request_model, body):
    """Shared strict parser; preserve exact wire bytes for assertion binding."""
    value = json.loads(body.decode('utf-8'), object_pairs_hook=_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    request = request_model.model_validate(value)
    request.message.encode('utf-8', errors='strict')  # Reject escaped lone surrogates too.
    return request


class SessionChatService:
    """Trusted internal caller supplies identity, body stream and gateway scope.

    Construct with the existing application, ChatControls, request model and
    shared worker. The private ASGI supervisor never dispatches the app router.
    Ordinary HTTP callers cannot invoke this service or supply TrustedIP objects.
    """
    def __init__(self, settings, controls, application, request_model, worker):
        self.settings, self.controls, self.application = settings, controls, application
        self.request_model, self.worker = request_model, worker

    async def run(self, gateway_scope, chunks, *, identity=None, principal=None, diagnostics=None):
        def reject(status, detail=ERROR_DETAIL):
            return SessionChatResult(status, {'detail': detail}, {'cache-control': 'no-store'})
        if (self.settings.session_chat_enabled is not True or self.settings.staging_auth_enabled is not True
                or self.settings.session_admission_enabled is not True or self.settings.ip_admission_enabled is not True
                or self.controls.settings != self.settings):
            return reject(503)
        if self.settings.capability_auth_enabled:
            try:
                principal = authenticate(self.settings, gateway_scope, required=Capability.SESSION_CHAT, principal=principal)
            except AuthorizationError as error:
                return reject(error.status)
        elif principal is not None:
            return reject(401)
        if diagnostics is not None:
            if (principal is None or type(diagnostics) is not ChatDiagnostics
                    or not all(type(v) in (float, int) and math.isfinite(v)
                               for v in (diagnostics.started, diagnostics.deadline))
                    or diagnostics.started > time.monotonic()
                    or diagnostics.deadline > diagnostics.started + self.settings.chat_deadline_seconds):
                return reject(503)
            try:
                diagnostics.check()
            except ChatDeadlineExceeded:
                return reject(504)
        if type(identity) is not TrustedIP:
            return reject(401)
        if gateway_scope.get('type') != 'http' or gateway_scope.get('method') != 'POST':
            return reject(405)
        headers = gateway_scope.get('headers', [])
        if gateway_scope.get('query_string') or any(k.lower() == b'origin' for k, _ in headers):
            return reject(403)
        types = [v for k, v in headers if k.lower() == b'content-type']
        encodings = [v for k, v in headers if k.lower() == b'content-encoding']
        if (len(types) != 1 or types[0].split(b';')[0].strip().lower() != b'application/json'
                or encodings not in ([], [b'identity'])):
            return reject(415)

        # Reuse ONLY the supervisor's private /chat branch, never legacy routing.
        # Drop supplied state so callers cannot inject leases or diagnostics.
        scope = {**gateway_scope, 'path': '/chat', 'raw_path': b'/chat', 'state': {}, 'app': self.application}
        stream = aiter(chunks)
        async def receive():
            try:
                chunk = await anext(stream)
            except StopAsyncIteration:
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            if type(chunk) is not bytes:
                raise ValueError('Invalid body stream.')
            return {'type': 'http.request', 'body': chunk, 'more_body': True}

        async def invoke(inner_scope, read, send):
            body = (await read())['body']  # Supervisor already bounded and buffered it.
            try:
                request = validate_chat_body(self.request_model, body)
            except (ValueError, RecursionError, ValidationError):
                await JSONResponse({'detail': 'Invalid chat request.'}, status_code=422)(inner_scope, read, send)
                return
            http_request = Request(inner_scope)
            try:
                result = await anyio.to_thread.run_sync(lambda: self.worker(
                    request, http_request, lambda: admitted_identity(self.settings, gateway_scope, identity, principal=principal)))
                response = JSONResponse(result.model_dump())
                if len(response.body) > 65536:
                    response = JSONResponse({'detail': ERROR_DETAIL}, status_code=502)
            except HTTPException as error:
                response = JSONResponse({'detail': ERROR_DETAIL}, status_code=error.status_code, headers=error.headers)
            await response(inner_scope, read, send)

        messages = []
        async def collect(message):
            messages.append(message)
        authorization = (principal, gateway_scope, Capability.SESSION_CHAT) if principal is not None else None
        await ChatProtectionMiddleware(invoke, self.controls, internal_authorization=authorization,
                                       internal_diagnostics=diagnostics, internal_session_chat=True)(scope, receive, collect)
        start = next((m for m in messages if m['type'] == 'http.response.start'), None)
        if start is None:
            return reject(503)
        content = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
        result_headers = {k.decode('latin-1'): v.decode('latin-1') for k, v in start['headers']}
        result_headers['cache-control'] = 'no-store'
        return SessionChatResult(start['status'], json.loads(content), result_headers)
