"""Disabled-by-default ASGI adapter, outside CORS/routing. No ingress defaults."""
import asyncio
import posixpath
import re
from threading import BoundedSemaphore
import time
from uuid import uuid4

from starlette.responses import JSONResponse

from src.auth import authenticate, AuthorizationError, Capability
from src.authenticated_session_chat import AuthenticatedSessionChatService
from src.diagnostics import ChatDiagnostics, ChatDeadlineExceeded
from src.gateway_assertions import AssertionError as InvalidAssertion, _b64, PATH
from src.provider import ERROR_DETAIL
from src.session_chat import validate_chat_body


class Rejected(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__('Internal chat unavailable.')


def validate_http_configuration(application, controls):
    """No DB, key loading, resolver factory, provider calls or migrations here."""
    settings = controls.settings
    if type(settings.session_chat_http_enabled) is not bool:
        raise RuntimeError('Internal chat configuration unavailable.')
    if not settings.session_chat_http_enabled:
        return None
    pipeline = getattr(application.state, 'session_chat_pipeline', None)
    if (not all(getattr(settings, name) is True for name in ('capability_auth_enabled', 'session_chat_enabled',
            'staging_auth_enabled', 'session_admission_enabled', 'ip_admission_enabled'))
            or type(pipeline) is not AuthenticatedSessionChatService or pipeline._settings != settings
            or pipeline._chat.controls is not controls or pipeline._chat.application is not application):
        raise RuntimeError('Internal chat configuration unavailable.')
    return pipeline


class SessionChatHTTPAdapter:
    """A reserved-path adapter, NOT a FastAPI route or a fallback to /chat.

    application/state and pipeline are exclusively trusted server composition.
    No environment variable can select a resolver or inject a pipeline.
    """
    def __init__(self, app, *, application, controls, upload_timeout_seconds=5):
        if type(upload_timeout_seconds) not in (int, float) or not 0 < upload_timeout_seconds <= 5:
            raise ValueError('Invalid internal upload limit.')
        self.app, self.application, self._controls = app, application, controls
        self.upload_timeout_seconds = upload_timeout_seconds
        self.capacity = BoundedSemaphore(controls.settings.max_concurrent)

    @staticmethod
    def _reserved(path):
        if type(path) is not str:
            return False
        # Normalize only to REJECT aliases, never to authorize them.
        return posixpath.normpath('/' + path.replace('\\', '/').lstrip('/')) == PATH

    @staticmethod
    def _framing(scope, limit, *, render_transport=False):
        raw_headers = scope.get('headers', [])
        if type(raw_headers) not in (list, tuple) or len(raw_headers) > 32:
            raise Rejected(400)
        headers = []
        total = 0
        for pair in raw_headers:
            if (type(pair) not in (list, tuple) or len(pair) != 2 or any(type(v) is not bytes for v in pair)
                    ):
                raise Rejected(400)
            total += len(pair[0]) + len(pair[1])
            if (total > 8192 or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", pair[0]) is None
                    or any(c in pair[1] for c in (b'\r', b'\n', b'\0'))):
                raise Rejected(400)
            headers.append((pair[0].lower(), pair[1]))
        if sum(len(k)+len(v) for k,v in headers) > 8192:
            raise Rejected(400)
        # Render adds X-Forwarded-For for the gateway connection. Under the
        # explicitly composed Render/Vercel policy it is transport metadata,
        # discarded AFTER original header bounds/validation, never IP evidence.
        if render_transport:
            headers = [(k, v) for k, v in headers if k != b'x-forwarded-for']
        def values(name):return [v for k,v in headers if k == name]
        if values(b'origin') or any(values(k) for k in (b'x-forwarded-for', b'x-real-ip', b'cf-connecting-ip',
                                                     b'forwarded', b'x-identity-digest', b'x-visitor-ip')):
            raise Rejected(403)
        if values(b'content-type') != [b'application/json'] or values(b'content-encoding') not in ([],[b'identity']):
            raise Rejected(415)
        lengths, transfers = values(b'content-length'), values(b'transfer-encoding')
        if len(lengths)>1 or len(transfers)>1 or (lengths and transfers) or values(b'trailer'):
            raise Rejected(400)
        length = None
        if lengths:
            if len(lengths[0])>20 or re.fullmatch(rb'0|[1-9][0-9]*',lengths[0]) is None:
                raise Rejected(400)
            length = int(lengths[0])
            if length>limit:raise Rejected(413)
        if transfers and (transfers != [b'chunked'] or scope.get('http_version') != '1.1'):
            raise Rejected(400)
        sessions, assertions = values(b'x-portfolio-session'), values(b'x-portfolio-gateway-assertion')
        if len(sessions)!=1:raise Rejected(401)
        try:
            session = sessions[0].decode('ascii')
            if len(session)!=43 or len(_b64(session,32))!=32:raise InvalidAssertion()
        except (UnicodeError,InvalidAssertion):
            raise Rejected(401) from None
        if len(assertions)!=1:raise Rejected(403)
        try:
            assertion=assertions[0].decode('ascii')
        except UnicodeError:
            raise Rejected(403) from None
        if not 1<=len(assertion)<=2048 or any(c.isspace() for c in assertion):
            raise Rejected(403)
        return headers,length,assertion

    async def __call__(self, scope, receive, send):
        started = time.monotonic()
        if scope.get('type') != 'http' or not self._reserved(scope.get('path')):
            await self.app(scope,receive,send)
            return
        diagnostics=ChatDiagnostics(started,self._controls.settings.chat_deadline_seconds)
        acquired=False
        async def respond(status, body=None, extra=None):
            headers={'Cache-Control':'no-store'}
            if status==401:headers['WWW-Authenticate']='Bearer'
            if extra:
                retry=extra.get('retry-after')
                if type(retry) is str and re.fullmatch(r'[0-9]{1,5}',retry):headers['Retry-After']=retry
            response=JSONResponse(body if body is not None else {'detail':ERROR_DETAIL},status_code=status,headers=headers)
            if len(response.body)>65536:
                response=JSONResponse({'detail':ERROR_DETAIL},status_code=502,headers={'Cache-Control':'no-store'})
            if status!=504 and time.monotonic()>=diagnostics.deadline:
                response=JSONResponse({'detail':ERROR_DETAIL},status_code=504,headers={'Cache-Control':'no-store'})
            await response(scope,receive,send)
        try:
            if self._controls.settings.session_chat_http_enabled is not True:
                # Preserve the existing scoped denial for the reserved canonical
                # path while never executing a disabled operation.
                if (self._controls.settings.capability_auth_enabled and scope.get('method')=='POST'
                        and scope.get('path')==PATH):
                    authenticate(self._controls.settings,{**scope,'state':{}},required=Capability.SESSION_CHAT)
                raise Rejected(404)
            try:
                pipeline=validate_http_configuration(self.application,self._controls)
            except RuntimeError:
                raise Rejected(503) from None
            if (scope.get('path')!=PATH or scope.get('raw_path',PATH.encode())!=PATH.encode()
                    or scope.get('root_path') or scope.get('query_string')):
                raise Rejected(400)
            if scope.get('method')!='POST':raise Rejected(405)
            limit=min(self._controls.settings.max_body_bytes,8192)
            from src.production_chat import VercelGatewayIdentity
            headers,length,assertion=self._framing(scope,limit,
                render_transport=type(pipeline._resolver) is VercelGatewayIdentity)
            # Clear caller state. A principal is minted only by the shared scoped
            # authenticator, before any body upload, parsing, replay or providers.
            request={**scope,'headers':headers,'state':{'request_id':uuid4().hex}}
            principal=authenticate(self._controls.settings,request,required=Capability.SESSION_CHAT)
            if not self.capacity.acquire(blocking=False):raise Rejected(503)
            acquired=True
            diagnostics.check()
            body=bytearray()
            upload=min(self.upload_timeout_seconds,max(0.,diagnostics.deadline-time.monotonic()))
            try:
                async with asyncio.timeout(upload):
                    while True:
                        message=await receive()
                        if message['type']=='http.disconnect':
                            diagnostics.stop()
                            return
                        if message['type']!='http.request' or type(message.get('body',b'')) is not bytes:
                            raise Rejected(400)
                        part=message.get('body',b'')
                        if len(body)+len(part)>limit:raise Rejected(413)
                        body.extend(part)
                        if length is not None and len(body)>length:raise Rejected(400)
                        if not message.get('more_body',False):break
            except TimeoutError:
                raise Rejected(504 if time.monotonic()>=diagnostics.deadline else 408) from None
            if length is not None and len(body)!=length:raise Rejected(400)
            diagnostics.check()
            raw=bytes(body)
            try:
                validate_chat_body(pipeline._chat.request_model,raw)
            except (ValueError,RecursionError):
                raise Rejected(422) from None
            diagnostics.check()
            result=await pipeline.run(request,raw,assertion,principal=principal,diagnostics=diagnostics)
            if result.status==200 and (type(result.body) is not dict or set(result.body)!={'answer'}
                                       or type(result.body['answer']) is not str):
                raise Rejected(502)
            await respond(result.status,result.body if result.status==200 else None,result.headers)
        except AuthorizationError as error:
            await respond(error.status)
        except Rejected as error:
            await respond(error.status)
        except ChatDeadlineExceeded:
            await respond(504)
        except asyncio.CancelledError:
            diagnostics.stop()
            raise
        except Exception:
            await respond(500)
        finally:
            if acquired:self.capacity.release()
