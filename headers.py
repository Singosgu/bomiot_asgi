from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class ServerHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Server"] = "Bomiot"
        return response