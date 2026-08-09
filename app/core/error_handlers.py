from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.core.exceptions import RTASAException
from app.core.logging import logger

async def rtasa_exception_handler(request: Request, exc: RTASAException):
    logger.warning(f"[{exc.__class__.__name__}] {request.method} {request.url.path} - {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error_type": exc.__class__.__name__,
            "message": exc.message
        }
    )

async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"[UnhandledError] {request.method} {request.url.path} - {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error_type": "InternalServerError",
            "message": "An unexpected system error occurred."
        }
    )