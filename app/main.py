from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exceptions import RTASAException
from app.core.error_handlers import (
    rtasa_exception_handler,
    unhandled_exception_handler
)

from app.api.v1.router import api_v1_router

# Database imports
from app.db.session import engine, Base

# Import models so SQLAlchemy registers tables
from app.models.domain import EncryptedSecret, ShareRecord, User


def create_application() -> FastAPI:

    # Create database tables
    Base.metadata.create_all(bind=engine)

    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
    )

    # ------------------------------------------------------------------
    # CORS Middleware Configuration (Frontend Integration)
    # ------------------------------------------------------------------
    origins = [
        "http://localhost:3000",      # React / Next.js default dev server
        "http://localhost:5173",      # Vite default dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*"                           # Open access for local testing/Axios
    ]

    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],          # GET, POST, PUT, DELETE, OPTIONS, etc.
        allow_headers=["*"],          # Content-Type, Authorization, etc.
        expose_headers=["Content-Disposition"],  # Critical for downloading stego images via Axios
    )

    # Register Global Exception Middleware
    application.add_exception_handler(
        RTASAException,
        rtasa_exception_handler
    )

    application.add_exception_handler(
        Exception,
        unhandled_exception_handler
    )

    # Register API V1 Router
    application.include_router(
        api_v1_router,
        prefix=settings.API_V1_STR
    )

    @application.get("/health")
    def health_check():
        return {
            "status": "healthy",
            "service": settings.PROJECT_NAME
        }

    return application


app = create_application()