from fastapi import APIRouter
from app.api.v1.endpoints import secrets, users
from app.api.v1.endpoints.secrets import router as secrets_router

api_v1_router = APIRouter()
api_v1_router.include_router(secrets_router)

api_v1_router.include_router(secrets.router, prefix="/secrets", tags=["Secrets"])
api_v1_router.include_router(users.router, prefix="/users", tags=["Users"])