import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "RTASA Enterprise Platform"
    VERSION: str = "1.0.0"  # Added
    API_V1_STR: str = "/api/v1"

    # Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "ENTERPRISE_SECRET_KEY_CHANGE_IN_PRODUCTION_0987654321")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 Hours

    # Database Configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./rtasa.db")

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="ignore"
    )


settings = Settings()