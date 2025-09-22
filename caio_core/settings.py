
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "CAIO Orchestrator"
    VERSION: str = "4.1.0-mvp"
    CORS_ORIGINS: str = "*"  # comma-separated or '*'
    JWT_SECRET: str = "CHANGE_ME"
    JWT_EXPIRE_MINUTES: int = 120

    ENGINE_PROVIDER: str = "openai"  # openai|local
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    # Storage (MVP can be local)
    STORAGE_DIR: str = "storage"

    class Config:
        env_file = ".env"

settings = Settings()
