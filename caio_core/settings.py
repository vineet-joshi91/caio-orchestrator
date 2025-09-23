# caio_core/settings.py
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except Exception:
    from pydantic import BaseSettings  # fallback for older envs
    SettingsConfigDict = dict  # type: ignore

from pydantic import field_validator
from typing import List, Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")  # type: ignore

    # ... your existing fields ...

    CORS_ORIGINS: List[str] = []
    ALLOWED_ORIGINS: List[str] = []      # <— add this

    @field_validator("CORS_ORIGINS", "ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if not v:
            return []
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

settings = Settings()
