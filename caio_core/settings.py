# caio_core/settings.py
from typing import List, Optional, Union, Any
import os

# Try to import the Pydantic v2 entry; fall back gently to v1 BaseSettings if needed.
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    from pydantic import field_validator
    PYDANTIC_V2 = True
except Exception:
    from pydantic import BaseSettings  # type: ignore
    PYDANTIC_V2 = False
    # provide no-op decorator fallback for field_validator on v1
    def field_validator(*args, **kwargs):
        def _d(fn):
            return fn
        return _d  # type: ignore

# Shared tiny helper to normalize a CSV or JSON-like env into a list
def _normalize_list_like(value: Union[str, List[str], None]) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        # ensure trimmed strings only
        return [str(x).strip() for x in value if str(x).strip()]
    s = str(value).strip()
    # If it looks like JSON array, try a safe parse
    if s.startswith("[") and s.endswith("]"):
        try:
            import json
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
    # Otherwise assume comma-separated
    return [part.strip() for part in s.split(",") if part.strip()]

class Settings(BaseSettings):
    # Pydantic v2 config compatibility
    if PYDANTIC_V2:
        model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    else:
        class Config:  # type: ignore
            env_file = ".env"
            extra = "ignore"

    # --- core envs (keep your existing fields here too) ----
    APP_NAME: str = "CAIO"
    VERSION: str = "0.0.1"
    DEBUG: bool = False

    # CORS envs - accept either str or list input at runtime
    CORS_ORIGINS: Optional[Union[List[str], str]] = None
    ALLOWED_ORIGINS: Optional[Union[List[str], str]] = None

    # JWT / secrets and other required fields (include ones you already use)
    JWT_SECRET: Optional[str] = None
    DATABASE_URL: Optional[str] = None
    # ... (add any other existing envs you require) ...

    # Validators (pydantic v2) or fallbacks (v1)
    @field_validator("CORS_ORIGINS", mode="before")
    @field_validator("ALLOWED_ORIGINS", mode="before")
    def _split_csv(cls, v: Any) -> List[str]:
        # This will accept: None, list, comma-separated string, or JSON-list string
        return _normalize_list_like(v)

    # Convenient property to get final allowed origins list
    @property
    def ALLOWED_ORIGINS_LIST(self) -> List[str]:
        # merge both and dedupe while preserving order
        cors = _normalize_list_like(self.CORS_ORIGINS)
        allowed = _normalize_list_like(self.ALLOWED_ORIGINS)
        out: List[str] = []
        for x in (cors + allowed):
            if x and x not in out:
                out.append(x)
        return out

# create the instance
settings = Settings()
