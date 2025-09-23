# caio_core/settings.py
from typing import List, Optional, Union
import json
from pydantic_settings import BaseSettings, SettingsConfigDict  # pydantic v2

def _as_list(value: Optional[Union[str, List[str]]]) -> List[str]:
    """Accepts: None | 'a,b' | '["a","b"]' | ['a','b'] -> ['a','b'] (trimmed)."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    s = str(value).strip()
    if not s:
        return []
    if s.startswith("[") and s.endswith("]"):
        try:
            arr = json.loads(s)
            if isinstance(arr, list):
                return [str(x).strip() for x in arr if str(x).strip()]
        except Exception:
            pass
    return [p.strip() for p in s.split(",") if p.strip()]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- your existing settings (keep adding as needed) ---
    APP_NAME: str = "CAIO"
    VERSION: str = "0.0.1"
    DEBUG: bool = False

    # Raw env values; accept either CSV string or JSON array string
    CORS_ORIGINS: Optional[Union[str, List[str]]] = None
    ALLOWED_ORIGINS: Optional[Union[str, List[str]]] = None

    JWT_SECRET: Optional[str] = None
    DATABASE_URL: Optional[str] = None
    # ... add the other envs you already use ...

    # Computed list, always safe
    @property
    def ALLOWED_ORIGINS_LIST(self) -> List[str]:
        merged: List[str] = []
        for item in _as_list(self.CORS_ORIGINS) + _as_list(self.ALLOWED_ORIGINS):
            if item and item not in merged:
                merged.append(item)
        return merged

settings = Settings()
