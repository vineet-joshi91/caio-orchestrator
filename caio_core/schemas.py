from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# -------- Inbound payloads --------

class DocumentIn(BaseModel):
    filename: str
    content: str                       # base64 or plain text for MVP
    mime_type: Optional[str] = "text/plain"
    tier: Optional[str] = "demo"       # align with backend/env: demo|pro|pro_plus|premium

class BrainRequest(BaseModel):
    # 'brain' is taken from the URL path (/api/brains/{brain}/run), so it doesn't need to be in the body.
    tier: Optional[str] = None
    inputs: Dict[str, Any] = Field(default_factory=dict)

# -------- Analyze result shapes --------

class Insight(BaseModel):
    role: str
    summary: str
    recommendations: List[str] = Field(default_factory=list)

class CombinedInsights(BaseModel):
    document_filename: str
    overall_summary: str
    insights: List[Insight] = Field(default_factory=list)
    # NEW: aggregator block (compact UI-ready rollup)
    aggregate: Optional[Dict[str, Any]] = None

class AnalyzeResponse(BaseModel):
    job_id: str
    combined: CombinedInsights

# -------- (Deprecated for MVP) --------

class ExportRequest(BaseModel):
    job_id: str
    format: str  # 'pdf' or 'docx'
    # NOTE: not used at MVP; safe to remove later.

# -------- Auth & profile --------

class AuthSignup(BaseModel):
    email: str
    password: str

class AuthLogin(BaseModel):
    email: str
    password: str

class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Me(BaseModel):
    email: str
    tier: str = "demo"
    is_admin: Optional[bool] = False
    is_paid: Optional[bool] = False

# -------- Health --------

class Health(BaseModel):
    status: str = "ok"
    version: str = "0.0.1"
