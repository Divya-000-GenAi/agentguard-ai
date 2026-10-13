from typing import Literal
from pydantic import BaseModel, Field

Source = Literal['user', 'retrieved_document', 'tool_response']

class ScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50000)
    source: Source = 'user'
    requested_tool: str | None = None
    tool_arguments: dict[str, str] = Field(default_factory=dict)

class Finding(BaseModel):
    category: str
    severity: Literal['low', 'medium', 'high']
    explanation: str
    evidence: str

class ScanResult(BaseModel):
    decision: Literal['allow', 'review', 'block']
    risk_score: int
    findings: list[Finding]
    requested_tool: str | None = None
    source: Source
    scan_id: str

class BatchRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)
