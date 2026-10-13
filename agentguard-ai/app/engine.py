"""Explainable heuristic scanner. Not a comprehensive prompt-injection defense."""
import re
import uuid
from .models import ScanRequest, ScanResult, Finding
from .policy import tool_risk

PATTERNS = [
    ('instruction_override', 'high', r'\b(ignore|disregard|override)\b.{0,65}\b(previous|prior|system|developer|instructions|rules)\b', 'Attempts to override higher-priority instructions'),
    ('role_spoofing', 'high', r'(?i)(\[\s*im_start\s*\]\s*system|<\|im_start\|>\s*system|\bSYSTEM\s*:\s*you\s+(must|are))', 'Possible forged system message'),
    ('exfiltration', 'high', r'\b(send|post|upload|exfiltrate|forward)\b.{0,90}\b(secret|password|api[_ -]?key|token|credentials)\b', 'Possible request to disclose secrets'),
    ('sensitive_data', 'medium', r'\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b', 'Potential credential detected'),
    ('unsafe_command', 'medium', r'\b(?:rm\s+-rf\s+/|del\s+/[sfq]|format\s+[a-z]:)\b', 'Potentially destructive shell command'),
]

EMAIL = re.compile(r'(?<![\w.])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.])')

def _mask(text: str) -> str:
    """Avoid echoing possible credentials or emails in scan results."""
    text = EMAIL.sub('[EMAIL REDACTED]', text)
    text = re.sub(r'sk-[A-Za-z0-9_-]{8,}', '[KEY REDACTED]', text)
    text = re.sub(r'AKIA[0-9A-Z]{16}', '[KEY REDACTED]', text)
    return text[:120]

def scan(request: ScanRequest) -> ScanResult:
    findings: list[Finding] = []
    for category, severity, pattern, explanation in PATTERNS:
        match = re.search(pattern, request.text, re.IGNORECASE | re.DOTALL)
        if match:
            findings.append(Finding(category=category, severity=severity, explanation=explanation, evidence=_mask(match.group(0))))
    if EMAIL.search(request.text):
        findings.append(Finding(category='personal_data', severity='low', explanation='Email address found; check sharing permissions', evidence='[EMAIL REDACTED]'))
    tool = tool_risk(request.requested_tool)
    if tool:
        severity, explanation = tool
        findings.append(Finding(category='tool_permission', severity=severity, explanation=explanation, evidence='[TOOL POLICY]'))
    weights = {'low': 10, 'medium': 35, 'high': 70}
    score = min(100, sum(weights[f.severity] for f in findings))
    decision = 'block' if score >= 70 else 'review' if score >= 30 else 'allow'
    return ScanResult(decision=decision, risk_score=score, findings=findings, requested_tool=request.requested_tool, source=request.source, scan_id=str(uuid.uuid4()))
