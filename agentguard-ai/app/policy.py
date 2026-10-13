"""Explicit, conservative demo tool authorization policy."""
ALLOWED_TOOLS = {'search_knowledge', 'get_weather', 'summarize_document'}
REVIEW_TOOLS = {'send_email', 'write_file', 'http_request'}

def tool_risk(tool: str | None) -> tuple[str, str] | None:
    if not tool:
        return None
    if tool in ALLOWED_TOOLS:
        return None
    if tool in REVIEW_TOOLS:
        return ('medium', f'Tool {tool!r} requires human approval')
    return ('high', f'Tool {tool!r} is not on the allowlist')
