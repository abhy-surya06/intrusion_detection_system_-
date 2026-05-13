import re

# Attack patterns: (name, regex, severity)
RULES = [
    ('SQL Injection', r'(\%27)|(\')|(\-\-)|(\%23)|(#)|(union.*select)', re.IGNORECASE),
    ('XSS', r'(<script)|(javascript:)|(onerror=)|(onload=)', re.IGNORECASE),
    ('Path Traversal', r'(\.\./|\.\.\\)|(etc/passwd)', re.IGNORECASE),
    ('Command Injection', r'(\||\&|\;|\$\(.*\)|\`.*\`)', re.IGNORECASE),
]

def detect_attack(request_data):
    """
    request_data: dict with keys 'url', 'headers', 'body' (body can be string or None)
    Returns: (attack_type, details) or (None, None) if clean
    """
    # Combine all data into one string for inspection
    text_to_inspect = request_data.get('url', '')
    # Add headers
    for key, value in request_data.get('headers', {}).items():
        text_to_inspect += f" {key}: {value}"
    # Add body
    if request_data.get('body'):
        text_to_inspect += f" {request_data['body']}"

    for attack_name, pattern, flags in RULES:
        if re.search(pattern, text_to_inspect, flags):
            # Return first matched attack
            return attack_name, text_to_inspect[:200]  # details snippet
    return None, None
