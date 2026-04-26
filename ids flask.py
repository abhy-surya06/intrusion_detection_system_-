from flask import Flask, request, jsonify, render_template
import database
import detection_rules
from rate_limiter import RateLimiter

app = Flask(__name__)

# Initialize database
database.init_db()

# Create rate limiter (e.g., max 30 requests per minute, block for 2 minutes)
rate_limiter = RateLimiter(limit=30, window=60, block_time=120)

# Dummy backend response (when request is allowed)
def backend_response():
    return "Request allowed. Your request was clean."

@app.before_request
def protect():
    """Inspect every incoming request before handling."""
    ip = request.remote_addr
    method = request.method
    url = request.url
    headers = dict(request.headers)
    body = request.get_data(as_text=True) if request.data else None

    # 1. Rate limiting check
    allowed, remaining = rate_limiter.is_allowed(ip)
    if not allowed:
        database.log_request(ip, method, url, 'Rate Limit Exceeded', blocked=True, 
                             details=f"Blocked for {remaining:.0f}s")
        return jsonify({"error": "Too many requests", "retry_after": remaining}), 429

    # 2. Attack detection
    request_data = {
        'url': url,
        'headers': headers,
        'body': body
    }
    attack_type, details = detection_rules.detect_attack(request_data)

    if attack_type:
        # Block the request
        database.log_request(ip, method, url, attack_type, blocked=True, details=details)
        return jsonify({"error": "Blocked due to suspicious activity", "attack": attack_type}), 403
    else:
        # Allow the request
        database.log_request(ip, method, url, 'None', blocked=False, details='Clean')
        # Here you would normally forward to the actual backend.
        # For demo, we just return a success message.
        return backend_response()

@app.route('/dashboard')
def dashboard():
    """Render the dashboard page."""
    logs = database.get_logs(limit=100)
    stats = database.get_attack_stats()
    return render_template('dashboard.html', logs=logs, stats=stats)

@app.route('/api/logs')
def api_logs():
    """JSON endpoint for dashboard charts."""
    logs = database.get_logs(limit=100)
    return jsonify(logs)

@app.route('/api/stats')
def api_stats():
    stats = database.get_attack_stats()
    return jsonify(stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)