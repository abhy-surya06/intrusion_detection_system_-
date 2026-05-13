import time

class RateLimiter:
    def __init__(self, limit=30, window=60, block_time=120):
        """
        limit: max requests per window seconds
        window: time window in seconds
        block_time: seconds to block if limit exceeded
        """
        self.limit = limit
        self.window = window
        self.block_time = block_time
        self.requests = {}  # ip -> list of timestamps
        self.blocked_until = {}  # ip -> unblock timestamp

    def is_allowed(self, ip):
        now = time.time()
        # Check if IP is currently blocked
        if ip in self.blocked_until and now < self.blocked_until[ip]:
            return False, self.blocked_until[ip] - now

        # Clean old entries
        if ip in self.requests:
            self.requests[ip] = [t for t in self.requests[ip] if now - t <= self.window]
        else:
            self.requests[ip] = []

        # Check limit
        if len(self.requests[ip]) >= self.limit:
            # Block this IP
            self.blocked_until[ip] = now + self.block_time
            return False, self.block_time
        else:
            self.requests[ip].append(now)
            return True, None
