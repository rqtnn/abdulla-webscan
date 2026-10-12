"""Rqtn Tool explicit one-origin session for built-in HTTP checks only."""
from scope import origin


class Session:
    def __init__(self, url, cookie_file):
        self.allowed = origin(url)
        if cookie_file.stat().st_size > 16384:
            raise ValueError('Cookie file exceeds 16 KiB')
        value = cookie_file.read_text(encoding='utf-8').strip()
        if not value or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError('Cookie file must contain one nonempty ASCII Cookie header value')
        self.cookie = value

    def headers_for(self, url):
        return {'Cookie': self.cookie} if origin(url) == self.allowed else {}
