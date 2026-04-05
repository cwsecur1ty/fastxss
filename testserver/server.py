"""
Intentionally vulnerable XSS test server for fastxss testing.
DO NOT expose this to the internet.

Usage: python server.py
Then scan: fastxss --target http://localhost:9999
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import html
import json

PORT = 9999

PAGES = {
    "/": """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Test App</title></head>
<body>
<h1>FastXSS Test Server</h1>
<ul>
    <li><a href="/search?q=test">Search (Reflected - Plain)</a></li>
    <li><a href="/profile?name=John">Profile (Reflected - Attribute)</a></li>
    <li><a href="/redirect?url=https://example.com">Redirect (Reflected - href)</a></li>
    <li><a href="/debug?code=console.log(1)">Debug (Reflected - Script Block)</a></li>
    <li><a href="/comment?text=hello">Comment (Reflected - HTML Comment)</a></li>
    <li><a href="/login">Login Form (POST Reflected)</a></li>
    <li><a href="/guestbook">Guestbook (Stored XSS)</a></li>
    <li><a href="/dom">DOM XSS (hash-based)</a></li>
    <li><a href="/filtered?q=test">Filtered Search (partial filter)</a></li>
    <li><a href="/header-reflect">Header Reflection (User-Agent)</a></li>
    <li><a href="/json-inject?callback=handleData">JSONP Endpoint</a></li>
    <li><a href="/multi?a=1&b=2&c=3">Multi-Param (multiple injection points)</a></li>
</ul>
</body>
</html>
""",
}

GUESTBOOK_ENTRIES = []


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress request logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Flatten params (take first value)
        p = {k: v[0] for k, v in params.items()}

        if path == "/":
            self.respond(200, PAGES["/"])

        elif path == "/search":
            # REFLECTED XSS - Plain text context, NO sanitization
            q = p.get("q", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: {q}</p>
<p>No results found for <b>{q}</b></p>
<form action="/search" method="GET">
    <input type="text" name="q" value="{q}" placeholder="Search...">
    <button type="submit">Search</button>
</form>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/profile":
            # REFLECTED XSS - Attribute context (inside value="...")
            name = p.get("name", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Profile</title></head>
<body>
<h1>User Profile</h1>
<form action="/profile" method="GET">
    <label>Name:</label>
    <input type="text" name="name" value="{name}">
    <button type="submit">Update</button>
</form>
<div id="greeting">Hello, {name}!</div>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/redirect":
            # REFLECTED XSS - href attribute context
            url = p.get("url", "#")
            body = f"""
<!DOCTYPE html>
<html><head><title>Redirect</title></head>
<body>
<h1>Redirect</h1>
<p>Click to continue:</p>
<a href="{url}">Continue to destination</a>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/debug":
            # REFLECTED XSS - Inside <script> block
            code = p.get("code", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Debug Console</title></head>
<body>
<h1>Debug</h1>
<pre id="output"></pre>
<script>
var userCode = "{code}";
document.getElementById('output').textContent = "Executing: " + userCode;
</script>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/comment":
            # REFLECTED XSS - Inside HTML comment
            text = p.get("text", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Comments</title></head>
<body>
<!-- User comment: {text} -->
<h1>Comments</h1>
<p>Your comment has been noted.</p>
<form action="/comment" method="GET">
    <textarea name="text" placeholder="Write a comment...">{text}</textarea>
    <button type="submit">Submit</button>
</form>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/login":
            # POST form for reflected XSS testing
            body = """
<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h1>Login</h1>
<form action="/login" method="POST">
    <label>Email:</label>
    <input type="email" name="email" placeholder="you@example.com"><br>
    <label>Password:</label>
    <input type="password" name="password"><br>
    <button type="submit">Login</button>
</form>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/guestbook":
            # STORED XSS - Entries persist in memory
            entries_html = ""
            for entry in GUESTBOOK_ENTRIES:
                # No sanitization on display!
                entries_html += f'<div class="entry"><b>{entry["name"]}</b>: {entry["message"]}</div>\n'

            body = f"""
<!DOCTYPE html>
<html><head><title>Guestbook</title></head>
<body>
<h1>Guestbook</h1>
<form action="/guestbook" method="POST">
    <input type="text" name="name" placeholder="Your name"><br>
    <textarea name="message" placeholder="Your message"></textarea><br>
    <button type="submit">Sign Guestbook</button>
</form>
<h2>Entries:</h2>
{entries_html}
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/dom":
            # DOM XSS - reads from location.hash and writes to innerHTML
            body = """
<!DOCTYPE html>
<html><head><title>DOM XSS</title></head>
<body>
<h1>Welcome</h1>
<div id="content"></div>
<script>
var hash = decodeURIComponent(window.location.hash.substring(1));
if (hash) {
    document.getElementById('content').innerHTML = 'You selected: ' + hash;
}
var params = new URLSearchParams(window.location.search);
var msg = params.get('msg');
if (msg) {
    document.getElementById('content').innerHTML = msg;
}
</script>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/filtered":
            # PARTIAL FILTER - removes <script> but not event handlers
            q = p.get("q", "")
            filtered = q.replace("<script>", "").replace("</script>", "").replace("<SCRIPT>", "").replace("</SCRIPT>", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Filtered Search</title></head>
<body>
<h1>Filtered Search</h1>
<p>Results for: {filtered}</p>
<form action="/filtered" method="GET">
    <input type="text" name="q" value="{filtered}">
    <button type="submit">Search</button>
</form>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/header-reflect":
            # Reflects User-Agent header
            ua = self.headers.get("User-Agent", "unknown")
            referer = self.headers.get("Referer", "none")
            body = f"""
<!DOCTYPE html>
<html><head><title>Debug Info</title></head>
<body>
<h1>Request Debug Info</h1>
<p>Your browser: {ua}</p>
<p>Referer: {referer}</p>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/json-inject":
            # JSONP-style callback injection
            callback = p.get("callback", "handleData")
            data = json.dumps({"status": "ok", "data": []})
            body = f"{callback}({data})"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body.encode())

        elif path == "/multi":
            # Multiple reflecting parameters
            a = p.get("a", "")
            b = p.get("b", "")
            c = p.get("c", "")
            body = f"""
<!DOCTYPE html>
<html><head><title>Multi Param</title></head>
<body>
<h1>Multi Parameter Test</h1>
<div>Param a: {a}</div>
<div>Param b = <input value="{b}"></div>
<!-- Param c: {c} -->
<script>var config = {{user: "{a}"}};</script>
<a href="/">Back</a>
</body></html>"""
            self.respond(200, body)

        elif path == "/sitemap.xml":
            sitemap = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://localhost:9999/search?q=test</loc></url>
    <url><loc>http://localhost:9999/profile?name=test</loc></url>
    <url><loc>http://localhost:9999/guestbook</loc></url>
    <url><loc>http://localhost:9999/dom</loc></url>
    <url><loc>http://localhost:9999/filtered?q=test</loc></url>
    <url><loc>http://localhost:9999/header-reflect</loc></url>
    <url><loc>http://localhost:9999/multi?a=1&b=2&c=3</loc></url>
</urlset>"""
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(sitemap.encode())

        else:
            self.respond(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode()
        params = parse_qs(post_data, keep_blank_values=True)
        p = {k: v[0] for k, v in params.items()}

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/login":
            email = p.get("email", "")
            # REFLECTED XSS via POST - reflects email in response
            body = f"""
<!DOCTYPE html>
<html><head><title>Login Failed</title></head>
<body>
<h1>Login Failed</h1>
<p>No account found for: {email}</p>
<p>Please <a href="/login">try again</a>.</p>
</body></html>"""
            self.respond(200, body)

        elif path == "/guestbook":
            name = p.get("name", "Anonymous")
            message = p.get("message", "")
            GUESTBOOK_ENTRIES.append({"name": name, "message": message})

            self.send_response(302)
            self.send_header("Location", "/guestbook")
            self.end_headers()

        else:
            self.respond(404, "<h1>404</h1>")

    def respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), VulnHandler)
    print(f"Vulnerable test server running on http://localhost:{PORT}")
    print(f"Scan with: fastxss --target http://localhost:{PORT}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
