import time
import logging
from flask import Flask, request, Response

app = Flask(__name__)
# Suppress flask logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/')
def index():
    return """
    <html>
        <body>
            <h1>Test Target App</h1>
            <a href="/xss">XSS Test</a>
            <a href="/sqli?id=1">SQLi Test</a>
            <a href="/malware">Malware Test</a>
        </body>
    </html>
    """

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    # Reflected XSS
    name = request.args.get('name', 'Guest')
    if request.method == 'POST':
        name = request.form.get('name', 'Guest')
    return f"""
    <html>
        <body>
            <h1>Hello, {name}</h1>
            <form method="POST" action="/xss">
                <input type="text" name="name" />
                <input type="submit" />
            </form>
        </body>
    </html>
    """

@app.route('/sqli')
def sqli():
    # Simulate time-based SQLi
    # e.g., if payload contains SLEEP(5)
    id_param = request.args.get('id', '1')
    
    if 'SLEEP(' in id_param.upper() or 'PG_SLEEP(' in id_param.upper():
        time.sleep(5.0)
    else:
        # normal response time (simulated baseline ~ 0.1s)
        time.sleep(0.1)
        
    return f"<html><body>Product ID: {id_param}</body></html>"

@app.route('/malware')
def malware():
    # Simulate malware content for YARA and VirusScanner
    return """
    <html>
        <body>
            <h1>Free Downloads</h1>
            <!-- YARA WebMiner_Coinhive match -->
            <script src="https://cnhv.co/coinhive.min.js"></script>
            
            <!-- VirusScanner malicious domain check -->
            <script src="http://evil.com/bad.js"></script>
            
            <!-- YARA Hidden_Iframe match -->
            <iframe src="http://example.com" style="display:none"></iframe>
            
            <!-- PE Test - provide a link to a dummy exe -->
            <a href="/dummy.exe">Download Game</a>
        </body>
    </html>
    """

@app.route('/dummy.exe')
def dummy_exe():
    # Just return the EICAR string to trigger YARA EICAR_Test_File
    # though it's technically not a PE, EICAR rule just checks at offset 0
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    return Response(eicar, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(port=5001, debug=False)
