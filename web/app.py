"""
Flask Web Application — WebSecScanner Dashboard
Provides a web interface for launching scans, viewing results,
and downloading reports.
"""
import os
import sys
import json
import logging
import threading
import time
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify, send_file,
    redirect, url_for, Response, session, flash
)
from flask_socketio import SocketIO, emit
from web import database
from functools import wraps

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner import Scanner
from scanner.reporter import ReportGenerator
from scanner.models import ScanResult, ScanStatus
from scanner.file_scanner import FileScanner
from config import WebConfig, ScannerConfig, MLConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "static"))
app.config["SECRET_KEY"] = WebConfig.SECRET_KEY
socketio = SocketIO(app, async_mode="threading")

# In-memory storage for scan results and progress
active_scans = {}       # scan_id -> {"scanner": Scanner, "thread": Thread, "result": ScanResult}
scan_history = []       # List of completed ScanResult.to_dict()
file_scan_history = []  # List of file scan results
report_generator = ReportGenerator()
file_scanner = FileScanner()

# Upload directory
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max


@app.route("/")
def index():
    """Landing page with tool selection."""
    return render_template("index.html")


@app.route("/pricing")
def pricing_page():
    """Pricing plans page."""
    return render_template("pricing.html")


@app.route("/web-scanner")
def web_scanner_page():
    """Web vulnerability scanner page."""
    return render_template("web_scanner.html", scan_history=scan_history[-10:])


@app.route("/start-scan", methods=["POST"])
def start_scan():
    """Start a new scan in a background thread."""
    target_url = request.form.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400
    
    # Ensure URL has a scheme
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    try:
        max_depth = int(request.form.get("max_depth", 3))
    except (ValueError, TypeError):
        max_depth = 3
        
    try:
        max_pages = int(request.form.get("max_pages", 50))
    except (ValueError, TypeError):
        max_pages = 50
        
    try:
        request_delay = float(request.form.get("request_delay", 0.3))
    except (ValueError, TypeError):
        request_delay = 0.3
    enable_ml = request.form.get("enable_ml") == "on"
    enable_vt = request.form.get("enable_vt") == "on"
    enable_miner_scan = request.form.get("enable_miner_scan") == "on"
    enable_subdomain_enum = request.form.get("enable_subdomain_enum") == "on"
    enable_rate_limit = request.form.get("enable_rate_limit") == "on"
    enable_virus = True
    
    auth_cookies = None
    cookies_str = request.form.get("auth_cookies", "").strip()
    if cookies_str:
        try:
            auth_cookies = json.loads(cookies_str)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format for High Privilege Cookies"}), 400

    scanner = Scanner(
        target_url=target_url,
        max_depth=max_depth,
        max_pages=max_pages,
        request_delay=request_delay,
        auth_cookies=auth_cookies,
        enable_ml=enable_ml,
        enable_virus_scan=enable_virus,
        enable_vt=enable_vt,
        enable_miner_scan=enable_miner_scan,
        enable_subdomain_enum=enable_subdomain_enum,
        enable_rate_limit=enable_rate_limit,
    )

    user_id = session.get('user', {}).get('id') if 'user' in session else None
    
    is_premium_user = False
    if 'user' in session and session['user'].get('plan') == 'Premium':
        is_premium_user = True

    scan_data = {
        "scanner": scanner,
        "result": None,
        "progress": scanner.progress,
        "start_time": datetime.now().isoformat(),
        "user_id": user_id,
        "type": "web"
    }
    active_scans[scanner.scan_id] = scan_data

    def run_scan():
        # Start a background emitter task
        def emit_progress():
            while scanner.progress.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                socketio.emit(f'scan_progress_{scanner.scan_id}', scanner.progress.to_dict())
                socketio.sleep(1)
            # Emit final status
            final_data = scanner.progress.to_dict()
            if scan_data.get("result"):
                final_data["summary"] = scan_data["result"].severity_summary
            socketio.emit(f'scan_progress_{scanner.scan_id}', final_data)
            
        socketio.start_background_task(emit_progress)
        
        try:
            result = scanner.scan()
            scan_data["result"] = result
            # Generate reports
            try:
                reports = report_generator.generate_all(result, is_premium=is_premium_user)
                scan_data["reports"] = reports
            except Exception as e:
                logger.error(f"Report generation failed: {e}")
                scan_data["reports"] = {}
            # Add to history
            scan_history.append({
                **result.to_dict(),
                "reports": scan_data.get("reports", {}),
                "user_id": scan_data["user_id"],
                "type": "web"
            })
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            scanner.progress.status = ScanStatus.FAILED
            scanner.progress.errors.append(str(e))

    thread = socketio.start_background_task(run_scan)
    scan_data["thread"] = thread

    return jsonify({"scan_id": scanner.scan_id, "redirect": f"/scan/{scanner.scan_id}"})


@app.route("/api/interactive-login", methods=["POST"])
def interactive_login():
    """Launch a visible Chromium browser for the user to log in."""
    data = request.json or {}
    login_url = data.get("login_url")
    
    if not login_url:
        return jsonify({"error": "login_url is required"}), 400
        
    # Ensure URL has a scheme (default to https:// if missing)
    if not login_url.startswith("http://") and not login_url.startswith("https://"):
        login_url = "https://" + login_url
        
    try:
        from scanner.interactive_login import launch_interactive_browser
        
        # Run the interactive browser function (now synchronous)
        # This will block until the user closes the browser
        cookies = launch_interactive_browser(login_url)
        
        if not cookies:
            return jsonify({"error": "No cookies captured. Did you close the window too early?"}), 400
            
        return jsonify({"cookies": cookies})
    except Exception as e:
        logger.error(f"Interactive login API error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/scan/<scan_id>")
def scan_page(scan_id):
    """Scan progress and results page."""
    if scan_id not in active_scans:
        return render_template("error.html", message="Scan not found"), 404
    
    scan_data = active_scans[scan_id]
    scanner = scan_data["scanner"]
    
    return render_template("scanning.html",
                           scan_id=scan_id,
                           target_url=scanner.target_url,
                           enable_ml=scanner.enable_ml,
                           enable_virus=scanner.enable_virus_scan)


@app.route("/api/scan-progress/<scan_id>")
def scan_progress(scan_id):
    """API endpoint for polling scan progress."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = active_scans[scan_id]
    scanner = scan_data["scanner"]
    progress = scanner.progress
    result = scan_data.get("result")

    response = {
        "status": progress.status.value,
        "current_action": progress.current_action,
        "crawled_urls": progress.crawled_urls,
        "total_urls": progress.total_urls,
        "tested_forms": progress.tested_forms,
        "total_forms": progress.total_forms,
        "total_payloads_sent": progress.total_payloads_sent,
        "findings_count": progress.findings_count if result is None else len(result.findings) if result else 0,
        "progress_percent": progress.progress_percent,
        "elapsed_seconds": progress.elapsed_seconds,
        "errors": progress.errors[-5:],  # Last 5 errors
    }

    if result:
        response["completed"] = True
        response["summary"] = result.severity_summary
        response["total_findings"] = len(result.findings)
        response["pages_crawled"] = result.pages_crawled
        response["forms_found"] = result.forms_found
        response["scan_duration"] = result.scan_duration_seconds
        response["reports"] = scan_data.get("reports", {})

    return jsonify(response)


@app.route("/results/<scan_id>")
def results_page(scan_id):
    """Results dashboard for a completed scan."""
    if scan_id not in active_scans:
        return render_template("error.html", message="Scan not found"), 404

    scan_data = active_scans[scan_id]
    result = scan_data.get("result")
    
    if not result:
        return redirect(url_for("scan_page", scan_id=scan_id))

    findings_data = [f.to_dict() for f in result.findings]
    reports = scan_data.get("reports", {})

    import urllib.parse
    domain = urllib.parse.urlparse(result.target_url).netloc.replace(":", "_") if result else "domain"

    return render_template("results.html",
                           scan_id=scan_id,
                           result=result,
                           findings=findings_data,
                           reports=reports,
                           domain=domain)


@app.route("/download/<scan_id>/<report_format>")
def download_report(scan_id, report_format):
    """Download a scan report in the specified format."""
    if scan_id not in active_scans:
        return "Scan not found", 404

    scan_data = active_scans[scan_id]
    reports = scan_data.get("reports", {})

    if report_format not in reports:
        return "Report format not available", 404

    filepath = reports[report_format]
    if not os.path.exists(filepath):
        return "Report file not found", 404

    mime_types = {
        "html": "text/html",
        "csv": "text/csv",
        "json": "application/json",
    }

    import urllib.parse
    target_url = scan_data.get("result").target_url if scan_data.get("result") else "report"
    domain = urllib.parse.urlparse(target_url).netloc.replace(":", "_") or "report"

    return send_file(
        filepath,
        mimetype=mime_types.get(report_format, "application/octet-stream"),
        as_attachment=True,
        download_name=f"scan_{domain}.{report_format}",
    )


@app.route("/api/findings/<scan_id>")
def api_findings(scan_id):
    """API: Get all findings as JSON."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    result = active_scans[scan_id].get("result")
    if not result:
        return jsonify({"error": "Scan not completed"}), 400

    return jsonify({"findings": [f.to_dict() for f in result.findings]})


# === File Scanner Routes ===

@app.route("/file-scanner")
def file_scanner_page():
    """File virus scanner page with drag-and-drop upload."""
    return render_template("file_scanner.html", scan_history=file_scan_history[-20:])


active_file_scans = {}  # scan_id -> {"progress": dict, "results": list, "thread": Thread}

@app.route("/api/scan-file", methods=["POST"])
def api_scan_file():
    """Legacy endpoint - redirects to new start-file-scan logic internally or just fails gracefully"""
    return jsonify({"error": "Deprecated. Use /start-file-scan"}), 400

@app.route("/start-file-scan", methods=["POST"])
def start_file_scan():
    """Start a new file scan in a background thread."""
    files = request.files.getlist("file")
    if not files or all(f.filename == "" for f in files):
        # Fallback if dropzone sends 'files'
        files = request.files.getlist("files")
    
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files provided"}), 400

    # Premium check for multiple files
    if len(files) > 1:
        user = session.get('user')
        if not user or user.get('plan') != 'Premium':
            return jsonify({"error": "Scanning multiple files simultaneously requires a Premium subscription."}), 403

    import uuid
    scan_id = uuid.uuid4().hex[:8]
    enable_ml = request.form.get("enable_ml") == "on" or request.form.get("enable_ml") == "true"
    enable_vt = request.form.get("enable_vt") == "on" or request.form.get("enable_vt") == "true"
    
    # Save files to temp directory
    saved_files = []
    for uploaded in files:
        if uploaded.filename == "":
            continue
        safe_name = f"{uuid.uuid4().hex[:8]}_{uploaded.filename}"
        filepath = os.path.join(UPLOAD_DIR, safe_name)
        uploaded.save(filepath)
        saved_files.append((uploaded.filename, filepath))

    user_id = session.get('user', {}).get('id') if 'user' in session else None

    scan_data = {
        "progress": {
            "status": "Initializing",
            "current_action": "Preparing files",
            "files_scanned": 0,
            "total_files": len(saved_files),
            "threats_found": 0,
            "progress_percent": 0,
            "completed": False,
            "errors": [],
            "start_time": time.time()
        },
        "results": [],
        "user_id": user_id,
        "type": "file_batch"
    }
    active_file_scans[scan_id] = scan_data

    def run_file_scan():
        def emit_progress():
            while not scan_data["progress"]["completed"]:
                socketio.emit(f'file_scan_progress_{scan_id}', scan_data["progress"])
                socketio.sleep(1)
            # Add summary for frontend
            scan_data["progress"]["summary"] = {
                "Files": scan_data["progress"]["total_files"],
                "Threats": scan_data["progress"]["threats_found"]
            }
            socketio.emit(f'file_scan_progress_{scan_id}', scan_data["progress"])

        socketio.start_background_task(emit_progress)

        try:
            scan_data["progress"]["status"] = "Scanning"
            for i, (orig_name, filepath) in enumerate(saved_files):
                scan_data["progress"]["current_action"] = f"Scanning {orig_name}..."
                try:
                    result = file_scanner.scan_file(filepath, enable_vt=enable_vt, enable_ml=enable_ml)
                    result_dict = result.to_dict()
                    result_dict["original_filename"] = orig_name
                    try:
                        reports = report_generator.generate_file_all(result_dict)
                        result_dict["reports"] = reports
                    except Exception as e:
                        logger.error(f"File report generation failed: {e}")
                        result_dict["reports"] = {}
                    scan_data["results"].append(result_dict)
                    scan_data["progress"]["threats_found"] += result_dict.get("threat_count", 0)
                except Exception as e:
                    logger.error(f"Error scanning {orig_name}: {e}")
                    scan_data["progress"]["errors"].append(f"Failed to scan {orig_name}: {e}")
                finally:
                    try:
                        if os.path.exists(filepath):
                            os.remove(filepath)
                    except Exception:
                        pass
                
                scan_data["progress"]["files_scanned"] = i + 1
                scan_data["progress"]["progress_percent"] = int(((i + 1) / len(saved_files)) * 100)

            scan_data["progress"]["status"] = "Completed"
            scan_data["progress"]["current_action"] = "Finished"
            scan_data["progress"]["completed"] = True
            
            # Save to history
            file_scan_history.append({
                "scan_id": scan_id,
                "user_id": user_id,
                "timestamp": datetime.now().isoformat(),
                "file_count": len(saved_files),
                "total_threats": scan_data["progress"]["threats_found"],
                "results": scan_data["results"],
                "type": "file_batch"
            })
            
        except Exception as e:
            logger.error(f"File batch scan failed: {e}", exc_info=True)
            scan_data["progress"]["status"] = "Failed"
            scan_data["progress"]["errors"].append(str(e))
            scan_data["progress"]["completed"] = True

    thread = socketio.start_background_task(run_file_scan)
    scan_data["thread"] = thread

    return jsonify({"scan_id": scan_id, "redirect": f"/file-scan/{scan_id}"})


@app.route("/file-scan/<scan_id>")
def file_scan_page(scan_id):
    """File scanning progress page."""
    if scan_id not in active_file_scans:
        return render_template("error.html", message="Scan not found"), 404
    
    scan_data = active_file_scans[scan_id]
    return render_template("file_scanning.html",
                           scan_id=scan_id,
                           total_files=scan_data["progress"]["total_files"])


@app.route("/api/file-scan-progress/<scan_id>")
def file_scan_progress(scan_id):
    """API endpoint for polling file scan progress."""
    if scan_id not in active_file_scans:
        return jsonify({"error": "Scan not found"}), 404

    progress = active_file_scans[scan_id]["progress"]
    elapsed = time.time() - progress["start_time"]
    
    response = {
        "status": progress["status"],
        "current_action": progress["current_action"],
        "files_scanned": progress["files_scanned"],
        "total_files": progress["total_files"],
        "threats_found": progress["threats_found"],
        "progress_percent": progress["progress_percent"],
        "elapsed_seconds": elapsed,
        "completed": progress["completed"],
        "errors": progress["errors"][-5:],
    }
    
    if progress["completed"]:
        response["summary"] = {"Files": progress["total_files"], "Threats": progress["threats_found"]}
        
    return jsonify(response)


@app.route("/file-results/<scan_id>")
def file_results_page(scan_id):
    """Results dashboard for a completed file scan."""
    if scan_id not in active_file_scans:
        return render_template("error.html", message="Scan not found"), 404

    scan_data = active_file_scans[scan_id]
    if not scan_data["progress"]["completed"]:
        return redirect(url_for("file_scan_page", scan_id=scan_id))

    return render_template("file_results.html",
                           scan_id=scan_id,
                           results=scan_data["results"],
                           is_premium=(session.get('user', {}).get('plan') == 'Premium'))

@app.route("/file-result/<scan_id>/<int:file_index>")
def single_file_result_page(scan_id, file_index):
    """View a single file's result from a batch scan."""
    if scan_id not in active_file_scans:
        return render_template("error.html", message="Scan not found"), 404

    scan_data = active_file_scans[scan_id]
    if not scan_data["progress"]["completed"]:
        return redirect(url_for("file_scan_page", scan_id=scan_id))
        
    if file_index < 0 or file_index >= len(scan_data["results"]):
        return render_template("error.html", message="File result not found"), 404

    # Pass only the specific result as a list of 1 to trigger Option A in the template
    return render_template("file_results.html",
                           scan_id=scan_id,
                           results=[scan_data["results"][file_index]],
                           file_index=file_index,
                           is_premium=(session.get('user', {}).get('plan') == 'Premium'))

@app.route("/download-file-report/<scan_id>")
def download_file_report(scan_id):
    """Download the generated HTML report for file scans."""
    if scan_id not in active_file_scans:
        return "Scan not found", 404
    
    scan_data = active_file_scans[scan_id]
    file_index = request.args.get('file_index', type=int)
    
    # If no file_index is provided but there is only 1 file in the results, default to index 0
    if file_index is None and len(scan_data["results"]) == 1:
        file_index = 0
        
    if file_index is not None and 0 <= file_index < len(scan_data["results"]):
        result = scan_data["results"][file_index]
        reports = result.get("reports", {})
        if "html" in reports and os.path.exists(reports["html"]):
            import urllib.parse
            dl_name = f"scan_{urllib.parse.quote(result.get('original_filename', 'unknown')).replace('%', '_')}.html"
            return send_file(
                reports["html"],
                mimetype="text/html",
                as_attachment=True,
                download_name=dl_name
            )
        else:
            return "Report not generated properly. Please scan again.", 404
    else:
        return "Batch reporting not supported yet.", 404


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login_page', next=request.url))
            
        device_id = session.get('device_id')
        device_token = session.get('device_token')
        
        if not device_id or not device_token or not database.validate_device_session(device_id, device_token):
            session.clear()
            flash('Your session has expired or you were logged out from another device.', 'error')
            return redirect(url_for('login_page'))
            
        return f(*args, **kwargs)
    return decorated_function

# === Authentication Routes ===

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("register_page"))
            
        success = database.create_user(username, email, password)
        if success:
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login_page"))
        else:
            flash("Username or Email already exists.", "error")
            return redirect(url_for("register_page"))
            
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        
        user = database.authenticate_user(email, password)
        if user:
            # Register device with token
            import uuid
            session_token = str(uuid.uuid4())
            device_info = request.user_agent.string if request.user_agent else "Unknown Device"
            ip_address = request.remote_addr or "Unknown IP"
            device_id = database.add_device(user['id'], device_info, ip_address, session_token)

            # Don't store password hash in session
            session['user'] = {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'plan': user['plan'],
                'premium_since': user['premium_since'],
                'cancel_date': user['cancel_date']
            }
            session['device_id'] = device_id
            session['device_token'] = session_token
            return redirect(request.args.get("next") or url_for("index"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("login_page"))
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

# === Account & Subscription Routes ===

@app.route("/account")
@login_required
def account_page():
    # Refresh user data from DB to ensure plan info is up-to-date
    user = database.get_user_by_id(session['user']['id'])
    if user:
        session['user'] = {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'plan': user['plan'],
            'premium_since': user['premium_since'],
            'cancel_date': user['cancel_date']
        }
    
    # Get user's devices
    devices = database.get_user_devices(session['user']['id'])
    
    # Get user's recent scans
    user_id = session['user']['id']
    user_web_scans = [s for s in scan_history if s.get('user_id') == user_id]
    user_file_scans = [s for s in file_scan_history if s.get('user_id') == user_id]
    
    recent_scans = user_web_scans + user_file_scans
    # Sort by start time if possible, otherwise just use order
    
    return render_template("account.html", user=session['user'], devices=devices, recent_scans=recent_scans)

@app.route("/account/update-username", methods=["POST"])
@login_required
def update_username():
    new_username = request.form.get("username", "").strip()
    if new_username:
        success = database.update_username(session['user']['id'], new_username)
        if success:
            flash("Username updated successfully.", "success")
        else:
            flash("Username already taken.", "error")
    return redirect(url_for("account_page"))

@app.route("/account/update-security", methods=["POST"])
@login_required
def update_security():
    current_password = request.form.get("current_password", "")
    new_email = request.form.get("email", "").strip()
    new_password = request.form.get("password", "")
    
    # Determine which form was submitted to reopen it
    open_form = "emailForm" if new_email else "passwordForm"
    
    # Verify current password
    if not database.authenticate_user(session['user']['email'], current_password):
        flash("Incorrect current password.", "error")
        return redirect(url_for("account_page", tab="security", open=open_form))
    
    if new_email and new_email != session['user']['email']:
        if database.update_email(session['user']['id'], new_email):
            flash("Email updated successfully.", "success")
        else:
            flash("Email already in use.", "error")
            
    if new_password:
        database.update_password(session['user']['id'], new_password)
        flash("Password updated successfully.", "success")
        
    return redirect(url_for("account_page", tab="security"))

@app.route("/account/logout-device/<int:device_id>", methods=["POST"])
@login_required
def logout_device(device_id):
    database.remove_device(device_id, session['user']['id'])
    # If the user logged out their current device, redirect them to index (which drops session on next login_required)
    if device_id == session.get('device_id'):
        session.clear()
        flash("You have logged out of this device.", "info")
        return redirect(url_for("index"))
    
    flash("Device logged out successfully.", "success")
    return redirect(url_for("account_page", tab="security"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        # Mocking the email functionality
        if email:
            flash(f"If an account with {email} exists, a password reset link has been sent.", "info")
            return redirect(url_for("login_page"))
        else:
            flash("Please enter a valid email.", "error")
    return render_template("forgot_password.html")

@app.route("/upgrade-mock", methods=["POST"])
@login_required
def upgrade_mock():
    user_id = session['user']['id']
    database.update_user_plan(user_id, 'Premium')
    flash("Successfully upgraded to Premium Plan!", "success")
    return redirect(url_for("account_page"))

@app.route("/cancel-premium", methods=["POST"])
@login_required
def cancel_premium():
    user_id = session['user']['id']
    from datetime import datetime, timedelta
    cancel_date = (datetime.now() + timedelta(days=30)).isoformat()
    database.update_user_plan(user_id, 'Premium', cancel_date=cancel_date)
    flash(f"Your Premium subscription has been cancelled and will end on {cancel_date[:10]}.", "info")
    return redirect(url_for("account_page"))

if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "templates"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "static", "css"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "static", "js"), exist_ok=True)
    socketio.run(app, host=WebConfig.HOST, port=WebConfig.PORT, debug=WebConfig.DEBUG, allow_unsafe_werkzeug=True)
