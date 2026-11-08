"""
dashboard.py - Admin dashboard for SecureShield.

Shows security stats and lets you browse the event log.
Uses Bootstrap 5 from CDN so I don't need to mess with CSS.

Routes:
  /dashboard/           — stats overview (total, blocked, breakdown)
  /dashboard/logs       — log viewer with filtering
  /dashboard/blocklist  — view/manage blocked IPs
  /dashboard/report     — generate and download PDF report
"""

from flask import Blueprint, render_template, request, send_file, redirect, url_for
from app.models import get_events, get_stats
from app.reports import generate_report
from rules.bruteforce import _blocked_ips, _failed_attempts, get_block_remaining
import time

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.route("/")
def stats():
    """Main dashboard page — summary statistics."""
    stats_data = get_stats()
    return render_template("dashboard/stats.html", stats=stats_data)


@dashboard_bp.route("/logs")
def logs():
    """Log viewer with filtering by outcome and detection method."""
    outcome = request.args.get("outcome", "").strip() or None
    detection = request.args.get("detection", "").strip() or None
    page = int(request.args.get("page", 1))
    per_page = 50

    offset = (page - 1) * per_page
    events = get_events(limit=per_page, offset=offset,
                        outcome=outcome, detection_method=detection)

    return render_template("dashboard/logs.html",
                           events=events,
                           outcome=outcome,
                           detection=detection,
                           page=page,
                           per_page=per_page)


@dashboard_bp.route("/blocklist")
def blocklist():
    """View currently blocked IPs and their remaining block time."""
    blocked = []
    now = time.time()
    for ip, blocked_at in list(_blocked_ips.items()):
        remaining = get_block_remaining(ip)
        if remaining > 0:
            blocked.append({
                "ip": ip,
                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(blocked_at)),
                "remaining": int(remaining),
            })
    return render_template("dashboard/blocklist.html", blocked=blocked)


@dashboard_bp.route("/blocklist/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    """Manually unblock an IP address."""
    if ip in _blocked_ips:
        del _blocked_ips[ip]
    if ip in _failed_attempts:
        del _failed_attempts[ip]
    return redirect(url_for("dashboard.blocklist"))


@dashboard_bp.route("/report")
def report():
    """Generate a PDF report and send it as a download."""
    filepath = generate_report()
    return send_file(filepath, as_attachment=True)
