"""
reports.py - PDF security report generation.

Generates a summary report of security events using fpdf2.
The report includes:
- Header with project name and date range
- Summary stats (total, blocked, allowed)
- Breakdown by detection method
- Top blocked IPs
- Recent blocked events table

Called from the dashboard when the user clicks "Generate Report".
"""

import os
from datetime import datetime
from fpdf import FPDF
from app.models import get_db
from config import DATABASE_PATH


class SecurityReport(FPDF):
    """Custom PDF class with header/footer."""

    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "SecureShield Security Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def generate_report():
    """
    Generate a PDF security report and return the file path.
    Covers all events currently in the database.
    """
    conn = get_db()

    # gather stats
    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE outcome='block'").fetchone()[0]
    allowed = total - blocked

    # breakdown by detection method
    breakdown = conn.execute(
        """SELECT detection_method, COUNT(*) as count
           FROM security_events WHERE outcome='block'
           GROUP BY detection_method ORDER BY count DESC"""
    ).fetchall()

    # top blocked IPs
    top_ips = conn.execute(
        """SELECT source_ip, COUNT(*) as count
           FROM security_events WHERE outcome='block'
           GROUP BY source_ip ORDER BY count DESC LIMIT 10"""
    ).fetchall()

    # recent blocked events (last 20)
    recent_blocked = conn.execute(
        """SELECT timestamp, source_ip, request_method, request_url, detection_method, details
           FROM security_events WHERE outcome='block'
           ORDER BY id DESC LIMIT 20"""
    ).fetchall()

    conn.close()

    # build the PDF
    pdf = SecurityReport()
    pdf.add_page()

    # summary section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Total requests processed: {total}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Allowed: {allowed}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Blocked: {blocked}", new_x="LMARGIN", new_y="NEXT")
    if total > 0:
        pdf.cell(0, 7, f"Block rate: {blocked/total*100:.1f}%", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # detection breakdown
    if breakdown:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Blocked by Detection Type", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        for row in breakdown:
            method_name = {
                "rule_sqli": "SQL Injection Rules",
                "rule_xss": "XSS Rules",
                "bruteforce": "Brute-Force Detection",
                "ml": "ML Classifier",
            }.get(row["detection_method"], row["detection_method"])
            pdf.cell(0, 7, f"  {method_name}: {row['count']}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    # top blocked IPs
    if top_ips:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Top Blocked IP Addresses", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        for row in top_ips:
            pdf.cell(0, 7, f"  {row['source_ip']}: {row['count']} blocked requests", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    # recent blocked events table
    if recent_blocked:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Recent Blocked Requests", new_x="LMARGIN", new_y="NEXT")

        # table header
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 7, "Time", border=1)
        pdf.cell(25, 7, "IP", border=1)
        pdf.cell(15, 7, "Method", border=1)
        pdf.cell(70, 7, "URL", border=1)
        pdf.cell(25, 7, "Detection", border=1)
        pdf.ln()

        # table rows
        pdf.set_font("Helvetica", "", 8)
        for row in recent_blocked:
            url = row["request_url"][:40] + "..." if len(row["request_url"]) > 40 else row["request_url"]
            pdf.cell(35, 6, row["timestamp"], border=1)
            pdf.cell(25, 6, row["source_ip"], border=1)
            pdf.cell(15, 6, row["request_method"], border=1)
            pdf.cell(70, 6, url, border=1)
            pdf.cell(25, 6, row["detection_method"], border=1)
            pdf.ln()

    # save
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename = f"secureshield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(reports_dir, filename)
    pdf.output(filepath)

    return filepath
