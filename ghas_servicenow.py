import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

# ----------------------------------------------------
# ENV VARS
# ----------------------------------------------------
repo = os.environ["REPO"]
gh_token = os.environ["GH_TOKEN"]

sn_url = os.environ["SN_URL"].rstrip("/")
sn_user = os.environ["SN_USER"]
sn_pass = os.environ["SN_PASS"]
change_sys_id = os.environ["CHANGE_SYS_ID"]
run_id = os.environ["RUN_ID"]
run_url = os.environ["RUN_URL"]

# Optional: if you want to populate reference field
app_release_sys_id = os.environ.get("APP_RELEASE_SYS_ID", "").strip()

# Optional: override table name if needed
summary_table = os.environ.get("SN_SUMMARY_TABLE", "sn_vul_app_vul_scan_summary").strip()

# ----------------------------------------------------
# GITHUB HEADERS
# ----------------------------------------------------
gh_headers = {
    "Authorization": f"Bearer {gh_token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ----------------------------------------------------
# SERVICENOW HEADERS
# ----------------------------------------------------
sn_auth = base64.b64encode(f"{sn_user}:{sn_pass}".encode()).decode()
sn_headers = {
    "Authorization": f"Basic {sn_auth}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# ----------------------------------------------------
# HELPERS
# ----------------------------------------------------
def gh_request(url):
    req = urllib.request.Request(url, headers=gh_headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"GitHub API error {e.code} for {url}: {err_body}")
    except Exception as e:
        raise RuntimeError(f"GitHub request failed for {url}: {e}")


def fetch_alerts(endpoint):
    """
    Fetch all alerts with pagination.
    Uses state=all so you don't miss resolved/closed alerts.
    """
    alerts = []
    page = 1

    while True:
        url = (
            f"https://api.github.com/repos/{repo}/{endpoint}"
            f"?state=all&per_page=100&page={page}"
        )
        batch = gh_request(url)

        if not batch:
            break

        alerts.extend(batch)

        if len(batch) < 100:
            break

        page += 1

    return alerts


def sn_request(method, url, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=sn_headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            if body:
                return json.loads(body)
            return {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"ServiceNow API error {e.code} for {url}: {err_body}")
    except Exception as e:
        raise RuntimeError(f"ServiceNow request failed for {url}: {e}")


def build_rating(total_count):
    if total_count == 0:
        return "Low"
    elif total_count <= 3:
        return "Medium"
    elif total_count <= 10:
        return "High"
    return "Critical"


def severity_rank(sev):
    sev = (sev or "").lower()
    order = {
        "low": 1,
        "moderate": 2,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get(sev, 0)


# ----------------------------------------------------
# FETCH GHAS ALERTS
# ----------------------------------------------------
code_alerts = fetch_alerts("code-scanning/alerts")
secret_alerts = fetch_alerts("secret-scanning/alerts")
dependabot_alerts = fetch_alerts("dependabot/alerts")

code_count = len(code_alerts)
secret_count = len(secret_alerts)
dependabot_count = len(dependabot_alerts)
total_count = code_count + secret_count + dependabot_count
rating = build_rating(total_count)

# ----------------------------------------------------
# BUILD WORK NOTES
# ----------------------------------------------------
lines = []
lines.append("--- SECURITY SCANNING REPORT ---")
lines.append(f"Repository: {repo}")
lines.append(f"Pipeline Run: {run_url}")
lines.append(f"Run ID: {run_id}")
lines.append("")
lines.append(f"Open Code Scanning Alerts: {code_count}")
lines.append(f"Open Secret Scanning Alerts: {secret_count}")
lines.append(f"Open Dependabot Alerts: {dependabot_count}")
lines.append(f"Total GHAS Alerts: {total_count}")
lines.append(f"Overall Rating: {rating}")
lines.append("")

if code_alerts:
    lines.append("Code Scanning:")
    for a in code_alerts:
        rule = a.get("rule", {})
        severity = rule.get("severity", "info").upper()
        desc = rule.get("description", "Code scanning issue")
        lines.append(f"- [{severity}] {desc}")
        lines.append(f"  {a.get('html_url', '')}")

if secret_alerts:
    lines.append("")
    lines.append("Secret Scanning:")
    for a in secret_alerts:
        secret_type = a.get("secret_type_display_name") or a.get("secret_type") or "Secret"
        lines.append(f"- [{secret_type}] Alert #{a.get('number')}")
        lines.append(f"  {a.get('html_url', '')}")

if dependabot_alerts:
    lines.append("")
    lines.append("Dependabot:")
    for a in dependabot_alerts:
        advisory = a.get("security_advisory", {})
        dependency = a.get("dependency", {})
        pkg = dependency.get("package", {}).get("name", "unknown-package")
        sev = advisory.get("severity", "unknown").upper()
        summary = advisory.get("summary", "")
        lines.append(f"- [{sev}] {pkg} - {summary}")
        lines.append(f"  {a.get('html_url', '')}")

work_note_content = "\n".join(lines)
print(work_note_content)

# ----------------------------------------------------
# UPDATE SERVICENOW CHANGE WORK NOTES
# ----------------------------------------------------
change_payload = {
    "work_notes": work_note_content
}

change_url = f"{sn_url}/api/now/table/change_request/{change_sys_id}"
sn_request("PATCH", change_url, change_payload)

print(f"Updated ServiceNow change request: {change_sys_id}")

# ----------------------------------------------------
# UPSERT SERVICENOW SCAN SUMMARY
# ----------------------------------------------------
# Field names from your table:
# source
# application_release
# scan_summary_name
# source_scan_id
# last_scan_date
# detected_flaw_count
# last_scan_rating

scan_summary_name = f"GHAS - {repo} - Run {run_id}"

summary_payload = {
    "source": "GitHub Advanced Security",
    "scan_summary_name": scan_summary_name,
    "source_scan_id": str(run_id),
    "last_scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    "detected_flaw_count": str(total_count),
    "last_scan_rating": rating,
}

if app_release_sys_id:
    summary_payload["application_release"] = app_release_sys_id

# Check if record already exists
query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
search_url = (
    f"{sn_url}/api/now/table/{summary_table}"
    f"?sysparm_query={query}&sysparm_limit=1"
)

search_result = sn_request("GET", search_url)
existing_records = search_result.get("result", [])

if existing_records:
    sys_id = existing_records[0]["sys_id"]
    update_url = f"{sn_url}/api/now/table/{summary_table}/{sys_id}"
    sn_request("PATCH", update_url, summary_payload)
    print(f"Updated scan summary record: {sys_id}")
else:
    create_url = f"{sn_url}/api/now/table/{summary_table}"
    created = sn_request("POST", create_url, summary_payload)
    created_sys_id = created.get("result", {}).get("sys_id", "unknown")
    print(f"Created scan summary record: {created_sys_id}")

print("GHAS sync completed successfully.")
