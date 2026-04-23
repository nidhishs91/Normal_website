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

# Optional
app_release_sys_id = os.environ.get("APP_RELEASE_SYS_ID", "").strip()
summary_table = os.environ.get("SN_SUMMARY_TABLE", "sn_vul_app_vul_scan_summary").strip()

# ----------------------------------------------------
# HEADERS
# ----------------------------------------------------
gh_headers = {
    "Authorization": f"Bearer {gh_token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

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
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"GitHub API error {e.code}: {err}")
    except Exception as e:
        raise RuntimeError(f"GitHub request failed: {e}")


def fetch_alerts(endpoint, state="open", paginate=True):
    """
    paginate=True  -> code scanning, secret scanning
    paginate=False -> dependabot (page param NOT allowed)
    """
    alerts = []
    page = 1

    while True:
        if paginate:
            url = (
                f"https://api.github.com/repos/{repo}/{endpoint}"
                f"?state={state}&per_page=100&page={page}"
            )
        else:
            url = (
                f"https://api.github.com/repos/{repo}/{endpoint}"
                f"?state={state}&per_page=100"
            )

        batch = gh_request(url)

        if not batch:
            break

        alerts.extend(batch)

        if not paginate or len(batch) < 100:
            break

        page += 1

    return alerts


def sn_request(method, url, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, method=method, headers=sn_headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"ServiceNow API error {e.code}: {err}")
    except Exception as e:
        raise RuntimeError(f"ServiceNow request failed: {e}")


def build_rating(total):
    if total == 0:
        return "Low"
    elif total <= 3:
        return "Medium"
    elif total <= 10:
        return "High"
    return "Critical"

# ----------------------------------------------------
# FETCH GHAS ALERTS ✅
# ----------------------------------------------------
code_alerts = fetch_alerts("code-scanning/alerts", paginate=True)
secret_alerts = fetch_alerts("secret-scanning/alerts", paginate=True)
dependabot_alerts = fetch_alerts("dependabot/alerts", paginate=False)  # ✅ FIX

code_count = len(code_alerts)
secret_count = len(secret_alerts)
dep_count = len(dependabot_alerts)
total_count = code_count + secret_count + dep_count
rating = build_rating(total_count)

# ----------------------------------------------------
# BUILD WORK NOTES
# ----------------------------------------------------
lines = [
    "--- SECURITY SCANNING REPORT ---",
    f"Repository: {repo}",
    f"Pipeline Run: {run_url}",
    f"Run ID: {run_id}",
    "",
    f"Open Code Scanning Alerts: {code_count}",
    f"Open Secret Scanning Alerts: {secret_count}",
    f"Open Dependabot Alerts: {dep_count}",
    f"Total GHAS Alerts: {total_count}",
    f"Overall Risk Rating: {rating}",
    "",
]

if code_alerts:
    lines.append("Code Scanning:")
    for a in code_alerts:
        rule = a.get("rule", {})
        lines.append(f"- [{rule.get('severity', 'info').upper()}] {rule.get('description', '')}")
        lines.append(f"  {a.get('html_url', '')}")

if secret_alerts:
    lines.append("")
    lines.append("Secret Scanning:")
    for a in secret_alerts:
        st = a.get("secret_type_display_name") or a.get("secret_type") or "Secret"
        lines.append(f"- [{st}] Alert #{a.get('number')}")
        lines.append(f"  {a.get('html_url', '')}")

if dependabot_alerts:
    lines.append("")
    lines.append("Dependabot:")
    for a in dependabot_alerts:
        adv = a.get("security_advisory", {})
        dep = a.get("dependency", {})
        pkg = dep.get("package", {}).get("name", "unknown")
        sev = adv.get("severity", "unknown").upper()
        summary = adv.get("summary", "")
        lines.append(f"- [{sev}] {pkg} - {summary}")
        lines.append(f"  {a.get('html_url', '')}")

work_notes = "\n".join(lines)
print(work_notes)

# ----------------------------------------------------
# UPDATE CHANGE WORK NOTES
# ----------------------------------------------------
sn_request(
    "PATCH",
    f"{sn_url}/api/now/table/change_request/{change_sys_id}",
    {"work_notes": work_notes},
)

print(f"✅ Updated change request {change_sys_id}")

# ----------------------------------------------------
# UPSERT SCAN SUMMARY
# ----------------------------------------------------
summary_payload = {
    "source": "GitHub Advanced Security",
    "scan_summary_name": f"GHAS - {repo} - Run {run_id}",
    "source_scan_id": str(run_id),
    "last_scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    "detected_flaw_count": str(total_count),
    "last_scan_rating": rating,
}

if app_release_sys_id:
    summary_payload["application_release"] = app_release_sys_id

query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
search_url = f"{sn_url}/api/now/table/{summary_table}?sysparm_query={query}&sysparm_limit=1"
existing = sn_request("GET", search_url).get("result", [])

if existing:
    sys_id = existing[0]["sys_id"]
    sn_request("PATCH", f"{sn_url}/api/now/table/{summary_table}/{sys_id}", summary_payload)
    print(f"✅ Updated scan summary {sys_id}")
else:
    created = sn_request("POST", f"{sn_url}/api/now/table/{summary_table}", summary_payload)
    print(f"✅ Created scan summary {created.get('result', {}).get('sys_id')}")

print("✅ GHAS → ServiceNow sync completed successfully.")
