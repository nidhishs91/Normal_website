import os
import json
import base64
import urllib.request
from collections import Counter
 
repo = os.environ["REPO"]
gh_token = os.environ["GH_TOKEN"]
 
gh_headers = {
    "Authorization": f"Bearer {gh_token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}
 
def gh_request(url):
    req = urllib.request.Request(url, headers=gh_headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))
 
def fetch_alerts(endpoint):
    alerts = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/{endpoint}?state=open&per_page=100&page={page}"
        batch = gh_request(url)
        if not batch:
            break
        alerts.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return alerts
 
code_alerts = fetch_alerts("code-scanning/alerts")
secret_alerts = fetch_alerts("secret-scanning/alerts")
dependabot_alerts = fetch_alerts("dependabot/alerts")
 
lines = []
lines.append("--- SECURITY SCANNING REPORT ---")
lines.append(f"Open Code Scanning Alerts: {len(code_alerts)}")
lines.append(f"Open Secret Scanning Alerts: {len(secret_alerts)}")
lines.append(f"Open Dependabot Alerts: {len(dependabot_alerts)}")
lines.append("")
 
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

# import os, json, base64, urllib.request, urllib.parse
# from datetime import datetime

# repo = os.environ["REPO"]
# run_id = os.environ["RUN_ID"]

# sn_url = os.environ["SN_URL"].rstrip("/")
# sn_user = os.environ["SN_USER"]
# sn_pass = os.environ["SN_PASS"]
# app_release_sys_id = os.environ.get("APP_RELEASE_SYS_ID", "")

# # Example counts from your GHAS logic
# code_count = len(code_alerts)
# secret_count = len(secret_alerts)
# dep_count = len(dependabot_alerts)
# total_count = code_count + secret_count + dep_count

# # Simple rating logic
# if total_count == 0:
#     rating = "Low"
# elif total_count <= 3:
#     rating = "Medium"
# elif total_count <= 10:
#     rating = "High"
# else:
#     rating = "Critical"

# payload = {
#     "source": "GitHub Advanced Security",
#     "scan_summary_name": f"GHAS - {repo} - {run_id}",
#     "source_scan_id": str(run_id),
#     "last_scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
#     "detected_flaw_count": str(total_count),
#     "last_scan_rating": rating
# }

# if app_release_sys_id:
#     payload["application_release"] = app_release_sys_id

# auth = base64.b64encode(f"{sn_user}:{sn_pass}".encode()).decode()
# headers = {
#     "Authorization": f"Basic {auth}",
#     "Content-Type": "application/json",
#     "Accept": "application/json"
# }

# # Find existing record
# query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
# get_url = f"{sn_url}/api/now/table/sn_vul_app_vul_scan_summary?sysparm_query={query}&sysparm_limit=1"

# req = urllib.request.Request(get_url, headers=headers)
# with urllib.request.urlopen(req) as resp:
#     existing = json.loads(resp.read().decode()).get("result", [])

# if existing:
#     sys_id = existing[0]["sys_id"]
#     update_url = f"{sn_url}/api/now/table/sn_vul_app_vul_scan_summary/{sys_id}"
#     req = urllib.request.Request(
#         update_url,
#         data=json.dumps(payload).encode(),
#         headers=headers,
#         method="PATCH"
#     )
# else:
#     create_url = f"{sn_url}/api/now/table/sn_vul_app_vul_scan_summary"
#     req = urllib.request.Request(
#         create_url,
#         data=json.dumps(payload).encode(),
#         headers=headers,
#         method="POST"
#     )

# with urllib.request.urlopen(req) as resp:
#     print(resp.read().decode())
