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
