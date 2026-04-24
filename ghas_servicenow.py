# import os
# import json
# import base64
# import urllib.request
# import urllib.parse
# import urllib.error
# from datetime import datetime, timezone

# # ----------------------------------------------------
# # ENV VARS
# # ----------------------------------------------------
# repo = os.environ["REPO"]
# gh_token = os.environ["GH_TOKEN"]

# sn_url = os.environ["SN_URL"].rstrip("/")
# sn_user = os.environ["SN_USER"]
# sn_pass = os.environ["SN_PASS"]
# change_sys_id = os.environ["CHANGE_SYS_ID"]
# run_id = os.environ["RUN_ID"]
# run_url = os.environ["RUN_URL"]

# # Optional
# app_release_sys_id = os.environ.get("APP_RELEASE_SYS_ID", "").strip()
# summary_table = os.environ.get("SN_SUMMARY_TABLE", "sn_vul_app_vul_scan_summary").strip()
# ghas_source_label = os.environ.get("GHAS_SOURCE_LABEL", "GitHub Advanced Security").strip()
# source_sdlc_status_value = os.environ.get("SOURCE_SDLC_STATUS", "GitHub Actions").strip()
# policy_value = os.environ.get("GHAS_POLICY", "GitHub Advanced Security").strip()

# now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# # ----------------------------------------------------
# # HEADERS
# # ----------------------------------------------------
# gh_headers = {
#     "Authorization": f"Bearer {gh_token}",
#     "Accept": "application/vnd.github+json",
#     "X-GitHub-Api-Version": "2022-11-28",
# }

# sn_auth = base64.b64encode(f"{sn_user}:{sn_pass}".encode()).decode()
# sn_headers = {
#     "Authorization": f"Basic {sn_auth}",
#     "Content-Type": "application/json",
#     "Accept": "application/json",
# }

# # ----------------------------------------------------
# # HELPERS
# # ----------------------------------------------------
# def gh_request(url):
#     req = urllib.request.Request(url, headers=gh_headers)
#     try:
#         with urllib.request.urlopen(req, timeout=60) as resp:
#             return json.loads(resp.read().decode("utf-8"))
#     except urllib.error.HTTPError as e:
#         err = e.read().decode("utf-8", errors="ignore")
#         raise RuntimeError(f"GitHub API error {e.code}: {err}")
#     except Exception as e:
#         raise RuntimeError(f"GitHub request failed: {e}")


# def fetch_alerts(endpoint, state="open", paginate=True):
#     """
#     paginate=True  -> code scanning, secret scanning
#     paginate=False -> dependabot (simple single page)
#     """
#     alerts = []
#     page = 1

#     while True:
#         if paginate:
#             url = (
#                 f"https://api.github.com/repos/{repo}/{endpoint}"
#                 f"?state={state}&per_page=100&page={page}"
#             )
#         else:
#             url = (
#                 f"https://api.github.com/repos/{repo}/{endpoint}"
#                 f"?state={state}&per_page=100"
#             )

#         batch = gh_request(url)

#         if not batch:
#             break

#         alerts.extend(batch)

#         if not paginate or len(batch) < 100:
#             break

#         page += 1

#     return alerts


# def sn_request(method, url, payload=None):
#     data = json.dumps(payload).encode("utf-8") if payload else None
#     req = urllib.request.Request(url, data=data, method=method, headers=sn_headers)
#     try:
#         with urllib.request.urlopen(req, timeout=60) as resp:
#             body = resp.read().decode("utf-8")
#             return json.loads(body) if body else {}
#     except urllib.error.HTTPError as e:
#         err = e.read().decode("utf-8", errors="ignore")
#         raise RuntimeError(f"ServiceNow API error {e.code}: {err}")
#     except Exception as e:
#         raise RuntimeError(f"ServiceNow request failed: {e}")


# def build_rating(total):
#     if total == 0:
#         return "Low"
#     elif total <= 3:
#         return "Medium"
#     elif total <= 10:
#         return "High"
#     return "Critical"


# def print_json(title, data):
#     print(title)
#     print(json.dumps(data, indent=2))


# # ----------------------------------------------------
# # FETCH GHAS ALERTS
# # ----------------------------------------------------
# code_open_alerts = fetch_alerts("code-scanning/alerts", state="open", paginate=True)
# secret_open_alerts = fetch_alerts("secret-scanning/alerts", state="open", paginate=True)
# dep_open_alerts = fetch_alerts("dependabot/alerts", state="open", paginate=False)

# code_fixed_alerts = fetch_alerts("code-scanning/alerts", state="fixed", paginate=True)
# code_dismissed_alerts = fetch_alerts("code-scanning/alerts", state="dismissed", paginate=True)

# secret_resolved_alerts = fetch_alerts("secret-scanning/alerts", state="resolved", paginate=True)

# dep_fixed_alerts = fetch_alerts("dependabot/alerts", state="fixed", paginate=False)
# dep_dismissed_alerts = fetch_alerts("dependabot/alerts", state="dismissed", paginate=False)

# # Counts
# code_open_count = len(code_open_alerts)
# secret_open_count = len(secret_open_alerts)
# dep_open_count = len(dep_open_alerts)

# code_fixed_count = len(code_fixed_alerts)
# code_dismissed_count = len(code_dismissed_alerts)
# secret_resolved_count = len(secret_resolved_alerts)
# dep_fixed_count = len(dep_fixed_alerts)
# dep_dismissed_count = len(dep_dismissed_alerts)

# total_open_count = code_open_count + secret_open_count + dep_open_count
# total_fixed_count = code_fixed_count + secret_resolved_count + dep_fixed_count
# total_dismissed_count = code_dismissed_count + dep_dismissed_count

# overall_rating = build_rating(total_open_count)
# code_rating = build_rating(code_open_count)
# dep_rating = build_rating(dep_open_count)

# # Severity breakdowns
# def normalize_severity(raw):
#     s = (raw or "").strip().lower()
#     mapping = {
#         "critical": "Critical",
#         "high": "High",
#         "medium": "Medium",
#         "moderate": "Medium",
#         "low": "Low",
#         "warning": "Medium",
#         "note": "Low",
#         "error": "High",
#         "info": "Info",
#         "none": "Info",
#         "unknown": "Unknown",
#     }
#     if not s:
#         return "Unknown"
#     return mapping.get(s, s.capitalize())


# def severity_counts(alerts, extractor):
#     counts = {}
#     for a in alerts:
#         sev = normalize_severity(extractor(a))
#         counts[sev] = counts.get(sev, 0) + 1
#     return counts


# def merge_counts(*dicts):
#     out = {}
#     for d in dicts:
#         for k, v in d.items():
#             out[k] = out.get(k, 0) + v
#     return out


# code_sev_counts = severity_counts(code_open_alerts, lambda a: a.get("rule", {}).get("severity"))
# dep_sev_counts = severity_counts(dep_open_alerts, lambda a: a.get("security_advisory", {}).get("severity"))
# total_sev_counts = merge_counts(code_sev_counts, dep_sev_counts)

# dep_packages = set()
# for a in dep_open_alerts:
#     pkg = a.get("dependency", {}).get("package", {}).get("name")
#     if pkg:
#         dep_packages.add(pkg)

# # ----------------------------------------------------
# # BUILD WORK NOTES
# # ----------------------------------------------------
# lines = [
#     "--- SECURITY SCANNING REPORT ---",
#     f"Repository: {repo}",
#     f"Pipeline Run: {run_url}",
#     f"Run ID: {run_id}",
#     "",
#     f"Open Code Scanning Alerts: {code_open_count}",
#     f"Fixed Code Scanning Alerts: {code_fixed_count}",
#     f"Dismissed Code Scanning Alerts: {code_dismissed_count}",
#     "",
#     f"Open Secret Scanning Alerts: {secret_open_count}",
#     f"Resolved Secret Scanning Alerts: {secret_resolved_count}",
#     "",
#     f"Open Dependabot Alerts: {dep_open_count}",
#     f"Fixed Dependabot Alerts: {dep_fixed_count}",
#     f"Dismissed Dependabot Alerts: {dep_dismissed_count}",
#     "",
#     f"Total Open GHAS Alerts: {total_open_count}",
#     f"Total Fixed/Resolved Alerts: {total_fixed_count}",
#     f"Total Dismissed Alerts: {total_dismissed_count}",
#     f"Overall Risk Rating: {overall_rating}",
#     "",
# ]

# if code_open_alerts:
#     lines.append("Code Scanning (Open):")
#     for a in code_open_alerts:
#         rule = a.get("rule", {})
#         severity = normalize_severity(rule.get("severity"))
#         desc = rule.get("description", "")
#         lines.append(f"- [{severity}] {desc}")
#         lines.append(f"  {a.get('html_url', '')}")

# if secret_open_alerts:
#     lines.append("")
#     lines.append("Secret Scanning (Open):")
#     for a in secret_open_alerts:
#         st = a.get("secret_type_display_name") or a.get("secret_type") or "Secret"
#         lines.append(f"- [{st}] Alert #{a.get('number')}")
#         lines.append(f"  {a.get('html_url', '')}")

# if dep_open_alerts:
#     lines.append("")
#     lines.append("Dependabot (Open):")
#     for a in dep_open_alerts:
#         adv = a.get("security_advisory", {})
#         dep = a.get("dependency", {})
#         pkg = dep.get("package", {}).get("name", "unknown")
#         sev = normalize_severity(adv.get("severity"))
#         summary = adv.get("summary", "")
#         lines.append(f"- [{sev}] {pkg} - {summary}")
#         lines.append(f"  {a.get('html_url', '')}")

# work_notes = "\n".join(lines)
# print(work_notes)

# # ----------------------------------------------------
# # UPDATE CHANGE WORK NOTES
# # ----------------------------------------------------
# sn_request(
#     "PATCH",
#     f"{sn_url}/api/now/table/change_request/{change_sys_id}",
#     {"work_notes": work_notes},
# )
# print(f"✅ Updated change request {change_sys_id}")

# # ----------------------------------------------------
# # BUILD SCAN SUMMARY PAYLOAD
# # ----------------------------------------------------
# summary_payload = {
#     "source": ghas_source_label,
#     "scan_summary_name": f"GHAS - {repo} - Run {run_id}",
#     "source_scan_id": str(run_id),
#     "last_scan_date": now_str,
#     "scan_published_date": now_str,
#     "detected_flaw_count": total_open_count,
#     "fixed_flaw_count": total_fixed_count,
#     "mitigated_flaw_count": total_dismissed_count,
#     "new_flaw_count": total_open_count,
#     "unmitigated_flaw_count": total_open_count,
#     "last_scan_rating": overall_rating,
#     "source_sdlc_status": source_sdlc_status_value,
#     "policy": policy_value,
#     "third_party_vulnerability_count": dep_open_count,
#     "third_party_library_count": len(dep_packages),
#     "third_party_library_issue_count": dep_open_count,
#     "third_party_license_issue_count": 0,
#     "vulnerable_third_party_library_count": len(dep_packages),
#     "total_flaw_count_by_severity": json.dumps(total_sev_counts, sort_keys=True),
#     "unmitigated_flaw_count_by_severity": json.dumps(total_sev_counts, sort_keys=True),
#     "sast_flaw_count_by_severity": json.dumps(code_sev_counts, sort_keys=True),
#     "tpe_vulnerabilty_count_by_severity": json.dumps(dep_sev_counts, sort_keys=True),
# }

# if code_open_count > 0 or code_fixed_count > 0 or code_dismissed_count > 0:
#     summary_payload["last_static_scan_date"] = now_str
#     summary_payload["last_static_scan_rating"] = code_rating

# if dep_open_count > 0 or dep_fixed_count > 0 or dep_dismissed_count > 0:
#     summary_payload["last_sca_scan_date"] = now_str
#     summary_payload["last_sca_scan_rating"] = dep_rating

# if app_release_sys_id:
#     summary_payload["application_release"] = app_release_sys_id

# print_json("✅ Summary payload being sent:", summary_payload)

# # ----------------------------------------------------
# # UPSERT SCAN SUMMARY
# # ----------------------------------------------------
# query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
# search_url = (
#     f"{sn_url}/api/now/table/{summary_table}"
#     f"?sysparm_query={query}"
#     f"&sysparm_limit=1"
# )

# existing = sn_request("GET", search_url).get("result", [])

# if existing:
#     summary_sys_id = existing[0]["sys_id"]
#     sn_request("PATCH", f"{sn_url}/api/now/table/{summary_table}/{summary_sys_id}", summary_payload)
#     print(f"✅ Updated scan summary {summary_sys_id}")
# else:
#     created = sn_request("POST", f"{sn_url}/api/now/table/{summary_table}", summary_payload)
#     summary_sys_id = created.get("result", {}).get("sys_id", "")
#     print(f"✅ Created scan summary {summary_sys_id}")

# # ----------------------------------------------------
# # VERIFY SAVED SUMMARY
# # ----------------------------------------------------
# if summary_sys_id:
#     verify_url = (
#         f"{sn_url}/api/now/table/{summary_table}/{summary_sys_id}"
#         "?sysparm_fields=source,scan_summary_name,source_scan_id,last_scan_date,scan_published_date,"
#         "detected_flaw_count,fixed_flaw_count,mitigated_flaw_count,new_flaw_count,unmitigated_flaw_count,"
#         "last_scan_rating,last_static_scan_date,last_static_scan_rating,last_sca_scan_date,last_sca_scan_rating,"
#         "third_party_vulnerability_count,third_party_library_count,third_party_library_issue_count,"
#         "third_party_license_issue_count,vulnerable_third_party_library_count,application_release,"
#         "sast_flaw_count_by_severity,tpe_vulnerabilty_count_by_severity,total_flaw_count_by_severity,"
#         "unmitigated_flaw_count_by_severity"
#     )
#     saved_record = sn_request("GET", verify_url)
#     print_json("✅ Saved ServiceNow summary record:", saved_record)

# print("✅ GHAS → ServiceNow sync completed successfully.")

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
ghas_source_label = os.environ.get("GHAS_SOURCE_LABEL", "GitHub Advanced Security").strip()
source_sdlc_status_value = os.environ.get("SOURCE_SDLC_STATUS", "GitHub Actions").strip()
policy_value = os.environ.get("GHAS_POLICY", "GitHub Advanced Security").strip()

now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

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
    paginate=False -> dependabot (simple single page)
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


def print_json(title, data):
    print(title)
    print(json.dumps(data, indent=2))


# ----------------------------------------------------
# FETCH GHAS ALERTS
# ----------------------------------------------------
code_open_alerts = fetch_alerts("code-scanning/alerts", state="open", paginate=True)
secret_open_alerts = fetch_alerts("secret-scanning/alerts", state="open", paginate=True)
dep_open_alerts = fetch_alerts("dependabot/alerts", state="open", paginate=False)

code_fixed_alerts = fetch_alerts("code-scanning/alerts", state="fixed", paginate=True)
code_dismissed_alerts = fetch_alerts("code-scanning/alerts", state="dismissed", paginate=True)

secret_resolved_alerts = fetch_alerts("secret-scanning/alerts", state="resolved", paginate=True)

dep_fixed_alerts = fetch_alerts("dependabot/alerts", state="fixed", paginate=False)
dep_dismissed_alerts = fetch_alerts("dependabot/alerts", state="dismissed", paginate=False)

# Counts
code_open_count = len(code_open_alerts)
secret_open_count = len(secret_open_alerts)
dep_open_count = len(dep_open_alerts)

code_fixed_count = len(code_fixed_alerts)
code_dismissed_count = len(code_dismissed_alerts)
secret_resolved_count = len(secret_resolved_alerts)
dep_fixed_count = len(dep_fixed_alerts)
dep_dismissed_count = len(dep_dismissed_alerts)

total_open_count = code_open_count + secret_open_count + dep_open_count
total_fixed_count = code_fixed_count + secret_resolved_count + dep_fixed_count
total_dismissed_count = code_dismissed_count + dep_dismissed_count

overall_rating = build_rating(total_open_count)
code_rating = build_rating(code_open_count)
dep_rating = build_rating(dep_open_count)

# Severity breakdowns
def normalize_severity(raw):
    s = (raw or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "warning": "Medium",
        "note": "Low",
        "error": "High",
        "info": "Info",
        "none": "Info",
        "unknown": "Unknown",
    }
    if not s:
        return "Unknown"
    return mapping.get(s, s.capitalize())


def severity_counts(alerts, extractor):
    counts = {}
    for a in alerts:
        sev = normalize_severity(extractor(a))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def merge_counts(*dicts):
    out = {}
    for d in dicts:
        for k, v in d.items():
            out[k] = out.get(k, 0) + v
    return out


code_sev_counts = severity_counts(code_open_alerts, lambda a: a.get("rule", {}).get("severity"))
dep_sev_counts = severity_counts(dep_open_alerts, lambda a: a.get("security_advisory", {}).get("severity"))
total_sev_counts = merge_counts(code_sev_counts, dep_sev_counts)

dep_packages = set()
for a in dep_open_alerts:
    pkg = a.get("dependency", {}).get("package", {}).get("name")
    if pkg:
        dep_packages.add(pkg)

# ----------------------------------------------------
# BUILD WORK NOTES
# ----------------------------------------------------
lines = [
    "--- SECURITY SCANNING REPORT ---",
    f"Repository: {repo}",
    f"Pipeline Run: {run_url}",
    f"Run ID: {run_id}",
    "",
    f"Open Code Scanning Alerts: {code_open_count}",
    f"Fixed Code Scanning Alerts: {code_fixed_count}",
    f"Dismissed Code Scanning Alerts: {code_dismissed_count}",
    "",
    f"Open Secret Scanning Alerts: {secret_open_count}",
    f"Resolved Secret Scanning Alerts: {secret_resolved_count}",
    "",
    f"Open Dependabot Alerts: {dep_open_count}",
    f"Fixed Dependabot Alerts: {dep_fixed_count}",
    f"Dismissed Dependabot Alerts: {dep_dismissed_count}",
    "",
    f"Total Open GHAS Alerts: {total_open_count}",
    f"Total Fixed/Resolved Alerts: {total_fixed_count}",
    f"Total Dismissed Alerts: {total_dismissed_count}",
    f"Overall Risk Rating: {overall_rating}",
    "",
]

if code_open_alerts:
    lines.append("Code Scanning (Open):")
    for a in code_open_alerts:
        rule = a.get("rule", {})
        severity = normalize_severity(rule.get("severity"))
        desc = rule.get("description", "")
        lines.append(f"- [{severity}] {desc}")
        lines.append(f"  {a.get('html_url', '')}")

if secret_open_alerts:
    lines.append("")
    lines.append("Secret Scanning (Open):")
    for a in secret_open_alerts:
        st = a.get("secret_type_display_name") or a.get("secret_type") or "Secret"
        lines.append(f"- [{st}] Alert #{a.get('number')}")
        lines.append(f"  {a.get('html_url', '')}")

if dep_open_alerts:
    lines.append("")
    lines.append("Dependabot (Open):")
    for a in dep_open_alerts:
        adv = a.get("security_advisory", {})
        dep = a.get("dependency", {})
        pkg = dep.get("package", {}).get("name", "unknown")
        sev = normalize_severity(adv.get("severity"))
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
# BUILD SCAN SUMMARY PAYLOAD
# ----------------------------------------------------
summary_payload = {
    "source": ghas_source_label,
    "scan_summary_name": f"GHAS - {repo} - Run {run_id}",
    "source_scan_id": str(run_id),
    "last_scan_date": now_str,
    "scan_published_date": now_str,
    "detected_flaw_count": total_open_count,
    "fixed_flaw_count": total_fixed_count,
    "mitigated_flaw_count": total_dismissed_count,
    "new_flaw_count": total_open_count,
    "unmitigated_flaw_count": total_open_count,
    "last_scan_rating": overall_rating,
    "source_sdlc_status": source_sdlc_status_value,
    "policy": policy_value,
    "third_party_vulnerability_count": dep_open_count,
    "third_party_library_count": len(dep_packages),
    "third_party_library_issue_count": dep_open_count,
    "third_party_license_issue_count": 0,
    "vulnerable_third_party_library_count": len(dep_packages),
    "total_flaw_count_by_severity": json.dumps(total_sev_counts, sort_keys=True),
    "unmitigated_flaw_count_by_severity": json.dumps(total_sev_counts, sort_keys=True),
    "sast_flaw_count_by_severity": json.dumps(code_sev_counts, sort_keys=True),
    "tpe_vulnerabilty_count_by_severity": json.dumps(dep_sev_counts, sort_keys=True),

    # Link GHAS summary to the Change Request
    "u_change_request": change_sys_id,
}

if code_open_count > 0 or code_fixed_count > 0 or code_dismissed_count > 0:
    summary_payload["last_static_scan_date"] = now_str
    summary_payload["last_static_scan_rating"] = code_rating

if dep_open_count > 0 or dep_fixed_count > 0 or dep_dismissed_count > 0:
    summary_payload["last_sca_scan_date"] = now_str
    summary_payload["last_sca_scan_rating"] = dep_rating

if app_release_sys_id:
    summary_payload["application_release"] = app_release_sys_id

print_json("✅ Summary payload being sent:", summary_payload)

# ----------------------------------------------------
# UPSERT SCAN SUMMARY
# ----------------------------------------------------
query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
search_url = (
    f"{sn_url}/api/now/table/{summary_table}"
    f"?sysparm_query={query}"
    f"&sysparm_limit=1"
)

existing = sn_request("GET", search_url).get("result", [])

if existing:
    summary_sys_id = existing[0]["sys_id"]
    sn_request("PATCH", f"{sn_url}/api/now/table/{summary_table}/{summary_sys_id}", summary_payload)
    print(f"✅ Updated scan summary {summary_sys_id}")
else:
    created = sn_request("POST", f"{sn_url}/api/now/table/{summary_table}", summary_payload)
    summary_sys_id = created.get("result", {}).get("sys_id", "")
    print(f"✅ Created scan summary {summary_sys_id}")

# ----------------------------------------------------
# VERIFY SAVED SUMMARY
# ----------------------------------------------------
if summary_sys_id:
    verify_url = (
        f"{sn_url}/api/now/table/{summary_table}/{summary_sys_id}"
        "?sysparm_fields=source,scan_summary_name,source_scan_id,last_scan_date,scan_published_date,"
        "detected_flaw_count,fixed_flaw_count,mitigated_flaw_count,new_flaw_count,unmitigated_flaw_count,"
        "last_scan_rating,last_static_scan_date,last_static_scan_rating,last_sca_scan_date,last_sca_scan_rating,"
        "third_party_vulnerability_count,third_party_library_count,third_party_library_issue_count,"
        "third_party_license_issue_count,vulnerable_third_party_library_count,application_release,"
        "u_change_request,sast_flaw_count_by_severity,tpe_vulnerabilty_count_by_severity,total_flaw_count_by_severity,"
        "unmitigated_flaw_count_by_severity"
    )
    saved_record = sn_request("GET", verify_url)
    print_json("✅ Saved ServiceNow summary record:", saved_record)

print("✅ GHAS → ServiceNow sync completed successfully.")
