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
app_release_query = os.environ.get("APP_RELEASE_QUERY", "").strip()
summary_table = os.environ.get("SN_SUMMARY_TABLE", "sn_vul_app_vul_scan_summary").strip()
summary_details_table = os.environ.get("SN_SUMMARY_DETAILS_TABLE", "sn_vul_app_vul_scan_summary_details").strip()
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
    paginate=False -> dependabot (page param NOT allowed in your setup)
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


_field_cache = {}


def discover_table_fields(table_name):
    """
    Best-effort dictionary lookup for a table's fields.
    Returns a set of available field names.
    """
    if table_name in _field_cache:
        return _field_cache[table_name]

    try:
        query = urllib.parse.quote(f"name={table_name}^active=true", safe="=^")
        url = (
            f"{sn_url}/api/now/table/sys_dictionary"
            f"?sysparm_query={query}"
            f"&sysparm_fields=element,column_label,internal_type,reference,mandatory,read_only"
            f"&sysparm_limit=5000"
        )
        result = sn_request("GET", url).get("result", [])
        fields = {r.get("element") for r in result if r.get("element")}
        _field_cache[table_name] = fields
        return fields
    except Exception as e:
        print(f"⚠️ Could not read dictionary for {table_name}: {e}")
        _field_cache[table_name] = set()
        return set()


def pick_field(available_fields, candidates):
    for c in candidates:
        if c in available_fields:
            return c
    return None


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


def severity_sort_key(sev):
    order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
        "Unknown": 5,
    }
    return order.get(sev, 99)


def count_by_severity(alerts, extractor):
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


def clean_repo_name(value):
    return value.split("/")[-1] if "/" in value else value


def find_application_release_sys_id():
    """
    Best effort:
    1) use APP_RELEASE_SYS_ID if provided
    2) try to find a matching release record using repo name / query hint
    3) otherwise return empty string
    """
    if app_release_sys_id:
        return app_release_sys_id

    table = "sn_vul_app_release"
    fields = discover_table_fields(table)
    if not fields:
        return ""

    text_fields = [
        f for f in [
            "name",
            "display_name",
            "short_description",
            "application_name",
            "title",
            "u_name",
            "description",
        ] if f in fields
    ]

    if not text_fields:
        return ""

    repo_short = clean_repo_name(repo)
    search_terms = []

    if app_release_query:
        search_terms.append(app_release_query)

    search_terms.extend([
        repo,
        repo_short,
        repo_short.replace("_", " "),
        repo_short.replace("-", " "),
        repo_short.replace("_", "-"),
        repo_short.title(),
        repo_short.upper(),
    ])

    seen = set()
    search_terms = [t for t in search_terms if t and not (t in seen or seen.add(t))]

    for field in text_fields:
        for term in search_terms:
            try:
                q = urllib.parse.quote(f"{field}LIKE{term}", safe="=^")
                url = (
                    f"{sn_url}/api/now/table/{table}"
                    f"?sysparm_query={q}"
                    f"&sysparm_fields=sys_id,{field}"
                    f"&sysparm_limit=1"
                )
                rows = sn_request("GET", url).get("result", [])
                if rows:
                    sys_id = rows[0].get("sys_id", "").strip()
                    if sys_id:
                        print(f"✅ Auto-found application_release sys_id: {sys_id}")
                        return sys_id
            except Exception:
                continue

    return ""


def build_work_notes():
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

    return "\n".join(lines)


def upsert_record(table_name, payload, query_field, query_value):
    query = urllib.parse.quote(f"{query_field}={query_value}", safe="=^")
    search_url = (
        f"{sn_url}/api/now/table/{table_name}"
        f"?sysparm_query={query}"
        f"&sysparm_limit=1"
    )
    existing = sn_request("GET", search_url).get("result", [])

    if existing:
        sys_id = existing[0]["sys_id"]
        sn_request("PATCH", f"{sn_url}/api/now/table/{table_name}/{sys_id}", payload)
        return sys_id, "updated"
    else:
        created = sn_request("POST", f"{sn_url}/api/now/table/{table_name}", payload)
        sys_id = created.get("result", {}).get("sys_id", "")
        return sys_id, "created"


def upsert_summary_details(parent_sys_id, detail_rows):
    if not detail_rows:
        return

    fields = discover_table_fields(summary_details_table)
    if not fields:
        print(f"⚠️ No field metadata found for {summary_details_table}; skipping detail rows.")
        return

    parent_field = pick_field(fields, [
        "scan_summary",
        "summary",
        "vul_scan_summary",
        "application_vulnerability_scan_summary",
        "u_scan_summary",
    ])
    category_field = pick_field(fields, ["category_name", "category"])
    severity_field = pick_field(fields, ["severity"])
    count_field = pick_field(fields, ["count", "issue_count", "alert_count"])

    if not all([parent_field, category_field, severity_field, count_field]):
        print(
            "⚠️ Could not identify detail table fields. "
            f"parent={parent_field}, category={category_field}, severity={severity_field}, count={count_field}"
        )
        return

    for category_name, severity, count in detail_rows:
        if count <= 0:
            continue

        payload = {
            parent_field: parent_sys_id,
            category_field: category_name,
            severity_field: severity,
            count_field: count,
        }

        query = urllib.parse.quote(
            f"{parent_field}={parent_sys_id}^{category_field}={category_name}^{severity_field}={severity}",
            safe="=^"
        )
        search_url = (
            f"{sn_url}/api/now/table/{summary_details_table}"
            f"?sysparm_query={query}"
            f"&sysparm_limit=1"
        )
        existing = sn_request("GET", search_url).get("result", [])

        if existing:
            detail_sys_id = existing[0]["sys_id"]
            sn_request("PATCH", f"{sn_url}/api/now/table/{summary_details_table}/{detail_sys_id}", payload)
            print(f"✅ Updated detail row: {category_name} / {severity}")
        else:
            created = sn_request("POST", f"{sn_url}/api/now/table/{summary_details_table}", payload)
            print(f"✅ Created detail row: {category_name} / {severity} -> {created.get('result', {}).get('sys_id', '')}")


# ----------------------------------------------------
# FETCH GHAS ALERTS
# ----------------------------------------------------
# Open
code_open_alerts = fetch_alerts("code-scanning/alerts", state="open", paginate=True)
secret_open_alerts = fetch_alerts("secret-scanning/alerts", state="open", paginate=True)
dep_open_alerts = fetch_alerts("dependabot/alerts", state="open", paginate=False)

# Fixed / resolved / dismissed for richer reporting
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

# Severity breakdowns for open alerts only
code_sev_counts = count_by_severity(code_open_alerts, lambda a: a.get("rule", {}).get("severity"))
dep_sev_counts = count_by_severity(dep_open_alerts, lambda a: a.get("security_advisory", {}).get("severity"))
total_sev_counts = merge_counts(code_sev_counts, dep_sev_counts)

# Unique package count from open Dependabot alerts
dep_packages = set()
for a in dep_open_alerts:
    pkg = a.get("dependency", {}).get("package", {}).get("name")
    if pkg:
        dep_packages.add(pkg)

# ----------------------------------------------------
# BUILD WORK NOTES
# ----------------------------------------------------
work_notes = build_work_notes()
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
# AUTO-FIND APPLICATION RELEASE (OPTIONAL)
# ----------------------------------------------------
resolved_app_release_sys_id = find_application_release_sys_id()

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
}

# Optional scan-specific dates/ratings
if code_open_count > 0 or code_fixed_count > 0 or code_dismissed_count > 0:
    summary_payload["last_static_scan_date"] = now_str
    summary_payload["last_static_scan_rating"] = code_rating

if dep_open_count > 0 or dep_fixed_count > 0 or dep_dismissed_count > 0:
    summary_payload["last_sca_scan_date"] = now_str
    summary_payload["last_sca_scan_rating"] = dep_rating

# Optional reference field
if resolved_app_release_sys_id:
    summary_payload["application_release"] = resolved_app_release_sys_id

print_json("✅ Summary payload being sent:", summary_payload)

# ----------------------------------------------------
# UPSERT SCAN SUMMARY
# ----------------------------------------------------
summary_query = urllib.parse.quote(f"source_scan_id={run_id}", safe="=")
search_url = (
    f"{sn_url}/api/now/table/{summary_table}"
    f"?sysparm_query={summary_query}"
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
# CREATE / UPDATE DETAIL ROWS
# ----------------------------------------------------
detail_rows = []

for sev in sorted(code_sev_counts.keys(), key=severity_sort_key):
    detail_rows.append(("Code Scanning", sev, code_sev_counts[sev]))

for sev in sorted(dep_sev_counts.keys(), key=severity_sort_key):
    detail_rows.append(("Dependabot", sev, dep_sev_counts[sev]))

if secret_open_count > 0:
    detail_rows.append(("Secret Scanning", "Info", secret_open_count))

if summary_sys_id:
    upsert_summary_details(summary_sys_id, detail_rows)

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
        "sast_flaw_count_by_severity,tpe_vulnerabilty_count_by_severity,total_flaw_count_by_severity,"
        "unmitigated_flaw_count_by_severity"
    )
    saved_record = sn_request("GET", verify_url)
    print_json("✅ Saved ServiceNow summary record:", saved_record)

print("✅ GHAS → ServiceNow sync completed successfully.")
