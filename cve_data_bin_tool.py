#!/usr/bin/env python3
"""
Read CVE IDs from cves.csv and enrich with:
  - EPSS score & percentile (FIRST)
  - KEV presence (CISA)
  - Exploit-DB script available? (Yes/No)  — via refs (OSV/NVD)
  - Git commit link (fix)                  — via OSV first, then NVD


Outputs:
  enriched_cves.csv with columns:
    cve_number,epss,epss_percentile,in_kev,exploitdb,git_commit_url
"""

import csv, os, sys, time, json, urllib.request, urllib.error
from urllib.parse import urlencode
import pathlib

EPSS_API = "https://api.first.org/data/v1/epss"  # supports CSV of CVEs
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_VULN = "https://api.osv.dev/v1/vulns/"       # + CVE
NVD_V2    = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # ?cveId=CVE-...

NVD_API_KEY = os.getenv("980ec4fa-d4b5-4295-b767-a382709f44ca")  # optional but helpful

def _get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "cve-enricher/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def load_cves_from_csv(path="cves.csv"):
    cves = []
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if "cve_number" not in r.fieldnames:
            sys.exit("ERROR: cves.csv must have a column named cve_number")
        for row in r:
            cve = (row.get("cve_number") or "").strip()
            if cve:
                cves.append(cve)
    # de-dupe, keep order
    seen = set(); out=[]
    for c in cves:
        if c not in seen:
            seen.add(c); out.append(c)
    return out

def fetch_epss(cves):
    """Batch query EPSS; returns dict CVE -> (epss, percentile) as strings."""
    out = {}
    if not cves:
        return out
    # EPSS accepts comma-separated list; split into chunks to be safe
    CHUNK=200
    for i in range(0, len(cves), CHUNK):
        chunk = cves[i:i+CHUNK]
        url = f"{EPSS_API}?{urlencode({'cve': ','.join(chunk)})}"
        try:
            data = json.loads(_get(url))
            for row in data.get("data", []):
                cve = row.get("cve")
                out[cve] = (row.get("epss"), row.get("percentile"))
        except Exception:
            # leave missing entries blank
            pass
        time.sleep(0.2)
    return out

def fetch_kev_set():
    """Return a set of CVE IDs present in CISA KEV."""
    try:
        data = json.loads(_get(CISA_KEV))
        items = data.get("vulnerabilities", [])
        return {it.get("cveID") for it in items if it.get("cveID")}
    except Exception:
        return set()

def try_osv(cve):
    """Return (commit_url, has_exploitdb) from OSV references if present."""
    try:
        data = json.loads(_get(OSV_VULN + cve))
    except urllib.error.HTTPError as e:
        # 404 -> not in OSV; ignore
        return (None, False)
    except Exception:
        return (None, False)

    commit_url = None
    has_exploitdb = False
    for ref in data.get("references", []) or []:
        url = ref.get("url", "")
        typ = ref.get("type", "")
        if "exploit-db.com" in url:
            has_exploitdb = True
        # Prefer explicit FIX commits; then PRs; then any commit-ish link
        if not commit_url and ("github.com" in url):
            if "/commit/" in url and typ.upper() in ("FIX", "PATCH"):
                commit_url = url
            elif "/pull/" in url and typ.upper() in ("FIX", "PATCH"):
                commit_url = url

    # If we didn’t find a FIX-typed link, take any github commit/pull as a fallback.
    if not commit_url:
        for ref in data.get("references", []) or []:
            url = ref.get("url", "")
            if "github.com" in url and ("/commit/" in url or "/pull/" in url):
                commit_url = url
                break

    return (commit_url, has_exploitdb)

def try_nvd(cve):
    """Return (commit_url, has_exploitdb) from NVD references (fallback)."""
    params = urlencode({"cveId": cve})
    headers = {"User-Agent": "cve-enricher/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    commit_url = None
    has_exploitdb = False
    try:
        data = json.loads(_get(f"{NVD_V2}?{params}", headers=headers))
        for item in data.get("vulnerabilities", []):
            refs = item.get("cve", {}).get("references", [])
            for ref in refs:
                url = ref.get("url", "")
                tags = [t.lower() for t in (ref.get("tags") or [])]
                if "exploit-db.com" in url:
                    has_exploitdb = True
                is_fixish = any(t in ("patch","fix","vendor-advisory") for t in tags)
                if "github.com" in url and ("/commit/" in url or "/pull/" in url):
                    if is_fixish:
                        return (url, has_exploitdb)
                    if not commit_url:
                        commit_url = url
    except Exception:
        pass
    return (commit_url, has_exploitdb)


def run_cbt_enrichment(in_csv, out_csv):
    in_path = pathlib.Path(in_csv)
    

    cves = load_cves_from_csv(in_csv)
    if not cves:
        sys.exit(f"No CVEs found in {in_csv}")

    print(f"[info] CVEs to enrich: {len(cves)}")

    epss_map = fetch_epss(cves)
    kev_set  = fetch_kev_set()

    rows = []
    for cve in cves:
        epss, pct = epss_map.get(cve, (None, None))
        in_kev = "Yes" if cve in kev_set else "No"

        commit_url, has_exploitdb = try_osv(cve)
        if commit_url is None:
            # fallback to NVD
            nvd_commit, nvd_exdb = try_nvd(cve)
            commit_url = nvd_commit
            has_exploitdb = has_exploitdb or nvd_exdb

        rows.append({
            "cve_number": cve,
            "epss": "" if epss is None else epss,
            "epss_percentile": "" if pct is None else pct,
            "in_kev": in_kev,
            "exploitdb": "Yes" if has_exploitdb else "No",
            "git_commit_url": "" if commit_url is None else commit_url
        })
        # be nice to public APIs
        time.sleep(0.15)

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve_number","epss","epss_percentile","in_kev","exploitdb","git_commit_url"])
        w.writeheader()
        w.writerows(rows)

    print(f"[ok] wrote {out_csv} ({len(rows)} rows)")

def main():
    if len(sys.argv) > 1:
        in_csv = sys.argv[1]
    else:
        sys.exit("Usage: python cve-data-bin-tool.py <input_csv>")
    # Output: <input_dir>/<filename>-enriched.csv
    in_path = pathlib.Path(in_csv)
    out_csv = str(in_path.parent / f"{in_path.stem}-enriched.csv")

    cves = load_cves_from_csv(in_csv)
    if not cves:
        sys.exit(f"No CVEs found in {in_csv}")

    print(f"[info] CVEs to enrich: {len(cves)}")

    epss_map = fetch_epss(cves)
    kev_set  = fetch_kev_set()

    rows = []
    for cve in cves:
        epss, pct = epss_map.get(cve, (None, None))
        in_kev = "Yes" if cve in kev_set else "No"

        commit_url, has_exploitdb = try_osv(cve)
        if commit_url is None:
            # fallback to NVD
            nvd_commit, nvd_exdb = try_nvd(cve)
            commit_url = nvd_commit
            has_exploitdb = has_exploitdb or nvd_exdb

        rows.append({
            "cve_number": cve,
            "epss": "" if epss is None else epss,
            "epss_percentile": "" if pct is None else pct,
            "in_kev": in_kev,
            "exploitdb": "Yes" if has_exploitdb else "No",
            "git_commit_url": "" if commit_url is None else commit_url
        })
        # be nice to public APIs
        time.sleep(0.15)

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve_number","epss","epss_percentile","in_kev","exploitdb","git_commit_url"])
        w.writeheader()
        w.writerows(rows)

    print(f"[ok] wrote {out_csv} ({len(rows)} rows)")

if __name__ == "__main__":
    main()
