#!/usr/bin/env python3
"""
Enrich Grype JSON (SBOM scan) with KEV, EPSS, Exploit-DB and patch/commit links.

Inputs:
  - grype JSON file produced by: grype sbom:<file> -o json > grype.json

Outputs:
  - enriched.json   (per-CVE objects)
  - enriched.csv    (flat table)

Optional:
  - If cve_searchsploit is installed, we add Exploit-DB IDs.

Refs:
  KEV JSON/CSV (CISA) ................ https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  EPSS API ........................... https://api.first.org/data/v1/epss
  NVD API 2.0 ........................ https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import argparse, csv, json, os, re, sys, time
from typing import Dict, List, Tuple, Optional
import requests
from tqdm import tqdm

# -----------------------
# Config
# -----------------------
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"  # fallback
# If CISA changes the path, see their KEV Catalog page for current CSV/JSON links.  :contentReference[oaicite:1]{index=1}
EPSS_API = "https://api.first.org/data/v1/epss"  # supports ?cve=CVE-1,CVE-2 batches  :contentReference[oaicite:2]{index=2}
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # ?cveId=CVE-YYYY-XXXX  :contentReference[oaicite:3]{index=3}
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
# Try optional Exploit-DB mapper
try:
    import cve_searchsploit as CS  # pip install cve_searchsploit  :contentReference[oaicite:4]{index=4}
    HAVE_CSS = True
except Exception:
    HAVE_CSS = False

GITHUB_COMMIT_RE = re.compile(r"https?://github\.com/[^/]+/[^/]+/(?:commit|pull)/[0-9a-fA-F]+", re.I)
OSV_API = "https://api.osv.dev/v1/vulns/"  # GET /v1/vulns/CVE-YYYY-NNNN

# -----------------------
# Helpers
# -----------------------



def fetch_osv(cve: str) -> dict:
    try:
        r = requests.get(OSV_API + cve, timeout=30)
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}
def nvd_details(cve: str) -> tuple[list[str], list[str], Optional[float], Optional[str], Optional[str]]:
    """
    Returns: (commit_links, patch_links, cvss_base, cvss_vector, cvss_version)
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    r = requests.get(NVD_API, params={"cveId": cve}, headers=headers, timeout=30)
    try:
        r = requests.get(NVD_API, params={"cveId": cve}, timeout=30)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        commit_links, patch_links = [], []
        cvss_base = None
        cvss_vector = None
        cvss_version = None

        for v in vulns:
            c = v.get("cve", {})
            # references
            refs = (c.get("references") or {}).get("referenceData") or []
            for ref in refs:
                url = ref.get("url", "")
                tags = ref.get("tags") or []
                if not url:
                    continue
                if ("commit" in url) or ("/pull/" in url) or url.endswith(".diff") or url.endswith(".patch"):
                    commit_links.append(url)
                if "Patch" in tags or "Vendor Advisory" in tags or url.endswith(".patch") or "diff" in url:
                    patch_links.append(url)

            # CVSS metrics (prefer v3.1, then v3.0, then v2)
            m = (c.get("metrics") or {})
            for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
                arr = m.get(key) or []
                if arr:
                    entry = arr[0]
                    data = entry.get("cvssData") or {}
                    cvss_base = data.get("baseScore")
                    cvss_vector = data.get("vectorString")
                    cvss_version = ver
                    break

        # de-dupe keep order
        def uniq(xs):
            s=set(); out=[]
            for x in xs:
                if x not in s: s.add(x); out.append(x)
            return out

        return uniq(commit_links), uniq(patch_links), cvss_base, cvss_vector, cvss_version
    except Exception:
        return [], [], None, None, None

def refs_from_osv(osv: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Return (commit_links, repo_urls, ghsa_ids) from OSV references.
    """
    commits, repos, ghsas = [], [], []
    for ref in osv.get("references", []) or []:
        url = ref.get("url", "")
        if not url:
            continue
        rtype = (ref.get("type") or "").upper()
        if rtype == "FIX" and ("commit" in url or "/pull/" in url or "diff" in url):
            commits.append(url)
        if rtype == "REPOSITORY":
            repos.append(url)
        if "github.com/advisories/GHSA-" in url:
            ghsas.append(url.rsplit("/", 1)[-1])  # keep GHSA-… id
    # uniq keep order
    def uniq(xs):
        s=set(); out=[]
        for x in xs:
            if x not in s: s.add(x); out.append(x)
        return out
    return uniq(commits), uniq(repos), uniq(ghsas)

def affected_versions_from_osv(osv: dict) -> tuple[list[str], list[str]]:
    """
    Collect introduced/fixed versions per affected package (flattened strings).
    """
    introduced, fixed = [], []
    for aff in osv.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            if (rng.get("type") or "").upper() in ("ECOSYSTEM","SEMVER","GIT"):
                for e in rng.get("events", []) or []:
                    if "introduced" in e and e["introduced"] not in ("0", ""):
                        introduced.append(e["introduced"])
                    if "fixed" in e and e["fixed"]:
                        fixed.append(e["fixed"])
    # uniq keep order
    def uniq(xs):
        s=set(); out=[]
        for x in xs:
            if x not in s: s.add(x); out.append(x)
        return out
    return uniq(introduced), uniq(fixed)

def read_grype_json(path: str) -> List[dict]:
    data = json.load(open(path, "r"))
    # Grype JSON top-level may be {"matches":[...]} or array; normalize to list of matches
    matches = data.get("matches", data if isinstance(data, list) else [])
    return matches

def extract_cves(matches: list[dict]) -> list[str]:
    """
    Collect CVE IDs from several locations:
      - vulnerability.id if already a CVE
      - relatedVulnerabilities[].id
      - vulnerability.knownExploited[].cve
      - vulnerability.epss[].cve
      - vulnerability.advisories[].id  (fallback)
    """
    cves = set()
    for m in matches:
        vuln = m.get("vulnerability") or {}
        # primary id
        vid = (vuln.get("id") or "").strip()
        if vid.startswith("CVE-"):
            cves.add(vid)

        # related CVEs (most important for GHSA→CVE mapping)
        for rv in m.get("relatedVulnerabilities") or []:
            rid = (rv.get("id") or "").strip()
            if rid.startswith("CVE-"):
                cves.add(rid)

        # KEV/EPSS blocks may carry CVE keys too
        for kev in vuln.get("knownExploited") or []:
            cid = (kev.get("cve") or "").strip()
            if cid.startswith("CVE-"):
                cves.add(cid)
        for e in vuln.get("epss") or []:
            cid = (e.get("cve") or "").strip()
            if cid.startswith("CVE-"):
                cves.add(cid)

        # advisories (rare in your sample, but keep for completeness)
        for adv in vuln.get("advisories") or []:
            aid = (adv.get("id") or "").strip()
            if aid.startswith("CVE-"):
                cves.add(aid)

    return sorted(cves)


def build_index_by_cve(matches: list[dict]) -> dict[str, list[dict]]:
    """
    Group all match records under each CVE we discover (same sources as above).
    """
    by: dict[str, list[dict]] = {}
    for m in matches:
        vuln = m.get("vulnerability") or {}

        def add(cve: str):
            if cve and cve.startswith("CVE-"):
                by.setdefault(cve, []).append(m)

        vid = (vuln.get("id") or "").strip()
        add(vid)

        for rv in m.get("relatedVulnerabilities") or []:
            add((rv.get("id") or "").strip())

        for kev in vuln.get("knownExploited") or []:
            add((kev.get("cve") or "").strip())

        for e in vuln.get("epss") or []:
            add((e.get("cve") or "").strip())

        for adv in vuln.get("advisories") or []:
            add((adv.get("id") or "").strip())

    # drop keys that aren’t CVEs (e.g., pure GHSA rows)
    return {k: v for k, v in by.items() if k.startswith("CVE-")}


def load_kev() -> Dict[str, dict]:
    """
    Return mapping {CVE-ID: record} from CISA KEV JSON.
    """
    try:
        r = requests.get(CISA_KEV_JSON, timeout=30)
        r.raise_for_status()
        obj = r.json()
        items = obj.get("vulnerabilities") or obj.get("known_exploited_vulnerabilities") or []
        kev = {}
        for it in items:
            cve = it.get("cveID") or it.get("cve", "")
            if cve:
                kev[cve] = it
        return kev
    except Exception as e:
        print(f"[warn] KEV fetch failed: {e}", file=sys.stderr)
        return {}

def fetch_epss(cves: List[str]) -> Dict[str, dict]:
    """
    Batch EPSS lookups; returns {CVE: {"epss": float, "percentile": float, "date": str}}
    """
    out = {}
    BATCH = 100
    for i in range(0, len(cves), BATCH):
        batch = cves[i:i+BATCH]
        params = {"cve": ",".join(batch)}
        try:
            r = requests.get(EPSS_API, params=params, timeout=30)
            r.raise_for_status()
            data = r.json().get("data", [])
            for row in data:
                # rows like {"cve":"CVE-XXXX","epss":"0.12345","percentile":"0.99","date":"YYYY-MM-DD"}
                cve = row.get("cve")
                if cve:
                    out[cve] = {
                        "epss": float(row.get("epss", 0.0)),
                        "percentile": float(row.get("percentile", 0.0)),
                        "date": row.get("date")
                    }
        except Exception as e:
            print(f"[warn] EPSS batch failed ({batch[0]}..): {e}", file=sys.stderr)
        time.sleep(0.2)  # be nice
    return out

def fetch_nvd_refs(cve: str) -> Tuple[List[str], List[str]]:
    """
    Ask NVD for a CVE and pull commit/PR/patch links from references.
    Returns (commit_like_urls, patch_like_urls)
    """
    try:
        r = requests.get(NVD_API, params={"cveId": cve}, timeout=30)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        commit_links, patch_links = [], []
        for v in vulns:
            refs = (((v.get("cve") or {}).get("references") or {})
                    .get("referenceData") or [])
            for ref in refs:
                url = ref.get("url", "")
                tags = ref.get("tags") or []
                if not url:
                    continue
                if GITHUB_COMMIT_RE.search(url) or "commit" in url or "/pull/" in url:
                    commit_links.append(url)
                if "Patch" in tags or "Vendor Advisory" in tags or "Release Notes" in tags or url.endswith(".patch") or "diff" in url:
                    patch_links.append(url)
        # dedup keep order
        def uniq(seq): 
            seen=set(); out=[] 
            for x in seq:
                if x not in seen:
                    out.append(x); seen.add(x)
            return out
        return uniq(commit_links), uniq(patch_links)
    except Exception as e:
        # Network or not found
        return [], []

def exploits_for_cve(cve: str) -> List[int]:
    if not HAVE_CSS:
        return []
    try:
        # ensure mapping DB is available (fast after first run)
        return CS.edbid_from_cve(cve) or []
    except Exception:
        return []

def flatten_row(
    cve: str, idxRow: List[dict], kev: dict, epss: dict,
    edb_ids: List[int],
    commits_nvd: List[str], patches_nvd: List[str],
    commits_osv: List[str], repos_osv: List[str], ghsa_ids: List[str],
    introduced_osv: List[str], fixed_osv: List[str],
    cvss_base: Optional[float], cvss_vector: Optional[str], cvss_version: Optional[str]
) -> dict:
    pkg = ""; ver = ""; sev = ""
    for m in idxRow or []:
        art = m.get("artifact") or {}
        pkg = art.get("name") or art.get("id") or pkg
        ver = art.get("version") or ver
        sev = (m.get("vulnerability") or {}).get("severity") or sev
        if pkg and ver and sev:
            break

    commit_links = list(dict.fromkeys((commits_nvd or []) + (commits_osv or [])))
    patch_links = list(dict.fromkeys(patches_nvd or []))
    edb_yes = bool(edb_ids)

    return {
        "cve": cve,
        "package": pkg,
        "version": ver,
        "severity": sev,
        # KEV/EPSS
        "kev": bool(kev),
        "kev_date_added": (kev or {}).get("dateAdded"),
        "epss": (epss or {}).get("epss"),
        "epss_percentile": (epss or {}).get("percentile"),
        # ExploitDB
        "exploitdb": "yes" if edb_yes else "no",
        "exploitdb_ids": ",".join(map(str, edb_ids)) if edb_ids else "",
        # Commits / patches
        "commit_links": " | ".join(commit_links[:8]),
        "patch_links": " | ".join(patch_links[:8]),
        "fix_commits": " | ".join(commits_osv[:8]),
        "repo_urls": " | ".join(repos_osv[:4]),
        "ghsa_ids": " | ".join(ghsa_ids[:6]),
        "introduced_versions": " | ".join(introduced_osv[:8]),
        "fixed_versions": " | ".join(fixed_osv[:8]),
        # CVSS
        "cvss_base": cvss_base,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
    }
def cvss_fallback_from_grype(idxRow):
    # look inside relatedVulnerabilities[].cvss where source == 'nvd@nist.gov'
    for m in idxRow or []:
        for rv in (m.get("relatedVulnerabilities") or []):
            for cv in (rv.get("cvss") or []):
                if (cv.get("source") or "").lower()=="nvd@nist.gov":
                    d = cv.get("metrics") or {}
                    return d.get("baseScore"), cv.get("vector"), cv.get("version")
    return None, None, None

def extract_flat_table(grype_json_path, out_csv_path):
    cols = [
        "vendor", "product", "version", "location", "cve_number", "severity",
        "score", "source", "cvss_version", "cvss_vector"
    ]
    data = json.load(open(grype_json_path, "r"))
    matches = data.get("matches", data if isinstance(data, list) else [])
    rows = []
    for m in matches:
        artifact = m.get("artifact", {})
        vuln = m.get("vulnerability", {})
        rel_vulns = m.get("relatedVulnerabilities", [])

        # Try to get CVE from relatedVulnerabilities, else from vulnerability.id if CVE
        cve_number = "unknown"
        for rv in rel_vulns:
            rid = (rv.get("id") or "").strip()
            if rid.startswith("CVE-"):
                cve_number = rid
                break
        if cve_number == "unknown":
            vid = (vuln.get("id") or "").strip()
            if vid.startswith("CVE-"):
                cve_number = vid

        # Severity
        severity = vuln.get("severity", "unknown")

        # CVSS details: prefer relatedVulnerabilities[].cvss where source == 'nvd@nist.gov'
        score = "unknown"
        source = "unknown"
        cvss_version = "unknown"
        cvss_vector = "unknown"
        found_cvss = False
        for rv in rel_vulns:
            for cv in rv.get("cvss", []):
                if (cv.get("source") or "").lower() == "nvd@nist.gov":
                    metrics = cv.get("metrics") or {}
                    score = metrics.get("baseScore", "unknown")
                    source = cv.get("source", "unknown")
                    cvss_version = cv.get("version", "unknown")
                    cvss_vector = cv.get("vector", "unknown")
                    found_cvss = True
                    break
            if found_cvss:
                break
        if not found_cvss:
            # fallback to vulnerability.cvss
            for cv in vuln.get("cvss", []):
                metrics = cv.get("metrics") or {}
                score = metrics.get("baseScore", "unknown")
                source = cv.get("source", "unknown")
                cvss_version = cv.get("version", "unknown")
                cvss_vector = cv.get("vector", "unknown")
                break

        # Product, version, location
        product = artifact.get("name", "unknown")
        version = artifact.get("version", "unknown")
        location = "NotFound"

        row = {
            "vendor": "unknown",
            "product": product,
            "version": version,
            "location": location,
            "cve_number": cve_number,
            "severity": severity,
            "score": score,
            "source": source,
            "cvss_version": cvss_version,
            "cvss_vector": cvss_vector,
        }
        rows.append(row)

    with open(out_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def run_main_enrichment(grype_json_path, out_prefix, flat_table=False):
    matches = read_grype_json(grype_json_path)
    cves = extract_cves(matches)
    if not cves:
        print("No CVEs found in grype JSON.", file=sys.stderr)
        sys.exit(2)

    print(f"[info] unique CVEs: {len(cves)}", file=sys.stderr)

    print("[info] loading KEV…", file=sys.stderr)
    kev_map = load_kev()

    print("[info] fetching EPSS (batched)…", file=sys.stderr)
    epss_map = fetch_epss(cves)

    idx = build_index_by_cve(matches)

    rows = []
    print("[info] enriching per-CVE…", file=sys.stderr)
    for cve in tqdm(cves):
        kev = kev_map.get(cve)
        epss = epss_map.get(cve)
        edb_ids = exploits_for_cve(cve)

        # NVD refs (commits/patches)
        commits_nvd, patches_nvd, cvss_base, cvss_vector, cvss_version = nvd_details(cve)
        if cvss_base is None:
            fb_base, fb_vec, fb_ver = cvss_fallback_from_grype(idx.get(cve, []))
            cvss_base = cvss_base or fb_base
            cvss_vector = cvss_vector or fb_vec
            cvss_version = cvss_version or fb_ver

        # 3) Deduplicate EDB IDs before passing to flatten_row()
        edb_ids = sorted(set(exploits_for_cve(cve)))
        # OSV refs + affected versions
        osv = fetch_osv(cve)
        commits_osv, repos_osv, ghsa_ids = refs_from_osv(osv)
        introduced_osv, fixed_osv = affected_versions_from_osv(osv)

        rows.append(flatten_row(
            cve, idx.get(cve, []), kev, epss, edb_ids,
            commits_nvd, patches_nvd,
            commits_osv, repos_osv, ghsa_ids,
            introduced_osv, fixed_osv,
            cvss_base, cvss_vector, cvss_version
        ))


    # write JSON
    json_path = f"{out_prefix}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(f"[ok] wrote {json_path}")

    # write CSV
    csv_path = f"{out_prefix}.csv"
    cols = [
            "cve","package","version","severity",
            "kev","kev_date_added",
            "epss","epss_percentile",
            "exploitdb","exploitdb_ids",
            "commit_links","patch_links","fix_commits",
            "repo_urls","ghsa_ids",
            "introduced_versions","fixed_versions",
            "cvss_base","cvss_vector","cvss_version"
            ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[ok] wrote {csv_path}")

    # write flat table CSV if requested
    if flat_table:
        extract_flat_table(grype_json_path, flat_table)
        print(f"[ok] wrote {flat_table}")

    return json_path, csv_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("grype_json", help="Path to grype JSON output")
    ap.add_argument("-o", "--out-prefix", default="enriched", help="Output prefix (default: enriched)")
    ap.add_argument("--flat-table", help="Output flat table CSV path (optional)")
    args = ap.parse_args()

    matches = read_grype_json(args.grype_json)
    cves = extract_cves(matches)
    if not cves:
        print("No CVEs found in grype JSON.", file=sys.stderr)
        sys.exit(2)

    print(f"[info] unique CVEs: {len(cves)}", file=sys.stderr)

    print("[info] loading KEV…", file=sys.stderr)
    kev_map = load_kev()

    print("[info] fetching EPSS (batched)…", file=sys.stderr)
    epss_map = fetch_epss(cves)

    idx = build_index_by_cve(matches)

    rows = []
    print("[info] enriching per-CVE…", file=sys.stderr)
    for cve in tqdm(cves):
        kev = kev_map.get(cve)
        epss = epss_map.get(cve)
        edb_ids = exploits_for_cve(cve)

        # NVD refs (commits/patches)
        commits_nvd, patches_nvd, cvss_base, cvss_vector, cvss_version = nvd_details(cve)
        if cvss_base is None:
            fb_base, fb_vec, fb_ver = cvss_fallback_from_grype(idx.get(cve, []))
            cvss_base = cvss_base or fb_base
            cvss_vector = cvss_vector or fb_vec
            cvss_version = cvss_version or fb_ver

        # 3) Deduplicate EDB IDs before passing to flatten_row()
        edb_ids = sorted(set(exploits_for_cve(cve)))
        # OSV refs + affected versions
        osv = fetch_osv(cve)
        commits_osv, repos_osv, ghsa_ids = refs_from_osv(osv)
        introduced_osv, fixed_osv = affected_versions_from_osv(osv)

        rows.append(flatten_row(
            cve, idx.get(cve, []), kev, epss, edb_ids,
            commits_nvd, patches_nvd,
            commits_osv, repos_osv, ghsa_ids,
            introduced_osv, fixed_osv,
            cvss_base, cvss_vector, cvss_version
        ))


    # write JSON
    json_path = f"{args.out_prefix}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(f"[ok] wrote {json_path}")

    # write CSV
    csv_path = f"{args.out_prefix}.csv"
    cols = [
            "cve","package","version","severity",
            "kev","kev_date_added",
            "epss","epss_percentile",
            "exploitdb","exploitdb_ids",
            "commit_links","patch_links","fix_commits",
            "repo_urls","ghsa_ids",
            "introduced_versions","fixed_versions",
            "cvss_base","cvss_vector","cvss_version"
            ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[ok] wrote {csv_path}")

    # write flat table CSV if requested
    if args.flat_table:
        extract_flat_table(args.grype_json, args.flat_table)
        print(f"[ok] wrote {args.flat_table}")

if __name__ == "__main__":
    main()
