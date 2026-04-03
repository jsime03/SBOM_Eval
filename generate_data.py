import os
import pathlib
import subprocess
from pathlib import Path
import json
import pandas as pd
import validation.sbom as sbom
import traceback
import numpy as np
from itertools import combinations
from typing import Tuple
from sbomCVE.src.cve_data_grype import run_main_enrichment
from sbomCVE.src.cve_data_bin_tool import run_cbt_enrichment
from enum import Enum

REPO_DIR = Path("repos")
SBOM_DIR = Path("sboms")
CVE_BIN_TOOL_REPORTS = Path("cve_bin_tool_reports")
GRYPE_REPORTS = Path("grype_reports")
LANGUAGES = ['python', 'rust', 'javascript', 'ruby', 'php', 'go', 'other']
RESULTS_CSV = Path("comparisons.csv")




def compare(fileone, filetwo, diff_path, save=True) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    # Compare SBOMs
    sbom1 = sbom.parse_spdx(fileone)
    sbom2 = sbom.parse_spdx(filetwo)
    try:
        left, right, common = sbom.analyze_difference(sbom1, sbom2)
    except Exception as e:
        print(f"Error comparing SBOMs: {e}, for {fileone} and {filetwo}")
        traceback.print_exc()
        return None, None, None

    def pandas_save_json(df: pd.DataFrame):
        # save the result as {"left": [], "right": [], "common": []}
        # convert the dataframe to list of dict
        result = df.to_dict(orient="records")
        return result
    
    full_json = {
        "left": pandas_save_json(left),
        "Left count": left.shape[0],
        "right": pandas_save_json(right),
        "Right count": right.shape[0],
        "common": pandas_save_json(common),
        "Common count": common.shape[0],
        "fileone": (str(fileone)),
        "filetwo": str(filetwo)
    }
    diff_name = f"{fileone.stem}_vs_{filetwo.stem}.json"
    with open(os.path.join(diff_path, diff_name), "w") as f:
        json.dump(full_json, f, indent=4)


    return left, right, common



def generate_sboms():
    print("Generating SBOMs for repositories...")
    for language in REPO_DIR.iterdir():
        if language.is_dir() and language.name in LANGUAGES:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                if repo.is_dir():
                    print(f"Generating SBOM for {repo.name}...")
                    raw_output_dir = SBOM_DIR / language.name / repo.name / "raw"
                    if not raw_output_dir.exists():
                        raw_output_dir.mkdir(parents=True, exist_ok=True)
                    output_file = raw_output_dir / f"{repo.name}.spdx.json"
                    if output_file.exists():
                        print(f"SBOM for {repo.name} already exists. Skipping...")
                        continue
                    else:
                        try:
                            env = None
                            if language.name == 'python':
                                venv = repo / '.venv'
                                if venv.exists():
                                    env = {**os.environ, 'VIRTUAL_ENV': str(venv), 'PATH': str(venv / 'bin') + ':' + os.environ['PATH']}
                            subprocess.run(['syft', f'dir:{repo}', '-o', 'spdx-json', '-q', '--file', str(output_file)], check=True, env=env)
                            print(f"SBOM for {repo.name} generated successfully.")
                            sbom.format_json(output_file)
                        except Exception as e:
                            print(f"Error generating SBOM for {repo.name}: {e}")

def run_vulnerabillity_scans():
    print("Running vulnerability scans for SBOMs...")
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in LANGUAGES:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                for raw in repo.iterdir():
                    if raw.is_dir() and raw.name == "raw":
                        print(f"Raw Dir found for {repo.name}. Running vulnerability scans...")
                        for sbom in raw.iterdir():
                            print(sbom.is_file(), sbom.suffix)
                            if sbom.is_file() and sbom.suffix == '.json':
                                print(f"Running Grype vulnerabliity scan for {sbom.name}...")
                                grype_output_file = GRYPE_REPORTS / f"{sbom.stem}_grype_report.json"
                                cbt_output_file = CVE_BIN_TOOL_REPORTS / f"{sbom.stem}_cve_bin_tool_report.csv"
                                if grype_output_file.exists():
                                    print(f"Grype report for {sbom.name} already exists. Skipping...")
                                    continue
                                else:
                                    try: 
                                        #grype sbom:sboms/django.spdx.pure.json -o json > cve-reports/grype-cve-django.json
                                        subprocess.run(['grype', f'sbom:{sbom}', '-o', 'json', '--file', str(grype_output_file)], check=True)
                                        print(f"Grype report for {sbom.name} generated successfully.")                    
                                    except Exception as e:
                                        print(f"Error enriching Grype report for {sbom.name}: {e}")

                                    try:
                                        run_main_enrichment(str(grype_output_file), f"{GRYPE_REPORTS}/{grype_output_file.stem}_enriched")
                                        print("Grype report enriched successfully.")

                                    except (Exception, SystemExit) as e:
                                        print(f"Error enriching Grype report for {sbom.name}: {e}")
                                    
                                    try:
                                        subprocess.run(['cve-bin-tool', '--sbom', 'spdx', '--sbom-file', str(sbom), '-f', 'csv', '-o', str(cbt_output_file)], check=True)
                                        print(f"CVE Bin Tool report for {sbom.name} generated successfully.")

                                    except Exception as e:
                                        print(f"Error generating CVE Bin Tool report for {sbom.name}: {e}")

                                    try:
                                        run_cbt_enrichment(f"{str(cbt_output_file)}.csv", f"{CVE_BIN_TOOL_REPORTS}/{cbt_output_file.stem}_enriched.csv")
                                        print("CVE Bin Tool report enriched successfully.")

                                    except Exception as e:
                                        print(f"Error enriching CVE Bin Tool report for {sbom.name}: {e}")


def run_comparisons():
    print("Comparing SBOMs for repositories...")
    df = pd.DataFrame(columns=["Repo", "File One", "File Two", "Left Count", "Right Count", "Common Count", "Jaccard Score"])
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in LANGUAGES:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                for raw in repo.iterdir():
                    if raw.is_dir() and raw.name == "raw":
                        print(f"Raw Dir found for {repo.name}. Comparing SBOMs...")
                        sbom_files = list(raw.glob("*.json"))
                        if len(sbom_files) < 2:
                            print(f"Not enough SBOM files to compare for {repo.name}. Skipping...")
                            continue
                        diff_path = repo / "diff"
                        if not diff_path.exists():
                            diff_path.mkdir(parents=True, exist_ok=True)
                        for fileone, filetwo in combinations(sbom_files, 2):
                            left, right, common = compare(fileone, filetwo, diff_path)
                            jaccard = len(common) / (len(left) + len(right) + len(common)) if (len(left) + len(right) + len(common)) > 0 else 1
                            row = pd.DataFrame([{
                                "Repo": repo.name,
                                "File One": fileone.name,
                                "File Two": filetwo.name,
                                "Left Count": len(left),
                                "Right Count": len(right),
                                "Common Count": len(common),
                                "Jaccard Score": jaccard
                            }])
                            df = pd.concat([df, row], ignore_index=True)
    df.to_csv(RESULTS_CSV, index=False)



def reset_sboms():
    print("Deleting SBOMs for repositories...")
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in LANGUAGES:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                if repo.is_dir():
                    raw_output_dir = repo / "raw"
                    output_file = raw_output_dir / f"{repo.name}.spdx.json"
                    if output_file.exists():
                        print(f"SBOM for {repo.name} located. Deleting...")
                        os.remove(output_file)

                    diff_dir = repo / "diff"
                    if diff_dir.exists():
                        for diff_file in diff_dir.glob("*.json"):
                            print(f"Deleting diff file {diff_file.name}...")
                            diff_file.unlink()

def reset_vulnerability_reports():
    print("Deleting vulnerability reports for SBOMs...")
    for report in GRYPE_REPORTS.glob("*.json"):
        print(f"Deleting Grype report {report.name}...")
        report.unlink()
    for report in CVE_BIN_TOOL_REPORTS.glob("*.csv"):
        print(f"Deleting CVE Bin Tool report {report.name}...")
        report.unlink()


def format_sboms():
    print("Formatting SBOMs for repositories...")
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in LANGUAGES:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                for raw in repo.iterdir():
                    if raw.is_dir() and raw.name == "raw":
                        print(f"Raw Dir found for {repo.name}. Formatting SBOMs...")
                        sbom_files = list(raw.glob("*.json"))
                        for sbom_file in sbom_files:
                            sbom.format_json(sbom_file)




def main():
    # reset_sboms()
    # reset_vulnerability_reports()
    # generate_sboms()
    format_sboms()
    # run_vulnerabillity_scans()
    # run_comparisons()

if __name__ == "__main__":
    main()



