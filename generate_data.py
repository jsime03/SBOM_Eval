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
from typing import List, Tuple
from cve_data_grype import run_main_enrichment
from cve_data_bin_tool import run_cbt_enrichment
from enum import Enum
import sys
import typer

REPO_DIR = Path("repos")
SBOM_DIR = Path("sboms")
CVE_BIN_TOOL_REPORTS = Path("cve_bin_tool_reports")
GRYPE_REPORTS = Path("grype_reports")
LANGUAGES = ['python', 'rust', 'javascript', 'ruby', 'php', 'go', 'other']
RESULTS_CSV = Path("comparisons.csv")
TEST_DIR = Path("test_dir")




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



def generate_sboms(language_list: list = None):
    langs = language_list or LANGUAGES
    print("Generating SBOMs for repositories...")
    for language in REPO_DIR.iterdir():
        if language.is_dir() and language.name in langs:
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
                            elif language.name == 'javascript':
                                env = {**os.environ, 'SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES': 'true'}
                                subprocess.run(['syft', f'dir:{repo}', '-o', 'spdx-json', '-q', '--file', str(output_file)], check=True, env=env)
                            else:
                                subprocess.run(['syft', f'dir:{repo}', '-o', 'spdx-json', '-q', '--file', str(output_file)], check=True, env=env)
                            print(f"SBOM for {repo.name} generated successfully.")
                            sbom.format_json(output_file)
                        except Exception as e:
                            print(f"Error generating SBOM for {repo.name}: {e}")


def run_vulnerabillity_scans(language_list: list = None):
    langs = language_list or LANGUAGES
    print("Running vulnerability scans for SBOMs...")
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in langs:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                for raw in repo.iterdir():
                    if raw.is_dir() and raw.name == "raw":
                        print(f"Raw Dir found for {repo.name}. Running vulnerability scans...")
                        for sbom in raw.iterdir():
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
                                        run_main_enrichment(str(grype_output_file), f"{GRYPE_REPORTS}/{grype_output_file.stem}_enriched") if not (GRYPE_REPORTS / f"{grype_output_file.stem}_enriched.json").exists() else print(f"Grype report for {sbom.name} already enriched. Skipping...")
                                        print("Grype report enriched successfully.")

                                    except (Exception, SystemExit) as e:
                                        print(f"Error enriching Grype report for {sbom.name}: {e}")
                                    
                                    try:
                                        subprocess.run(['cve-bin-tool', '--sbom', 'spdx', '--sbom-file', str(sbom), '-f', 'csv', '-o', str(cbt_output_file)], check=True) if not cbt_output_file.exists() else print(f"CVE Bin Tool report for {sbom.name} already exists. Skipping...")
                                        print(f"CVE Bin Tool report for {sbom.name} generated successfully.")

                                    except Exception as e:
                                        print(f"Error generating CVE Bin Tool report for {sbom.name}: {e}")

                                    try:
                                        run_cbt_enrichment(f"{str(cbt_output_file)}.csv", f"{CVE_BIN_TOOL_REPORTS}/{cbt_output_file.stem}_enriched.csv") if not (CVE_BIN_TOOL_REPORTS / f"{cbt_output_file.stem}_enriched.csv").exists() else print(f"CVE Bin Tool report for {sbom.name} already enriched. Skipping...")
                                        print("CVE Bin Tool report enriched successfully.")

                                    except Exception as e:
                                        print(f"Error enriching CVE Bin Tool report for {sbom.name}: {e}")


def run_comparisons(language_list: list = None):
    langs = language_list or LANGUAGES
    print("Comparing SBOMs for repositories...")
    df = pd.DataFrame(columns=["Repo", "File One", "File Two", "Left Count", "Right Count", "Common Count", "Jaccard Score"])
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in langs:
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

def format_sboms(language_list: list = None):
    langs = language_list or LANGUAGES
    print("Formatting SBOMs for repositories...")
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in langs:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                for raw in repo.iterdir():
                    if raw.is_dir() and raw.name == "raw":
                        print(f"Raw Dir found for {repo.name}. Formatting SBOMs...")
                        sbom_files = list(raw.glob("*.json"))
                        for sbom_file in sbom_files:
                            format_json(sbom_file)

def format_json(input_path: str, output_path: str = None, indent: int = 4):
    """
    Reads a JSON file, formats it with indentation, and saves to a new file.

    Args:
        input_path (str): Path to the input JSON file.
        output_path (str): Path to the output JSON file.
        indent (int): Number of spaces for indentation. Default is 4.
    """

    if output_path is None:
        output_path = input_path

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, dict) and list(data.keys()) == ["sbom"]:
        data = data["sbom"]

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)

def test_javascript_sbom_generation():
    for file in TEST_DIR.glob('*.json'):
        try:
            format_json(file)
            print(f"Formatted {file.name} successfully.")
        except Exception as e:
            print(f"Error formatting {file.name}: {e}")
    sbom_files = list(TEST_DIR.glob("*.json"))
    df = pd.DataFrame(columns=["File One", "File Two", "Left Count", "Right Count", "Common Count", "Jaccard Score"])
    for fileone, filetwo in combinations(sbom_files, 2):
        left, right, common = compare(fileone, filetwo, TEST_DIR)
        jaccard = len(common) / (len(left) + len(right) + len(common)) if (len(left) + len(right) + len(common)) > 0 else 1
        row = pd.DataFrame([{
            "File One": fileone.name,
            "File Two": filetwo.name,
            "Left Count": len(left),
            "Right Count": len(right),
            "Common Count": len(common),
            "Jaccard Score": jaccard
        }])
        df = pd.concat([df, row], ignore_index=True)
    df.to_csv(TEST_DIR / "comparison_results.csv", index=False)

def reset_language_files(language_list: list):
    for language in SBOM_DIR.iterdir():
        if language.is_dir() and language.name in language_list:
            print(f"Processing language: {language.name}")
            for repo in language.iterdir():
                if repo.is_dir():
                    output_file = SBOM_DIR / language.name / repo.name / "raw" / f"{repo.name}.spdx.json"
                    if output_file.exists():
                        print(f"Resetting SBOM for {repo.name}. Deleting...")
                        os.remove(output_file)
                    else:
                        print(f"No SBOM found for {repo.name}. Skipping...")

                    for raw in repo.iterdir():
                        if raw.is_dir() and raw.name == "raw":
                            for sbom_file in raw.iterdir():
                                if sbom_file.is_file() and sbom_file.suffix == '.json':
                                    grype_output_file = GRYPE_REPORTS / f"{sbom_file.stem}_grype_report.json"
                                    cbt_output_file = CVE_BIN_TOOL_REPORTS / f"{sbom_file.stem}_cve_bin_tool_report.csv"
                                    if grype_output_file.exists():
                                        print(f"Deleting Grype report for {sbom_file.name}...")
                                        os.remove(grype_output_file)
                                    if cbt_output_file.exists():
                                        print(f"Deleting CVE Bin Tool report for {sbom_file.name}...")
                                        os.remove(cbt_output_file)
                                    enriched_cbt = CVE_BIN_TOOL_REPORTS / f"{cbt_output_file.stem}_enriched.csv"
                                    if enriched_cbt.exists():
                                        print(f"Deleting enriched CVE Bin Tool report for {sbom_file.name}...")
                                        os.remove(enriched_cbt)
                                    enriched_grype = GRYPE_REPORTS / f"{grype_output_file.stem}_enriched.json"
                                    if enriched_grype.exists():
                                        print(f"Deleting enriched Grype report for {sbom_file.name}...")
                                        os.remove(enriched_grype)


def main(reset: bool = typer.Option(False, '-r', '--reset', help="Reset SBOMS and vulnerability reports before generating new data."), language: List[str] = typer.Option(None, '-l', '--language', help="Specify a language to reset and regenerate data for (e.g. python, javascript). If not specified, all languages will be processed.")):
    if reset:
        reset_sboms()
        reset_vulnerability_reports()
    if language:
        reset_language_files(language_list=language)
    generate_sboms(language_list=language or None)
    format_sboms(language_list=language or None)
    run_vulnerabillity_scans(language_list=language or None)
    run_comparisons()

if __name__ == "__main__":
    typer.run(main)



