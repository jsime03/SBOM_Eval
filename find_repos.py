import requests
import json
import time
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")
LANGUAGE = "typescript"
TOP_N = 50

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

def get_top_repos(language, n=10):
    url = "https://api.github.com/search/repositories"
    params = {
        "q": f"language:{language}",
        "sort": "stars",
        "order": "desc",
        "per_page": n
    }
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()["items"]

def get_sbom(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None  # Dependency graph not enabled
    else:
        response.raise_for_status()

def main():
    print(f"Fetching top {TOP_N} {LANGUAGE} repos...\n")
    repos = get_top_repos(LANGUAGE, TOP_N)
    hit_count = 0

    for repo in repos:
        owner = repo["owner"]["login"]
        name = repo["name"]
        stars = repo["stargazers_count"]

        print(f"⭐ {stars:,} | {owner}/{name}")
        try:
            sbom = get_sbom(owner, name)
        except Exception as e:
            print(f"  ❌ Error fetching SBOM for {owner}/{name}: {e}")
            continue

        if sbom:
            filename = f"sbom_{owner}_{name}.json"
            with open(filename, "w") as f:
                json.dump(sbom, f, indent=2)
            package_count = len(sbom.get("sbom", {}).get("packages", []))
            print(f"  ✅ SBOM saved to {filename} ({package_count} packages)\n")
            hit_count += 1
        else:
            print(f"  ❌ Dependency graph not enabled\n")

        # if hit_count >= 12:
        #     break

        time.sleep(0.5)  

    print(f"Total SBOMs found: {hit_count}")

if __name__ == "__main__":
    main()