# Files
-------------------------------------------------------------------------------------
### generate_data.py:
```
- Generates sboms for the repos located in the repos directory
- Generates Grype reports and CVE-Bin-Tool reports using the previously generated repos
- Generates a comparison.csv file that shows the differences between sboms generated from github site, validation repo, and local build sboms.
- If -r is passed as a command line argument, the script will reset the vulnerability report directories along with the sboms generated ONLY from this script.
- You may also pass -l <comma separated list of languages> that you want processed from the repos dir. The default is every language.
NOTE: The comparison tool is dependent on the validation tool, therefore the validation tool is expected to be cloned in the top level directory. https://github.com/damaoooo/validation?tab=readme-ov-file#usage-examples
```

### build_repos.sh:
```
- A general use build file that builds the repos in the repos directory according to their main language.
NOTE: If a repo contains project files from multiple languages, only the project file that corresponds to the language directory that the repo is in will be built. In other words, if it contains multiple project files from different languages, the remaining languages that aren't caught in this script will have to be manually built or you can move the repo to the directory of the project language you want built. Its best to try and find repos where only one language is present.
NOTE: build_repos is intended to build repos with one type of project file. Therefore, it is possible that the script may not work for repos that have project files not listed in the script or have more than one project file.
```

### find_repos.py:
```
- Finds the most popular repos according to their main language they are written in
- Checks if the repo has dependency grpah enabled
    - If dependency graph is enabled, the repos sbom is downloaded.
```

### add_repos.sh:
```
- adds the repos listed in the script to the repos dir according to their language
```

### reset_repos.sh:
```
- Resets repos to their fresh states if anything was changed in them
```





# File Structure
--------------------------
### sbom directory should have the following file structure:
```
sboms/
├── javascript/
│   ├── diff/
│   └── raw/
└── python/
    ├── diff/
    └── raw/
```
The general structure is 
```
sboms/
└── <language>/
    ├── diff/
    └── raw/
```

### Repo Directory should have the following file structure:

```
repos/
|--<languages>/
|    |--<repo>/
```


# Workflow
```
1. Clone this repo
2. Clone validation repo in the same dir as SBOM_Eval https://github.com/damaoooo/validation?tab=readme-ov-file#usage-examples 
    NOTE: generate_data.py uses some of the functions from the validation repo, and you will have to make the following change in the sbom.py file of the validation repo if you want to run generate_data.py:
    On line 9 of sbom.py change "from utils import SBOMStandard" -> "from .utils import SBOMStandard"
3. Create .venv and install requirements listed in requirements.txt
4. Add any repo that you want to evaluate to the list of repos in the add_repos.sh script and then run add_repos.sh or you can manually clone repos that you want and build file structure in sbom dir (refer to the previous section for expected file structure).
    NOTE: You must add your github token to .env before you run add_repos.sh.
5. Run build_repos.sh
6. Run generate_data.py
```

# List of Repos evaluated:
## javascript/typescript
```
30-seconds-of-code
GitNexus
ant-design
axios
chromecasts
cline
developer-roadmap
dify
docusaurus
echarts
eslint-plugin-graphql
everything-claude-code
excalidraw
immich
iptv
javascript
material-ui
n8n
openclaw
page-agent
promptfoo
react
supermemory
three.js
ui
vscode
vue
```

## Python:

```
AstrBot
ComfyUI
Deep-Live-Cam
LlamaFactory
Python
ai-hedge-fund
ansible
awesome-llm-apps
browser-use
code-graph-rag
core
django
fast-graphrag
fastapi
flask
gpt4free
manim
mindsdb
newton
sherlock
spec-kit
system-design-primer
transformers
whisper
yt-dlp

```

