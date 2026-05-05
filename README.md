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
1. Clone repos into their corresponding language directories manually or using the add_repos.sh script
2. Use validation tool to generate sboms pre build sboms (optional) https://github.com/damaoooo/validation?tab=readme-ov-file#usage-examples
3. Run reset_repos.sh if validation tool made any changes.
4. Use the build_repos.sh script to build repos or build repos manually.
5. Run generate_data.py to generate grype reports, cve_bin_tool reports, post build sboms and a csv that compares each sboms differences with eachother.


