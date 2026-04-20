# Files
```
-------------------------------------------------------------------------------------
### generate_data.py:
```
- Generates sboms for the repos located in the repos directory
- Generates Grype reports and CVE-Bin-Tool reports using the previously generated repos
- Generates a comparison.csv file that shows the differences between sboms generated from github site, validation repo, and local build sboms.
- If -r is passed as a command line argument, the script will reset the vulnerability report directories along with the sboms generated ONLY from this script.
``` 


### File Structure
--------------------------
sbom directory should have the following file structure:
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

Repo Directory should have the following file structure:

```
repos/
|--<languages>/
|    |--<repos>/
```
