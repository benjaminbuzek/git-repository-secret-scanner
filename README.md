# 🐙 GIT-RS - Git Repository Secret Scanner

## General Information

The scanner uses predefined patterns that could indicate suspicious-looking information, which is further 
processed and filtered. Entropy calculation is applied to commit messages to determine "impurity" and skip general or 
known information.

**Table of Contents**
1. Installation
2. Scanner Usage Guide
3. Usage Example


## 1. Installation

### 1.1 Requirements

```
python version >= 3.10
pip version >= 22.3.1 
```

I recommend using pip for the installation of all dependencies that are used by this project. The `requirements.txt` file
contains all for GIT-RS required packages.

```
pip install -r requirements.txt
```

## 2. Scanner Usage Guide

### 2.1 Git Repositories

The scanner is able to handle any Git repositories. You can simply use your local Git repositories or repositories found on GitHub and co.

```shell
python3 gitrsscan.py -r <REPOSITORY-URL>
```

### 2.2 Scanner Arguments

The scanner uses several arguments that can be specified by the user to allow more targeted scans. For standard usage 
it is not necessary to specify all arguments for a scan since standard settings are in use.

```
ARGUMENT    ALIAS           DESCRIPTION
---------------------------------------
 -r         --repo          Git repository to scan
 -c         --count         Total number of commits to scan (default: all)
 -e         --entropy       Min entropy (default: 4.5); used for avoiding the scan of too similare commits
 -l         --length        Max line length (default: 500)
 -b         --branch        Branch to scan; only scan the specified branch
 -v         --verbose       Verbose output
```

### 2.3 General Config

In addition to the scanner arguments, several predefined file and file prefix settings are specified to be ignored by the scanner.
These ignored files and prefixes are stored in two files under `./config/<FILE-NAME>`.

If you want to add files to the scanner to be avoided for scanning, just add them in the appropriate file.

```shell
.
├── IGNORED_FILES
└── IGNORED_FILE_PREFIXES
```


### 2.4 Targets

`IMPORTANT:` The scanner does not download the remote repository every time it is scanned. If there is a local repository instance 
stored at `./target`, it will be preferred by the scanner. It is recommended to use the target folder for storing the repositories 
to be scanned.

If the specified repository does not exist in the destination folder, the program tries to clone the repository from the specified URL.




### 2.5 Logs

The scanner creates log files for each test. These files are stored in `./logs` with the timestamp when the test was performed.

## 3. Usage Example

### 3.1 Scan Example

For a default scan, use the following command with an arbitrary git repository.

```shell
python3 gitrsscan.py -r ./target/<REPOSITORY-NAME>
```

Here you can see an example output of the scanner. For privacy reasons the findings are concealed! 

```text
 Commit : origin/XXX/rack-2.2.3.1@b4e6d6ddeXXX
 Date   : 04/11/2021 13:42:52
 Author : XXX
 https://github.com/XXX
 + "integrity" "sha512-a7ZpuTZU1TRtnwXXX


 Commit : origin/XXX/rack-2.2.3.1@0f1d3b6fe9XXX
 Date   : 04/05/2021 08:39:27
 Author : XXX
 https://github.com/XXX/README.md
 + Get the IDs from https://XXX.com/developers/apps/XXX
```