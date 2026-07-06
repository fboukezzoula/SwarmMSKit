# GitHub Repository Cleanup Audit Tool

## 📌 Overview
This tool is designed to perform a **safe, non-destructive audit** of open Pull Requests (PRs) and feature branches across specific GitHub Enterprise repositories. 

The goal is to identify which branches can be merged safely, which are already obsolete, and which require manual conflict resolution before they can be integrated into the `main` branch.

**⚠️ Note: This script is a "Dry Run" tool. It does not perform any merges, deletes, or modifications to your remote repositories.**

---

## 🚀 Features
- **Targeted Scanning**: Audit only specific repositories defined in a scope file.
- **Enterprise Ready**: Supports GitHub Enterprise via `GH_HOST` configuration.
- **Conflict Detection**: Uses `git merge-tree` to simulate merges and detect conflicts without touching the working directory.
- **Status Classification**: Categorizes every PR into specific states (Clean, Conflict, Out of Date, etc.).
- **CSV Reporting**: Generates a comprehensive `audit_report.csv` for easy analysis.

---

## 🛠️ Prerequisites

Before running the script, ensure you have the following installed and configured:

1. **GitHub CLI (`gh`)**: 
   - [Installation Guide](https://cli.github.com/)
   - Authenticate your account: `gh auth login`
2. **Git**: Version **2.38 or higher** is recommended (required for the `merge-tree` simulation).
3. **Permissions**: You must have read access to the repositories and organizations being audited.

---

## ⚙️ Configuration

### 1. Script Settings (`git_audit.sh`)
Open `git_audit.sh` and update the following variables:
- `GH_HOST`: Your GitHub Enterprise domain (e.g., `github.yourcompany.com`).
- `MAIN_BRANCH`: The target base branch (usually `main` or `master`).

### 2. Defining the Scope (`scope.txt`)
Instead of scanning everything, this tool uses a `scope.txt` file to target specific repositories. Create a file named `scope.txt` in the same folder as the script and add the repositories you want to audit, one per line:

**Format:** `organization repository`

**Example `scope.txt`:**
```text
org-marketing repo-site-web
org-marketing repo-assets
org-tech repo-api-gateway
org-tech repo-auth-service
```

---

## 📖 Usage

1. **Give execution permissions to the script**:
   ```bash
   chmod +x git_audit.sh
   ```

2. **Run the audit**:
   ```bash
   ./git_audit.sh
   ```

3. **Review the results**:
   Open the generated `audit_report.csv` in your preferred spreadsheet software.

---

## 📊 Interpreting the Report

The report provides a `Status` and a recommended `Action_Required` for each PR:

| Status | Meaning | Recommended Action | Risk Level |
| :--- | :--- | :--- | :--- |
| **Already Merged** | The branch's changes are already present in `main`. | **Delete the branch** immediately. | 🟢 None |
| **Clean** | No conflicts; the branch is up-to-date with `main`. | **Merge the PR** and delete the branch. | 🟢 Low |
| **Out of Date** | No conflicts, but `main` has moved forward since the branch was created. | Perform a `git pull --rebase origin main` before merging. | 🟡 Medium |
| **Conflict** | Overlapping changes detected between the branch and `main`. | **Manual Intervention**: Developer must resolve conflicts and test. | 🔴 High |

---

## 🔄 Recommended Workflow for the Team

To clean up the repositories efficiently, we suggest the following order:

1. **Quick Wins**: Process all **"Already Merged"** branches first.
2. **Easy Merges**: Process **"Clean"** PRs via the GitHub UI.
3. **Updates**: For **"Out of Date"** branches, notify the PR author to rebase their branch against `main`.
4. **Complex Cases**: For **"Conflict"** status, assign the PR back to the original developer for manual resolution.

---

## 🛡️ Safety Disclaimer
This script operates in temporary directories and uses simulation commands. It does not push any code or delete any branches. However, always ensure you have a backup or a clear understanding of the branch's purpose before performing the final manual deletions/merges based on the report.
