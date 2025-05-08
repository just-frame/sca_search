# sca_search
# Snyk Vulnerability Search Tool

This tool allows you to search for vulnerabilities in open source libraries using the Snyk public vulnerability database. You can check vulnerabilities for a specific library and version, either manually or in bulk using an Excel file.

## Features
- **Manual Search:** Enter a library name and version to check for vulnerabilities interactively.
- **Excel Bulk Search:** Process an Excel file containing a list of libraries and versions, and output the results to a new Excel file.
- **Ecosystem Selection:** Choose the package ecosystem (e.g., `swift`, `npm`, `pip`, `all`, etc.) for more accurate results.
- **Robust Version Handling:** Handles version ranges and skips invalid version strings gracefully.

## Setup
1. Clone this repository.
2. Install dependencies:
   ```bash
   pip install pandas requests beautifulsoup4 packaging openpyxl
   ```
3. Place your Excel file (e.g., `test.xlsx`) in the project directory. The file should have columns named `Library` and `Version` (header row at line 9, i.e., Excel row 10).

## Usage
Run the script:
```bash
python snyk_search.py
```

You will be prompted to choose a mode:
- Type `manual` to enter a library and version interactively.
- Type `excel` to process all rows in your Excel file.

You will also be prompted to enter the ecosystem (e.g., `swift`, `npm`, `pip`, `all`, etc.).

### Manual Example
```
Type 'excel' to process the Excel file, or 'manual' to enter a library and version: manual
Enter ecosystem (e.g., 'swift', 'all', 'npm', 'pip', etc.): swift
Enter library name: yyjson
Enter version: 0.8.9
```

### Excel Example
```
Type 'excel' to process the Excel file, or 'manual' to enter a library and version: excel
Enter ecosystem (e.g., 'swift', 'all', 'npm', 'pip', etc.): swift
```
- Results will be saved to `output_with_vulns.xlsx`.

## Notes
- The tool scrapes the Snyk public website and may break if the site structure changes.
- Only valid version strings are processed; invalid versions are marked in the output.
- Ecosystem selection ensures more relevant results (e.g., `swift` for Swift packages).

## Development
Development will continue intermittently. Contributions and suggestions are welcome!
