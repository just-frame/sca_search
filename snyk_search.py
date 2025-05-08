import pandas as pd
import requests
from bs4 import BeautifulSoup
from packaging import version as pkg_version
import re
from packaging.version import InvalidVersion, Version

def is_version_affected(affects_str, user_version):
    v = pkg_version.parse(user_version)
    # Patterns for different version range formats
    patterns = [
        (r'<\s*([0-9a-zA-Z\.\-]+)', lambda bound: v < pkg_version.parse(bound)),
        (r'<=\s*([0-9a-zA-Z\.\-]+)', lambda bound: v <= pkg_version.parse(bound)),
        (r'>\s*([0-9a-zA-Z\.\-]+)', lambda bound: v > pkg_version.parse(bound)),
        (r'>=\s*([0-9a-zA-Z\.\-]+)', lambda bound: v >= pkg_version.parse(bound)),
        (r'\[([0-9a-zA-Z\.\-]+),([0-9a-zA-Z\.\-]+)\)', lambda lower, upper: pkg_version.parse(lower) <= v < pkg_version.parse(upper)),
        (r'\[([0-9a-zA-Z\.\-]+),([0-9a-zA-Z\.\-]+)\]', lambda lower, upper: pkg_version.parse(lower) <= v <= pkg_version.parse(upper)),
        (r'([0-9a-zA-Z\.\-]+)', lambda bound: v == pkg_version.parse(bound)),
    ]
    for pattern, check in patterns:
        for match in re.finditer(pattern, affects_str):
            try:
                if len(match.groups()) == 1:
                    if check(match.group(1)):
                        return True
                elif len(match.groups()) == 2:
                    if check(match.group(1), match.group(2)):
                        return True
            except Exception:
                continue
    return False

def search_snyk_for_library(lib, ver, ecosystem="swift"):
    """
    Search Snyk for a library and version, and print if there are vulnerabilities for the exact version,
    lower, or higher versions. If not found, print that the library is not found on Snyk.
    """
    try:
        _ = Version(ver)
    except InvalidVersion:
        return f'Invalid version: {ver}'
    def normalize_name(name):
        return name.lower().replace('_', '-').replace(' ', '-')

    lib_variants = [lib, normalize_name(lib)]
    found_any = False
    affected_vulns = []
    for lib_name in lib_variants:
        if ecosystem == "swift":
            url = f"https://security.snyk.io/vuln/swift?search={lib_name}"
        else:
            url = f"https://security.snyk.io/vuln/?search={lib_name}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Find the table with the right headers
        for table in soup.find_all('table'):
            headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]
            if 'affects' in headers and 'vulnerability' in headers:
                for row in table.find_all('tr'):
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        vuln_title = cells[0].get_text(strip=True)
                        affects = cells[1].get_text(separator=' ', strip=True)
                        # Uncomment for debugging:
                        # print(f"DEBUG: {vuln_title} | {affects}")
                        if is_version_affected(affects, ver):
                            affected_vulns.append((vuln_title, affects))
                            found_any = True
        if found_any:
            break
    if affected_vulns:
        print(f"{lib} {ver}: Vulnerabilities found for this version:")
        for title, affects in affected_vulns:
            print(f"  - {title} (Affects: {affects})")
        return 'Vulnerabilities found for this version.'
    else:
        print(f"{lib} {ver}: No vulnerabilities found for this version.")
        return 'No vulnerabilities found for this version.'

def main():
    mode = input("Type 'excel' to process the Excel file, or 'manual' to enter a library and version: ").strip().lower()
    ecosystem = input("Enter ecosystem (e.g., 'swift', 'all', 'npm', 'pip', etc.): ").strip().lower()
    if mode == 'manual':
        lib = input("Enter library name: ").strip()
        ver = input("Enter version: ").strip()
        search_snyk_for_library(lib, ver, ecosystem=ecosystem)
    else:
        df = pd.read_excel('test.xlsx', header=8)
        df['Snyk Vulnerability'] = ''
        for idx, row in df.iterrows():
            lib = str(row['Library']).strip()
            ver = str(row['Version']).strip()
            if not lib or not ver:
                df.at[idx, 'Snyk Vulnerability'] = 'Missing data'
                continue
            result = search_snyk_for_library(lib, ver, ecosystem=ecosystem)
            df.at[idx, 'Snyk Vulnerability'] = result
        df.to_excel('output_with_vulns.xlsx', index=False)

if __name__ == "__main__":
    main()
