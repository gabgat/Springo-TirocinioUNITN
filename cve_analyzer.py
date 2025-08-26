import requests
import os
import json
import re
from dotenv import load_dotenv
import time
from urllib.parse import quote
from packaging import version
from printer import printerr, printwarn, printout


class CVEChecker:
    def __init__(self, output_dir):
        load_dotenv()
        self.api_key = os.getenv('CIRCL_API_KEY')
        self.base_url = "https://vulnerability.circl.lu/api"
        self.request_delay = 1.0

        os.makedirs(os.path.join(output_dir, "reports"), exist_ok=True)
        self.output_file = os.path.join(output_dir, "reports", "cves.json")

        self.session = requests.Session()
        self.session.headers.update({
            'accept': 'application/json',
            'User-Agent': 'CVE-Checker/1.0',
            **({'X-API-KEY': self.api_key} if self.api_key else {})
        })

        self.stats = {'products_found': 0, 'api_requests': 0, 'cves_found': 0, 'cves_filtered': 0, 'cvss_medium': 0.0,
                      'errors': 0}

    def normalize_version(self, v):
        if not v or not str(v).strip():
            return None
        clean = re.sub(r'^[vV]|p\d+$|[-+].*$', '', str(v).strip())
        try:
            return version.parse(clean)
        except:
            parts = re.findall(r'\d+', clean)
            try:
                return version.parse('.'.join(parts[:3])) if parts else None
            except:
                return None

    def version_affected(self, target, constraint_text, description=""):
        target_ver = self.normalize_version(target)
        if not target_ver:
            return True

        text = constraint_text.lower() if constraint_text else ""
        desc = description.lower() if description else ""

        # If constraint is n/a, parse description
        if text in ['n/a', 'unknown', '*', '']:
            if not desc:
                return True  # No info = assume affected (conservative approach)
            text = desc

        # Parse version patterns
        patterns = [
            (r'(\d+(?:\.\d+)*(?:p\d+)?)\s+and\s+earlier', lambda m: target_ver <= self.normalize_version(m[1])),
            (r'before\s+(\d+(?:\.\d+)*(?:p\d+)?)', lambda m: target_ver < self.normalize_version(m[1])),
            (r'(\d+(?:\.\d+)*(?:p\d+)?)\s+and\s+(?:later|newer)', lambda m: target_ver >= self.normalize_version(m[1])),
            (r'since\s+(\d+(?:\.\d+)*(?:p\d+)?)', lambda m: target_ver >= self.normalize_version(m[1])),
            (r'up\s+to\s+(\d+(?:\.\d+)*(?:p\d+)?)', lambda m: target_ver <= self.normalize_version(m[1])),
            (r'prior\s+to\s+(\d+(?:\.\d+)*(?:p\d+)?)', lambda m: target_ver < self.normalize_version(m[1])),
            (r'(\d+(?:\.\d+)*(?:p\d+)?)\s+(?:through|to)\s+(\d+(?:\.\d+)*(?:p\d+)?)',
             lambda m: self.normalize_version(m[1]) <= target_ver <= self.normalize_version(m[2])),
            # Add pattern for exact version mentions
            (r'in\s+(?:version\s+)?(\d+(?:\.\d+)*(?:p\d+)?)', lambda m: target_ver == self.normalize_version(m[1])),
        ]

        for pattern, check in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    result = check(match.groups()) if self.normalize_version(match.group(1)) else False
                    return result
                except:
                    continue

        return True  # No pattern matched = assume affected (conservative approach)

    def extract_products(self, scan_results):
        products = set()

        print(f"DEBUG: Scan results structure: {list(scan_results.keys())}")  # Debug

        for port, port_data in scan_results.items():
            if not isinstance(port_data, dict):
                continue

            print(f"DEBUG: Port {port} tools: {list(port_data.keys())}")  # Debug

            for tool, data in port_data.items():
                if not isinstance(data, dict):
                    continue

                print(f"DEBUG: Tool {tool} data keys: {list(data.keys())}")  # Debug

                try:
                    # WhatWeb extraction - check for web servers
                    if 'whatweb' in tool.lower():
                        # Check direct server detection
                        for server in ['Apache', 'Nginx', 'IIS']:
                            if server in data and 'version' in data:
                                vendor_map = {'Apache': 'apache', 'Nginx': 'nginx', 'IIS': 'microsoft'}
                                product_map = {'Apache': 'http_server', 'Nginx': 'nginx',
                                               'IIS': 'internet_information_server'}
                                versions = data['version'] if isinstance(data['version'], list) else [data['version']]
                                for v in versions:
                                    if v and str(v).strip():
                                        products.add((vendor_map[server], product_map[server], str(v).strip()))
                                        print(f"DEBUG: Found {server} {v}")

                        # Check HTTPServer field
                        if 'HTTPServer' in data and 'string' in data['HTTPServer']:
                            strings = data['HTTPServer']['string'] if isinstance(data['HTTPServer']['string'],
                                                                                 list) else [
                                data['HTTPServer']['string']]
                            for string in strings:
                                # Apache detection
                                match = re.search(r'Apache/([0-9.]+)', string)
                                if match:
                                    products.add(('apache', 'http_server', match.group(1)))
                                    print(f"DEBUG: Found Apache {match.group(1)} from HTTPServer")

                                # Nginx detection
                                match = re.search(r'nginx/([0-9.]+)', string)
                                if match:
                                    products.add(('nginx', 'nginx', match.group(1)))
                                    print(f"DEBUG: Found Nginx {match.group(1)} from HTTPServer")

                    # Nmap service detection
                    if 'nmap' in tool.lower():
                        if 'open_ports' in data:
                            for port_info in data['open_ports']:
                                if isinstance(port_info, dict):
                                    service = port_info.get('service', '').lower()
                                    product = port_info.get('product', '').lower()
                                    version_str = port_info.get('version', '')

                                    if service and version_str:
                                        if service == 'http' and 'apache' in product:
                                            products.add(('apache', 'http_server', str(version_str)))
                                        elif service == 'http' and 'nginx' in product:
                                            products.add(('nginx', 'nginx', str(version_str)))
                                        elif service == 'ssh':
                                            products.add(('openbsd', 'openssh', str(version_str)))
                                        elif service == 'mysql':
                                            products.add(('mysql', 'mysql', str(version_str)))

                    # Direct product/version in service scans
                    if 'product' in data and 'version' in data:
                        product = str(data['product']).lower()
                        ver = str(data['version']).split('-')[0].strip()

                        if ver:
                            if 'apache' in product:
                                products.add(('apache', 'http_server', ver))
                                print(f"DEBUG: Found Apache {ver} from direct detection")
                            elif 'nginx' in product:
                                products.add(('nginx', 'nginx', ver))
                            elif 'openssh' in product or 'ssh' in product:
                                products.add(('openbsd', 'openssh', ver.split('p')[0]))
                            elif 'samba' in product:
                                products.add(('samba', 'samba', ver))
                            elif 'mysql' in product:
                                products.add(('mysql', 'mysql', ver))
                            elif 'postfix' in product:
                                products.add(('postfix', 'postfix', ver))

                    # SSH audit extraction
                    if 'software' in data:
                        software = str(data['software']).lower()
                        match = re.search(r'openssh[_\s]([0-9.]+)', software)
                        if match:
                            products.add(('openbsd', 'openssh', match.group(1).split('p')[0]))

                    # WordPress extraction
                    if 'wpscan' in tool and 'version' in data:
                        if isinstance(data['version'], dict) and 'number' in data['version']:
                            products.add(('wordpress', 'wordpress', str(data['version']['number'])))
                        elif isinstance(data['version'], str):
                            products.add(('wordpress', 'wordpress', str(data['version'])))

                except Exception as e:
                    print(f"DEBUG: Error extracting from {tool}: {e}")
                    self.stats['errors'] += 1

        print(f"DEBUG: Extracted products: {products}")  # Debug
        self.stats['products_found'] = len(products)
        return list(products)

    def search_cves(self, vendor, product):
        try:
            url = f"{self.base_url}/vulnerability/search/{quote(vendor)}/{quote(product)}"
            response = self.session.get(url, timeout=30)
            self.stats['api_requests'] += 1
            return response.json() if response.status_code == 200 else {}
        except Exception as e:
            printerr(f"API error for {vendor}/{product}: {e}")
            self.stats['errors'] += 1
            return {}

    def parse_cve(self, cve_id, cve_data, section, vendor, product, target_version):
        try:
            cve = {
                'cve_id': cve_id, 'vendor': vendor, 'product': product, 'version': target_version,
                'summary': '', 'cvss_score': None, 'severity': None, 'published': None
            }

            version_constraints = []

            if section == 'fkie_nvd':
                cve['summary'] = next(
                    (d.get('value', '')[:500] for d in cve_data.get('descriptions', []) if d.get('lang') == 'en'), '')
                cve['published'] = cve_data.get('published')

                # CVSS
                for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    metrics = cve_data.get('metrics', {}).get(metric_type, [])
                    if metrics:
                        cvss = metrics[0].get('cvssData', {})
                        cve['cvss_score'] = cvss.get('baseScore')
                        cve['severity'] = metrics[0].get('baseSeverity', '').lower()
                        break

                # Version constraints
                for config in cve_data.get('configurations', []):
                    for node in config.get('nodes', []):
                        for cpe in node.get('cpeMatch', []):
                            if cpe.get('vulnerable'):
                                constraint = ""
                                if 'versionStartIncluding' in cpe:
                                    constraint = f"since {cpe['versionStartIncluding']}"
                                elif 'versionStartExcluding' in cpe:
                                    constraint = f"after {cpe['versionStartExcluding']}"
                                if 'versionEndIncluding' in cpe:
                                    constraint += f" up to {cpe['versionEndIncluding']}"
                                elif 'versionEndExcluding' in cpe:
                                    constraint += f" before {cve['versionEndExcluding']}"
                                version_constraints.append(constraint.strip())

            elif section == 'cvelistv5':
                containers = cve_data.get('containers', {})

                # CNA data
                if 'cna' in containers:
                    cna = containers['cna']
                    cve['summary'] = next(
                        (d.get('value', '')[:500] for d in cna.get('descriptions', []) if d.get('lang') == 'en'), '')

                    # CVSS
                    for metric in cna.get('metrics', []):
                        for cvss_ver in ['cvssV3_1', 'cvssV3_0']:
                            if cvss_ver in metric:
                                cvss = metric[cvss_ver]
                                cve['cvss_score'] = cvss.get('baseScore')
                                cve['severity'] = cvss.get('baseSeverity', '').lower()
                                break
                        if cve['cvss_score']:
                            break

                    # Affected versions
                    for affected in cna.get('affected', []):
                        for ver in affected.get('versions', []):
                            if ver.get('status') == 'affected':
                                version_constraints.append(ver.get('version', ''))

            elif section == 'variot':
                cve['summary'] = cve_data.get('description', {}).get('data', '')[:500]

                # CVSS
                for cvss_entry in cve_data.get('cvss', {}).get('data', []):
                    for cvss_v3 in cvss_entry.get('cvssV3', []):
                        cve['cvss_score'] = cvss_v3.get('baseScore')
                        cve['severity'] = cvss_v3.get('baseSeverity', '').lower()
                        break
                    if cve['cvss_score']:
                        break

            # Check if version is affected
            is_affected = False

            if version_constraints:
                # If we have structured constraints, check them
                for constraint in version_constraints:
                    if self.version_affected(target_version, constraint, cve['summary']):
                        is_affected = True
                        break
            else:
                # No structured constraints, check description only
                is_affected = self.version_affected(target_version, '', cve['summary'])

            if is_affected:
                self.stats['cves_found'] += 1
                return cve
            else:
                self.stats['cves_filtered'] += 1
                return None

        except Exception as e:
            printwarn(f"Error parsing {cve_id}: {e}")
            self.stats['errors'] += 1
            return None

    def analyze_scan_results(self, scan_results):
        printout("Starting CVE analysis")
        self.stats = {'products_found': 0, 'api_requests': 0, 'cves_found': 0, 'cves_filtered': 0, 'cvss_medium': 0.0,
                      'errors': 0}

        products = self.extract_products(scan_results)
        if not products:
            printwarn("No products found")
            return []

        printout(f"Found {len(products)} products to check")
        all_cves = []

        for i, (vendor, product, ver) in enumerate(products, 1):
            printout(f"Checking {vendor}/{product} {ver} ({i}/{len(products)})")

            cve_data = self.search_cves(vendor, product)
            if cve_data:
                for section in ['fkie_nvd', 'cvelistv5', 'variot']:
                    for entry in cve_data.get(section, []):
                        if isinstance(entry, list) and len(entry) >= 2:
                            cve = self.parse_cve(entry[0], entry[1], section, vendor, product, ver)
                            if cve:
                                all_cves.append(cve)

            time.sleep(self.request_delay)

        # Calculate stats
        cvss_scores = [c['cvss_score'] for c in all_cves if c.get('cvss_score')]
        if cvss_scores:
            self.stats['cvss_medium'] = round(sum(cvss_scores) / len(cvss_scores), 1)

        # Save results
        results = {'cves': all_cves, 'statistics': self.stats, 'total_cves': len(all_cves)}
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        printout(f"Found {len(all_cves)} relevant CVEs, filtered {self.stats['cves_filtered']}")
        return all_cves

    def get_statistics(self):
        return self.stats.copy()