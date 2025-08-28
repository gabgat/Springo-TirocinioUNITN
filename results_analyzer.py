def get_useful_info(tool, content, port):
    info_list = {port: {}}

    if tool == 'aftp' and content.get('anonymous_login'):
        info_list[port][tool] = {'anonymous_login': content.get('anonymous_login')}

    elif tool == 'dig':
        info_list[port][tool] = []
        for item in content:
            if item.get('vulnerability_type') in ['open_resolver', 'information_disclosure', 'amplification']:
                info_list[port][tool].append({
                    'vulnerability_type': item.get('vulnerability_type'),
                    'severity': item.get('severity'),
                    'description': item.get('description')
                })

    elif tool == 'ffuf' and content.get('results'):
        info_list[port][tool] = []
        for result in content.get('results'):
            info_list[port][tool].append({
                'FUZZ': result.get('input').get('FUZZ'),
                'url': result.get('url'),
                'status': result.get('status')
            })

    elif tool == 'nikto' and content.get('vulnerabilities'):
        info_list[port][tool] = []
        for result in content.get('vulnerabilities'):
            info_list[port][tool].append({
                'references': result.get('references'),
                'url': result.get('url'),
                'msg': result.get('msg')
            })

    elif tool == 'ssh-audit':
        if content.get('banner'):
            info_list[port][tool] = {
                'protocol': content.get('banner', {}).get('protocol'),
                'software': content.get('banner', {}).get('software'),
            }

        if content.get('cves'):
            info_list[port][tool]['cves'] = content.get('cves')

        for category in ['enc', 'kex', 'key', 'mac']:
            category_data = content.get(category, [])
            for i, algorithm in enumerate(category_data):
                if algorithm.get('notes'):
                    notes = algorithm.get('notes', {})
                    if notes.get('fail') or notes.get('warn'):
                        info_list[port][tool][algorithm.get('algorithm')] = {}
                        info_list[port][tool][algorithm.get('algorithm')]['fail'] = notes.get('fail')
                        info_list[port][tool][algorithm.get('algorithm')]['warn'] = notes.get('warn')

    elif tool == 'whatweb' and content.get('plugins'):
        plugins = content.get('plugins', {})
        info_list[port][tool] = {}

        if plugins.get('HTTPServer'):
            plugin_data = plugins.get('HTTPServer')
            info_list[port][tool]["HTTPServer"] = {
                'string': plugin_data.get('string'),
                'os': plugin_data.get('os')
            }

        for plugin_name in ['Apache', 'Nginx', 'IIS', 'PhpMyAdmin', 'Tomcat', 'Jenkins', 'GitLab', 'Confluence', 'JIRA', 'MySQL', 'WordPress',
                            'Drupal', 'Joomla', 'JQuery', 'Bootstrap', 'OutdatedJS']:
            if plugins.get(plugin_name):
                info_list[port][tool][plugin_name] = {
                    'version': plugins.get(plugin_name, {}).get('version')
                }

        if plugins.get('X-Powered-By'):
            info_list[port][tool]["X-Powered-By"] = {
                'string': plugins.get('X-Powered-By', {}).get('string')
            }

        if plugins.get('DirectoryListing'):
            info_list[port][tool]["DirectoryListing"] = plugins.get('DirectoryListing')

        if plugins.get('DefaultCredentials'):
            info_list[port][tool]["DefaultCredentials"] = plugins.get('DefaultCredentials', {}).get('string')

    elif tool == 'enum4linux' and content.get('target'):
        info_list[port][tool] = {}
        if content.get('listeners') in ['LDAP', 'LDAPS', 'SMB', 'SMB over NetBIOS', 'RPC']:
            for service, data in content.get('listeners', {}).items():
                if data.get('accessible'):
                    info_list[port][tool][{service}] = {
                        'accessible': data.get('accessible')
                    }

        if content.get('smb_dialects'):
            info_list[port][tool]["smb_dialects"] = {
                'smb_1_0': content.get('smb_dialects', {}).get('Supported dialects').get('SMB 1.0'),
                'smb_signing_required': content.get('smb_dialects', {}).get('SMB signing required')
            }

        if content.get('users'):
            info_list[port][tool]["users"] = {}
            for user_id, user_data in content.get('users', {}).items():
                if user_data.get('username'):
                    info_list[port][tool]["users"][user_id] = user_data.get('username')

        if content.get('policy', {}).get('Domain password information'):
            policy_info = content.get('policy', {}).get('Domain password information', {})
            info_list[port][tool]["policy"] = {
                'min_password_length': policy_info.get('Minimum password length'),
                'DOMAIN_PASSWORD_COMPLEX': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_COMPLEX'),
                'DOMAIN_PASSWORD_NO_ANON_CHANGE': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_NO_ANON_CHANGE'),
                'DOMAIN_PASSWORD_NO_CLEAR_CHANGE': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_NO_CLEAR_CHANGE'),
                'DOMAIN_PASSWORD_LOCKOUT_ADMINS': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_LOCKOUT_ADMINS'),
                'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT')
            }

    elif tool == 'hydra' and content.get('success'):
        info_list[port][tool] = []
        for success in content.get('results'):
            info_list[port][tool].append({
                'login': success.get('login'),
                'password': success.get('password')
            })

    elif tool == 'smtp_user_enum' and content.get('valid_users'):
        for user in content.get('valid_users', []):
            info_list[port][tool].append(user)

    elif tool == 'sslscan':
        if content.get('protocols'):
            protocols = content.get('protocols', {})
            enabled_protocols = {}
            for protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                if protocols.get(protocol):
                    enabled_protocols[protocol] = protocols.get(protocol)

            if enabled_protocols:
                info_list[port][tool]["protocols"] = enabled_protocols

        if content.get('cipher_suites'):
            cipher_data = content.get('cipher_suites', {})
            cipher_info = {}

            if cipher_data.get('weak'):
                cipher_info['weak'] = cipher_data.get('weak')
            if cipher_data.get('insecure'):
                cipher_info['insecure'] = cipher_data.get('insecure')

            if cipher_info:
                info_list[port][tool]["ciphers"] = cipher_info

        if content.get('certificate'):
            info_list[port][tool]["certificate"] = {
                "expired": content.get('certificate', {}).get('expired'),
                "self_signed": content.get('certificate', {}).get('self_signed'),
                "short_key": content.get('certificate', {}).get('short_key'),
            }

    elif tool == 'wpscan':
        info_list[port][tool] = {}

        if content.get('version'):
            version_data = content.get('version')
            info_list[port][tool]["version"] = version_data.get('number')
            info_list[port][tool]["release"] = version_data.get('release_date')
            info_list[port][tool]["secure"] = version_data.get('status') == 'secure'
            info_list[port][tool]["vulnerabilities"] = []

            if version_data.get('vulnerabilities'):
                for vuln in version_data.get('vulnerabilities', []):
                    info_list[port][tool]["vulnerabilities"].append({
                        "title": vuln.get('title'),
                        "cve": vuln.get('references', {}).get('cve', [''])[0]
                    })

        if content.get('interesting_findings'):
            info_list[port][tool]["interesting_findings"] = []

            for item in content.get('interesting_findings', []):
                info_list[port][tool]["interesting_findings"].append(item.get('url'))

        if content.get('plugins'):
            info_list[port][tool]["plugins"] = {}

            for plugin_slug, plugin_data in content.get('plugins', {}).items():
                info_list[port][tool]["plugins"][plugin_slug] = {
                    "version": plugin_data.get('version', {}).get('number') if plugin_data.get('version') else None,
                    "latest_version": plugin_data.get('latest_version'),
                    "outdated": plugin_data.get('outdated'),
                    "vulnerabilities": []
                }

                if plugin_data.get("vulnerabilities"):
                    for vuln in plugin_data.get("vulnerabilities", []):
                        info_list[port][tool]["plugins"][plugin_slug]["vulnerabilities"].append({
                            "title": vuln.get('title'),
                            "cve": vuln.get('references', {}).get('cve', [''])[0]
                        })

        if content.get('main_theme'):
            theme_data = content.get('main_theme')

            info_list[port][tool]["main_theme"] = {
                "name": theme_data.get('style_name'),
                "version": theme_data.get('version', {}).get('number') if theme_data.get('version') else None,
                "latest_version": theme_data.get('latest_version'),
                "outdated": theme_data.get('outdated'),
                "vulnerabilities": []
            }

            if theme_data.get("vulnerabilities"):
                for vuln in theme_data.get("vulnerabilities", []):
                    info_list[port][tool]["main_theme"]["vulnerabilities"].append({
                        "title": vuln.get('title'),
                        "cve": vuln.get('references', {}).get('cve', [''])[0]
                    })

        if content.get('users'):
            info_list[port][tool]["users"] = []
            for username, data in content.get('users', {}).items():
                info_list[port][tool]["users"].append(username)

        if content.get('themes'):
            info_list[port][tool]["themes"] = {}
            for theme_slug, theme_data in content.get('themes', {}).items():
                info_list[port][tool]["themes"][theme_slug] = {
                    "version": theme_data.get('version', {}).get('number') if theme_data.get('version') else None,
                    "latest_version": theme_data.get('latest_version'),
                    "outdated": theme_data.get('outdated'),
                    "vulnerabilities": []
                }

                if theme_data.get("vulnerabilities"):
                    for vuln in theme_data.get("vulnerabilities", []):
                        info_list[port][tool]["themes"][theme_slug]["vulnerabilities"].append({
                            "title": vuln.get('title'),
                            "cve": vuln.get('references', {}).get('cve', [''])[0]
                        })


    elif tool == 'nftp' and content.get('scan_result'):
        host_data = content['scan_result']['raw_output']['scan']
        for ip, ip_data in host_data.items():
            tcp = ip_data.get('tcp', {}).get(str(port), {})
            scripts = tcp.get('script', {})

            info_list[port][tool] = {}

            # Basic service information
            if tcp.get('product'):
                info_list[port][tool]['product'] = tcp['product']
            if tcp.get('version'):
                info_list[port][tool]['version'] = tcp['version']
            if tcp.get('extrainfo'):
                info_list[port][tool]['extrainfo'] = tcp['extrainfo']

            if scripts.get("ftp-bounce", ""):
                if "bounce working" in scripts.get("ftp-bounce", "").lower():
                    info_list[port][tool]['ftp_bounce_vulnerable'] = True
                else:
                    info_list[port][tool]['ftp_bounce_vulnerable'] = False

            if scripts.get("ftp-vuln-cve2010-4221", ""):
                if "vulnerable" in scripts.get("ftp-vuln-cve2010-4221", "").lower():
                    info_list[port][tool]['ftp_vuln_cve2010_4221'] = True
                else:
                    info_list[port][tool]['ftp_vuln_cve2010_4221'] = False

            if scripts.get("ftp-libopie", ""):
                if "vulnerable" in scripts.get("ftp-libopie", "").lower():
                    info_list[port][tool]['ftp_vuln_cve2010_1938'] = True
                else:
                    info_list[port][tool]['ftp_vuln_cve2010_1938'] = False

            if scripts.get("ftp-ls", ""):
                info_list[port][tool]['directory_listing'] = scripts.get("ftp-ls", "").strip()

            if "VULNERABLE" in scripts.get("ftp-proftpd-backdoor", ""):
                info_list[port][tool]['proftpd_backdoor'] = True
            else:
                info_list[port][tool]['proftpd_backdoor'] = False

            if "VULNERABLE" in scripts.get("ftp-vsftpd-backdoor", ""):
                info_list[port][tool]['vsftpd_backdoor'] = True
            else:
                info_list[port][tool]['vsftpd_backdoor'] = False

    elif tool == 'nssh' and content.get('scan_result'):
        host_data = content['scan_result']['raw_output']['scan']
        for ip, ip_data in host_data.items():
            tcp = ip_data.get('tcp', {}).get(str(port), {})
            scripts = tcp.get('script', {})

            info_list[port][tool] = {}

            if tcp.get('product'):
                info_list[port][tool]['product'] = tcp['product']
            if tcp.get('version'):
                info_list[port][tool]['version'] = tcp['version']
            if tcp.get('extrainfo'):
                info_list[port][tool]['extrainfo'] = tcp['extrainfo']

            if scripts.get("ssh-publickey-acceptance", ""):
                if "no public keys accepted" in scripts.get("ssh-publickey-acceptance", "").lower():
                    info_list[port][tool]['publickey_acceptance'] = False
                else:
                    info_list[port][tool]['publickey_acceptance'] = True

    elif tool == 'nsmb' and content.get('scan_result'):
        for ip, ip_data in content['scan_result']['raw_output']['scan'].items():
            info_list[port][tool] = {}
            tcp = ip_data.get('tcp', {}).get(str(port), {})
            if tcp.get('product'):
                info_list[port][tool]['product'] = tcp['product']
            if tcp.get('version'):
                info_list[port][tool]['version'] = tcp['version']

            for script in ip_data.get('hostscript', []):
                output = (script.get('output') or "").strip()
                if not output:
                    continue
                sid = script.get('id')

                if sid == "smb-security-mode":
                    for line in output.splitlines():
                        if line.startswith("account_used:"):
                            info_list[port][tool]['account_used'] = line.split(":", 1)[1].strip()
                        elif line.startswith("authentication_level:"):
                            info_list[port][tool]['authentication_level'] = line.split(":", 1)[1].strip()
                        elif line.startswith("message_signing:"):
                            info_list[port][tool]['message_signing'] = line.split(":", 1)[1].strip()

                elif sid == "smb-protocols":
                    dialects = [l.strip() for l in output.splitlines() if l.strip() and not l.startswith("dialects:")]
                    if dialects: info_list[port][tool]['dialects'] = dialects

                elif sid.startswith("smb-vuln-"):
                    if output.startswith("VULNERABLE:"):
                        info_list[port][tool].setdefault('vulnerabilities', {})[sid] = "true"
                    else:
                        info_list[port][tool].setdefault('vulnerabilities', {})[sid] = output

    elif tool == 'nsmtp' and content.get('scan_result'):
        scan = content["scan_result"]["raw_output"]["scan"]

        for ip, host_data in scan.items():
            tcp_data = host_data.get("tcp", {})
            for port, port_data in tcp_data.items():

                commands = None
                if port_data.get('script', {}).get('smtp-commands'):
                    commands = [c.strip() for c in port_data.get('script', {})['smtp-commands'].split(',') if c.strip()]

                open_relay = None
                if port_data.get('script', {}).get('smtp-open-relay'):
                    open_relay = "Server doesn't seem to be an open relay" not in port_data.get('script', {})['smtp-open-relay'].lower()

                vuln_cve2010_4344 = None
                if port_data.get('script', {}).get('smtp-vuln-cve2010-4344'):
                    vuln_cve2010_4344 = "not vulnerable" not in port_data.get('script', {})['smtp-vuln-cve2010-4344'].lower()

                enum_users = None
                if port_data.get('script', {}).get('smtp-enum-users') and "couldn't find any accounts" not in port_data.get('script', {})['smtp-enum-users'].lower():
                    enum_users = [u.strip() for u in port_data.get('script', {})['smtp-enum-users'].splitlines() if u.strip()]

                info_list[port][tool] = {
                    'product': port_data.get('product'),
                    'version': port_data.get('version'),
                    'extrainfo': port_data.get('extrainfo'),
                    'smtp_commands': commands,
                    'open_relay': open_relay,
                    'enum_users': enum_users,
                    'vuln_cve2010_4344': vuln_cve2010_4344
                }

    elif tool == 'nhttp' and content.get('scan_result'):
        host_data = content['scan_result']['raw_output']['scan']
        for ip, ip_data in host_data.items():
            scripts = ip_data.get('tcp', {}).get(str(port), {}).get('script', {})

            info_list[port][tool] = {}

            # http-title
            if scripts.get("http-title"):
                info_list[port][tool]['http_title'] = scripts.get("http-title").partition('\n')[0]

            # http-favicon (matched or False)
            if scripts.get("http-favicon") and "unknown" not in scripts.get("http-favicon").lower():
                info_list[port][tool]['http_favicon'] = scripts.get("http-favicon").strip()
            else:
                info_list[port][tool]['http_favicon'] = False

            # http-git
            if scripts.get("http-git") and "git repository found!" in scripts.get("http-git").lower():
                info_list[port][tool]['http_git'] = {}
                if [line.strip() for line in scripts.get("http-git").split('\n') if line.strip().startswith('http')]:
                    info_list[port][tool]['http_git']['url'] = [line.strip() for line in scripts.get("http-git").split('\n') if line.strip().startswith('http')][0].strip()

                if [line for line in scripts.get("http-git").split('\n') if 'Project type:' in line]:
                    info_list[port][tool]['http_git']['type'] = [line for line in scripts.get("http-git").split('\n') if 'Project type:' in line][0].split('Project type:')[1].strip()
            else:
                info_list[port][tool]['http_git'] = False

            # http-robots.txt (True if present)
            if scripts.get("http-robots.txt"):
                text = scripts.get("http-robots.txt", "")
                disallowed = []

                # Split by "disallowed entry" and process each part
                parts = text.split('disallowed entry')
                for i in range(1, len(parts)):  # Skip first part (before any "disallowed entry")
                    part = parts[i]
                    # Find the newline and extract what comes after it
                    if '\n' in part:
                        lines_after = part.split('\n')[1:]  # Get all lines after the first one
                        for line in lines_after:
                            line = line.strip()
                            if line:  # Only add non-empty entries
                                disallowed.append(line)
                                break  # Only take the first non-empty line after each "disallowed entry"

                info_list[port][tool]['http_robots'] = disallowed if disallowed else False
            else:
                info_list[port][tool]['http_robots'] = False

            # http-auth-finder (url inside FORM or False)
            if scripts.get("http-auth-finder"):
                lines = [l.strip() for l in scripts.get("http-auth-finder", "").splitlines() if "FORM" in l]
                if lines:
                    # Extract just the URLs where FORM was detected
                    urls = [l.split()[0] for l in lines if l.startswith("http")]
                    info_list[port][tool]['http_auth_finder'] = urls if urls else False
                else:
                    info_list[port][tool]['http_auth_finder'] = False
            else:
                info_list[port][tool]['http_auth_finder'] = False

            # http-methods (list if PUT/DELETE/TRACE present, else False)
            if scripts.get("http-methods"):
                methods_line = scripts.get("http-methods", "")
                methods = []
                for verb in ["PUT", "DELETE", "TRACE"]:
                    if verb in methods_line:
                        methods.append(verb)
                info_list[port][tool]['http_methods'] = methods if methods else "No risky methods detected"
            else:
                info_list[port][tool]['http_methods'] = False

            # http-waf-detect (True/False)
            if scripts.get("http-waf-detect") and "detected" in scripts.get("http-waf-detect").lower():
                info_list[port][tool]['http_waf_detect'] = True
            else:
                info_list[port][tool]['http_waf_detect'] = False

            # http-open-proxy (true, false or possible)
            if scripts.get("http-open-proxy"):
                output = scripts.get("http-open-proxy").lower()
                if "potentially open proxy" in output:
                    info_list[port][tool]['http_open_proxy'] = True
                elif "proxy might be redirecting" in output:
                    info_list[port][tool]['http_open_proxy'] = "possible"
                else:
                    info_list[port][tool]['http_open_proxy'] = False
            else:
                info_list[port][tool]['http_open_proxy'] = False

    elif tool == 'nmap':

        info_list[port][tool] = {
            'target_ip': content.get('scan_result', {}).get('ip_address'),
            'open_ports': content.get('scan_result', {}).get('open_ports', []),
            'os': content.get('scan_result', {}).get('os_info', {}).get('name'),
            'family': content.get('scan_result', {}).get('os_info', {}).get('osfamily'),
            'vendor': content.get('scan_result', {}).get('os_info', {}).get('vendor'),
            'type': content.get('scan_result', {}).get('os_info', {}).get('type'),
            'mac': content.get('scan_result', {}).get('os_info', {}).get('addresses', {}).get('mac')
        }

    return info_list


class ResultAnalyzer:
    def __init__(self, input_dict):
        self.input_dict = input_dict
        self.results = {}

    def start(self):
        for tool, content in self.input_dict.items():
            for port, data in content.items():
                if tool in ['dig', 'smtp_user_enum']:
                    if not isinstance(data, list):
                        data = [data] if data else []
                else:
                    if isinstance(data, list):
                        if data and isinstance(data[0], dict):
                            data = data[0]
                        else:
                            data = {"data": data}
                    elif not isinstance(data, dict):
                        continue

                useful_info = get_useful_info(tool, data, port)
                if useful_info:
                    for port_num, tool_data in useful_info.items():
                        if port_num not in self.results:
                            self.results[port_num] = {}

                        self.results[port_num].update(tool_data)

        return self.results