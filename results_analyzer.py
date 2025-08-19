def get_useful_info(tool, content, port):
    info_list = {}

    if tool == 'aftp' and content.get('anonymous_login'):
        info_list[f"{tool}_{port}_0"] = {'anonymous_login': content.get('anonymous_login')}

    elif tool == 'dig':
        counter = 0
        for item in content:
            if item.get('vulnerability_type') in ['open_resolver', 'information_disclosure', 'amplification']:
                info_list[f"{tool}_{port}_{counter}"] = {
                    'vulnerability_type': item.get('vulnerability_type'),
                    'severity': item.get('severity'),
                    'description': item.get('description')
                }
                counter += 1

    elif tool == 'ffuf' and content.get('results'):
        counter = 0
        for result in content.get('results'):
            info_list[f"{tool}_{port}_{counter}"] = {
                'FUZZ': result.get('input').get('FUZZ'),
                'url': result.get('url'),
                'status': result.get('status')
            }
            counter += 1

    elif tool == 'nikto' and content.get('vulnerabilities'):
        counter = 0
        for result in content.get('vulnerabilities'):
            info_list[f"{tool}_{port}_{counter}"] = {
                'references': result.get('references'),
                'url': result.get('url'),
                'msg': result.get('msg')
            }
            counter += 1

    elif tool == 'ssh-audit':
        if content.get('banner'):
            info_list[f"{tool}_{port}_0"] = {
                'protocol': content.get('banner', {}).get('protocol'),
                'software': content.get('banner', {}).get('software'),
                'version': content.get('banner', {}).get('version')
            }

        if content.get('cves'):
            info_list[f"{tool}_{port}_0"]['cves'] = content.get('cves')

        for category in ['enc', 'kex', 'key', 'mac']:
            category_data = content.get(category, [])
            for i, algorithm in enumerate(category_data):
                if algorithm.get('notes'):
                    notes = algorithm.get('notes', {})
                    if notes.get('fail') or notes.get('warn'):
                        info_list[f"{tool}_{port}_0"]['algorithm'] = algorithm.get('algorithm')
                        info_list[f"{tool}_{port}_0"]['fail'] = notes.get('fail')
                        info_list[f"{tool}_{port}_0"]['warn'] = notes.get('warn')

    elif tool == 'whatweb' and content.get('plugins'):
        plugins = content.get('plugins', {})

        if plugins.get('HTTPServer'):
            plugin_data = plugins.get('HTTPServer')
            info_list[f"{tool}_{port}_HTTPServer"] = {
                'string': plugin_data.get('string'),
                'os': plugin_data.get('os')
            }

        for plugin_name in ['Apache', 'Nginx', 'IIS']:
            if plugins.get(plugin_name):
                plugin_data = plugins.get(plugin_name)
                info_list[f"{tool}_{port}_{plugin_name}"] = {
                    'version': plugin_data.get('version')
                }

        if plugins.get('X-Powered-By'):
            info_list[f"{tool}_{port}_X-Powered-By"] = {
                'string': plugins.get('X-Powered-By', {}).get('string')
            }

        for plugin_name in ['PhpMyAdmin', 'Tomcat', 'Jenkins', 'GitLab', 'Confluence', 'JIRA', 'MySQL', 'WordPress',
                            'Drupal', 'Joomla', 'JQuery', 'Bootstrap', 'OutdatedJS']:
            if plugins.get(plugin_name):
                info_list[f"{tool}_{port}_{plugin_name}"] = {
                    'version': plugins.get(plugin_name, {}).get('version')
                }
        if plugins.get('DirectoryListing'):
            info_list[f"{tool}_{port}_DirectoryListing"] = {'DirectoryListing': plugins.get('DirectoryListing')}

        if plugins.get('DefaultCredentials'):
            info_list[f"{tool}_{port}_DefaultCredentials"] = {
                'string': plugins.get('DefaultCredentials', {}).get('string')
            }

    elif tool == 'enum4linux' and content.get('target'):
        info_list[f"{tool}_{port}_0"] = {}
        if content.get('listeners') in ['LDAP', 'LDAPS', 'SMB', 'SMB over NetBIOS', 'RPC']:
            for service, data in content.get('listeners', {}).items():
                if data.get('accessible'):
                    info_list[f"{tool}_{port}_0"][{service}] = {
                        'accessible': data.get('accessible')
                    }

        if content.get('smb_dialects'):
            info_list[f"{tool}_{port}_0"]["smb_dialects"] = {
                'smb_1_0': content.get('smb_dialects', {}).get('Supported dialects').get('SMB 1.0'),
                'smb_signing_required': content.get('smb_dialects', {}).get('SMB signing required')
            }

        if content.get('users'):
            info_list[f"{tool}_{port}_0"]["users"] = {}
            for user_id, user_data in content.get('users', {}).items():
                if user_data.get('username'):
                    info_list[f"{tool}_{port}_0"]["users"][user_id] = user_data.get('username')

        if content.get('policy', {}).get('Domain password information'):
            policy_info = content.get('policy', {}).get('Domain password information', {})
            info_list[f"{tool}_{port}_0"]["policy"] = {
                'min_password_length': policy_info.get('Minimum password length'),
                'DOMAIN_PASSWORD_COMPLEX': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_COMPLEX'),
                'DOMAIN_PASSWORD_NO_ANON_CHANGE': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_NO_ANON_CHANGE'),
                'DOMAIN_PASSWORD_NO_CLEAR_CHANGE': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_NO_CLEAR_CHANGE'),
                'DOMAIN_PASSWORD_LOCKOUT_ADMINS': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_LOCKOUT_ADMINS'),
                'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT': policy_info.get('Password properties')[0].get('DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT')
            }

    elif tool == 'hydra' and content.get('success'):
        counter = 0
        for success in content.get('results'):
            info_list[f"{tool}_{port}_{counter}"] = {
                'login': success.get('login'),
                'password': success.get('password')
            }
            counter += 1

    elif tool == 'smtp_user_enum' and content.get('valid_users'):
        counter = 0
        for user in content.get('valid_users', []):
            info_list[f"{tool}_{port}_{counter}"] = {
                'username': user
            }
            counter += 1

    elif tool == 'sslscan':
        if content.get('protocols'):
            protocols = content.get('protocols', {})
            enabled_protocols = {}
            for protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                if protocols.get(protocol):
                    enabled_protocols[protocol] = protocols.get(protocol)

            if enabled_protocols:
                info_list[f"{tool}_{port}_protocols"] = enabled_protocols

        if content.get('cipher_suites'):
            cipher_data = content.get('cipher_suites', {})
            cipher_info = {}

            if cipher_data.get('weak'):
                cipher_info['weak'] = cipher_data.get('weak')
            if cipher_data.get('insecure'):
                cipher_info['insecure'] = cipher_data.get('insecure')

            if cipher_info:
                info_list[f"{tool}_{port}_ciphers"] = cipher_info

        if content.get('certificate'):
            info_list[f"{tool}_{port}_certificate"] = {
                "expired": content.get('certificate', {}).get('expired'),
                "self_signed": content.get('certificate', {}).get('self_signed'),
                "short_key": content.get('certificate', {}).get('short_key'),
            }

    elif tool == 'wpscan':
        if content.get('version'):
            info_list[f"{tool}_{port}_version"] = {
                'version': content.get('version')
            }

        if content.get('vulnerable_plugins'):
            plugins_dict = {}
            for plugin in content.get('vulnerable_plugins', []):
                plugin_name = plugin.get('name', 'unknown')
                plugins_dict[plugin_name] = {
                    'version': plugin.get('version'),
                    'cves': plugin.get('cves')
                }

            if plugins_dict:
                info_list[f"{tool}_{port}_plugins"] = plugins_dict

        if content.get('vulnerable_themes'):
            themes_dict = {}
            for theme in content.get('vulnerable_themes', []):
                theme_name = theme.get('name', 'unknown')
                themes_dict[theme_name] = {
                    'version': theme.get('version'),
                    'cves': theme.get('cves')
                }

            if themes_dict:
                info_list[f"{tool}_{port}_themes"] = themes_dict

        if content.get('users'):
            info_list[f"{tool}_{port}_users"] = {
                'users': content.get('users')
            }

        if content.get('default_creds'):
            info_list[f"{tool}_{port}_default_creds"] = {
                'default_creds': content.get('default_creds')
            }

    #elif tool == 'nftp' and content.get('scan_result'):

    elif tool == "nssh" and content.get('scan_result'):
        scripts = content.get("script", {})

        pubkey_acceptance = scripts.get("ssh-publickey-acceptance", "").lower()
        pubkey_acceptance = not ("no public keys accepted" in pubkey_acceptance)

        brute = scripts.get("ssh-brute", "")
        if "No valid accounts found" in brute:
            brute_force = False
        else:
            brute_force = []
            for line in brute.splitlines():
                if "login:" in line or "username:" in line:
                    brute_force.append(line.strip())

        info_list[f"{tool}_{port}_0"] = {
            "product": content.get("product"),
            "version": content.get("version"),
            "os": content.get("extrainfo"),
            "cpe": content.get("cpe"),
            "ssh_hostkeys": scripts.get("ssh-hostkey"),
            "auth_methods": scripts.get("ssh-auth-methods"),
            "publickey_acceptance": pubkey_acceptance,
            "brute_force": brute_force,
        }

    elif tool == 'nsmb' and content.get('scan_result'):
        host_data = content['scan_result']['raw_output']['scan']
        for ip, ip_data in host_data.items():
            target = info_list[f"{tool}_{port}_0"] = {}
            tcp = ip_data.get('tcp', {}).get(str(port), {})
            if tcp.get('product'):
                target['product'] = tcp['product']
            if tcp.get('version'):
                target['version'] = tcp['version']

            for script in ip_data.get('hostscript', []):
                output = (script.get('output') or "").strip()
                if not output:
                    continue
                sid = script.get('id')

                if sid == "smb-security-mode":
                    for line in output.splitlines():
                        if line.startswith("account_used:"):
                            target['account_used'] = line.split(":", 1)[1].strip()
                        elif line.startswith("authentication_level:"):
                            target['authentication_level'] = line.split(":", 1)[1].strip()
                        elif line.startswith("message_signing:"):
                            target['message_signing'] = line.split(":", 1)[1].strip()

                elif sid == "smb-protocols":
                    dialects = [l.strip() for l in output.splitlines() if l.strip() and not l.startswith("dialects:")]
                    if dialects: target['dialects'] = dialects

                elif sid.startswith("smb-vuln-"):
                    if output.startswith("VULNERABLE:"):
                        target.setdefault('vulnerabilities', {})[sid] = "true"
                    else:
                        target.setdefault('vulnerabilities', {})[sid] = output

    elif tool == 'nsmtp' and content.get('scan_result'):
        script = content.get('script', {})

        commands = None
        if script.get('smtp-commands'):
            commands = [c.strip() for c in script['smtp-commands'].split(',') if c.strip()]

        open_relay = None
        if script.get('smtp-open-relay'):
            open_relay = "doesn't" not in script['smtp-open-relay'].lower()

        vuln_cve2010_4344 = None
        if script.get('smtp-vuln-cve2010-4344'):
            vuln_cve2010_4344 = "not vulnerable" not in script['smtp-vuln-cve2010-4344'].lower()

        enum_users = None
        if script.get('smtp-enum-users') and "couldn't" not in script['smtp-enum-users'].lower():
            enum_users = [u.strip() for u in script['smtp-enum-users'].splitlines() if u.strip()]

        info_list[f"{tool}_{port}_0"] = {
            'product': content.get('product'),
            'version': content.get('version'),
            'extrainfo': content.get('extrainfo'),
            'cpe': content.get('cpe'),
            'smtp_commands': commands,
            'open_relay': open_relay,
            'enum_users': enum_users,
            'vuln_cve2010_4344': vuln_cve2010_4344
        }

    elif tool == 'nmap':
        scan_result = content.get('scan_result', {})
        os_info = scan_result.get('os_info', {})
        services = scan_result.get('services', {})

        nmap_info = {
            'target_ip': scan_result.get('ip_address'),
            'open_ports': scan_result.get('open_ports', [])
        }

        if os_info.get('name'):
            nmap_info['os'] = os_info['name']

        for port_num, service in services.items():
            scripts = service.get('scripts', {})

            if 'Anonymous FTP login allowed' in scripts.get('ftp-anon', ''):
                nmap_info[f'ftp_{port_num}_anonymous'] = True

            if 'Git repository found' in scripts.get('http-git', ''):
                nmap_info[f'http_{port_num}_git'] = True

            if 'VRFY' in scripts.get('smtp-commands', ''):
                nmap_info[f'smtp_{port_num}_vrfy'] = True

            if scripts.get('http-open-proxy'):
                nmap_info[f'proxy_{port_num}'] = True

        info_list[f"{tool}_{port}_0"] = nmap_info

    return info_list


class ResultAnalyzer:
    def __init__(self, input_dict):
        self.input_dict = input_dict
        self.results = {}

    def start(self):
        for tool, content in self.input_dict.items():
            for port, data in content.items():
                if tool in ['dig', 'wpscan', 'smtp_user_enum']:
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
                    self.results.update(useful_info)

        print(self.results)
        return self.results