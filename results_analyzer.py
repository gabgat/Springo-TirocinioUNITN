def get_useful_info(tool, content, port):
    info_list = {port: {}}

    if tool == 'aftp' and content.get('anonymous_login'):
        info_list[port][tool] = {'anonymous_login': content.get('anonymous_login')}

    elif tool == 'dig':
        info_list[port][tool] = []
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get('vulnerability_type') in ['open_resolver',
                                                                                 'information_disclosure',
                                                                                 'amplification']:
                    info_list[port][tool].append({
                        'vulnerability_type': item.get('vulnerability_type'),
                        'severity': item.get('severity'),
                        'description': item.get('description')
                    })

    elif tool == 'ffuf' and content.get('results'):
        info_list[port][tool] = []
        results = content.get('results')
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict) and result.get('input') and result.get('input').get('FUZZ'):
                    info_list[port][tool].append({
                        'FUZZ': result.get('input').get('FUZZ'),
                        'url': result.get('url'),
                        'status': result.get('status')
                    })

    elif tool == 'nikto' and content.get('vulnerabilities'):
        info_list[port][tool] = []
        vulnerabilities = content.get('vulnerabilities')
        if isinstance(vulnerabilities, list):
            for result in vulnerabilities:
                if isinstance(result, dict):
                    info_list[port][tool].append({
                        'references': result.get('references'),
                        'url': result.get('url'),
                        'msg': result.get('msg')
                    })

    elif tool == 'ssh-audit':
        info_list[port][tool] = {}

        if content.get('banner') and isinstance(content.get('banner'), dict):
            banner = content.get('banner')
            info_list[port][tool]['protocol'] = banner.get('protocol')
            info_list[port][tool]['software'] = banner.get('software')

        if content.get('cves'):
            info_list[port][tool]['cves'] = content.get('cves')

        for category in ['enc', 'kex', 'key', 'mac']:
            category_data = content.get(category, [])
            if isinstance(category_data, list):
                for algorithm in category_data:
                    if isinstance(algorithm, dict) and algorithm.get('notes'):
                        notes = algorithm.get('notes', {})
                        if isinstance(notes, dict) and (notes.get('fail') or notes.get('warn')):
                            alg_name = algorithm.get('algorithm')
                            if alg_name:
                                info_list[port][tool][alg_name] = {
                                    'fail': notes.get('fail'),
                                    'warn': notes.get('warn')
                                }

    elif tool == 'whatweb' and content.get('plugins'):
        plugins = content.get('plugins', {})
        if isinstance(plugins, dict):
            info_list[port][tool] = {}

            if plugins.get('HTTPServer') and isinstance(plugins.get('HTTPServer'), dict):
                plugin_data = plugins.get('HTTPServer')
                info_list[port][tool]["HTTPServer"] = {
                    'string': plugin_data.get('string'),
                    'os': plugin_data.get('os')
                }

            for plugin_name in ['Apache', 'Nginx', 'IIS', 'PhpMyAdmin', 'Tomcat', 'Jenkins', 'GitLab', 'Confluence',
                                'JIRA', 'MySQL', 'WordPress',
                                'Drupal', 'Joomla', 'JQuery', 'Bootstrap', 'OutdatedJS']:
                if plugins.get(plugin_name):
                    plugin_data = plugins.get(plugin_name, {})
                    if isinstance(plugin_data, dict):
                        info_list[port][tool][plugin_name] = {
                            'version': plugin_data.get('version')
                        }

            if plugins.get('X-Powered-By') and isinstance(plugins.get('X-Powered-By'), dict):
                info_list[port][tool]["X-Powered-By"] = {
                    'string': plugins.get('X-Powered-By', {}).get('string')
                }

            if plugins.get('DirectoryListing'):
                info_list[port][tool]["DirectoryListing"] = plugins.get('DirectoryListing')

            if plugins.get('DefaultCredentials') and isinstance(plugins.get('DefaultCredentials'), dict):
                info_list[port][tool]["DefaultCredentials"] = plugins.get('DefaultCredentials', {}).get('string')

    elif tool == 'enum4linux' and content.get('target'):
        info_list[port][tool] = {}

        listeners = content.get('listeners', {})
        if isinstance(listeners, dict):
            for service, data in listeners.items():
                if isinstance(data, dict) and data.get('accessible'):
                    info_list[port][tool][service] = {  # Fixed: removed curly braces
                        'accessible': data.get('accessible')
                    }

        smb_dialects = content.get('smb_dialects', {})
        if isinstance(smb_dialects, dict):
            supported_dialects = smb_dialects.get('Supported dialects', {})
            if isinstance(supported_dialects, dict):
                info_list[port][tool]["smb_dialects"] = {
                    'smb_1_0': supported_dialects.get('SMB 1.0'),
                    'smb_signing_required': smb_dialects.get('SMB signing required')
                }

        users = content.get('users', {})
        if isinstance(users, dict):
            info_list[port][tool]["users"] = {}
            for user_id, user_data in users.items():
                if isinstance(user_data, dict) and user_data.get('username'):
                    info_list[port][tool]["users"][user_id] = user_data.get('username')

        policy = content.get('policy', {})
        if isinstance(policy, dict):
            domain_password_info = policy.get('Domain password information', {})
            if isinstance(domain_password_info, dict):
                password_properties = domain_password_info.get('Password properties')
                if isinstance(password_properties, list) and len(password_properties) > 0:
                    props = password_properties[0]
                    if isinstance(props, dict):
                        info_list[port][tool]["policy"] = {
                            'min_password_length': domain_password_info.get('Minimum password length'),
                            'DOMAIN_PASSWORD_COMPLEX': props.get('DOMAIN_PASSWORD_COMPLEX'),
                            'DOMAIN_PASSWORD_NO_ANON_CHANGE': props.get('DOMAIN_PASSWORD_NO_ANON_CHANGE'),
                            'DOMAIN_PASSWORD_NO_CLEAR_CHANGE': props.get('DOMAIN_PASSWORD_NO_CLEAR_CHANGE'),
                            'DOMAIN_PASSWORD_LOCKOUT_ADMINS': props.get('DOMAIN_PASSWORD_LOCKOUT_ADMINS'),
                            'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT': props.get(
                                'DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT')
                        }

    elif tool == 'hydra' and content.get('success'):
        info_list[port][tool] = []
        results = content.get('results', [])
        if isinstance(results, list):
            for success in results:
                if isinstance(success, dict):
                    info_list[port][tool].append({
                        'login': success.get('login'),
                        'password': success.get('password')
                    })

    elif tool == 'smtp_user_enum' and content.get('valid_users'):
        valid_users = content.get('valid_users', [])
        if isinstance(valid_users, list):
            info_list[port][tool] = []
            for user in valid_users:
                info_list[port][tool].append(user)

    elif tool == 'sslscan':
        info_list[port][tool] = {}

        protocols = content.get('protocols', {})
        if isinstance(protocols, dict):
            enabled_protocols = {}
            for protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                if protocols.get(protocol):
                    enabled_protocols[protocol] = protocols.get(protocol)

            if enabled_protocols:
                info_list[port][tool]["protocols"] = enabled_protocols

        cipher_suites = content.get('cipher_suites', {})
        if isinstance(cipher_suites, dict):
            cipher_info = {}

            if cipher_suites.get('weak'):
                cipher_info['weak'] = cipher_suites.get('weak')
            if cipher_suites.get('insecure'):
                cipher_info['insecure'] = cipher_suites.get('insecure')

            if cipher_info:
                info_list[port][tool]["ciphers"] = cipher_info

        certificate = content.get('certificate', {})
        if isinstance(certificate, dict):
            info_list[port][tool]["certificate"] = {
                "expired": certificate.get('expired'),
                "self_signed": certificate.get('self_signed'),
                "short_key": certificate.get('short_key'),
            }

    elif tool == 'wpscan':
        info_list[port][tool] = {}

        version_data = content.get('version')
        if isinstance(version_data, dict):
            info_list[port][tool]["version"] = version_data.get('number')
            info_list[port][tool]["release"] = version_data.get('release_date')
            info_list[port][tool]["secure"] = version_data.get('status') == 'secure'
            info_list[port][tool]["vulnerabilities"] = []

            vulnerabilities = version_data.get('vulnerabilities', [])
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        cve_refs = vuln.get('references', {})
                        cve_list = cve_refs.get('cve', []) if isinstance(cve_refs, dict) else []
                        cve_value = cve_list[0] if isinstance(cve_list, list) and cve_list else ''

                        info_list[port][tool]["vulnerabilities"].append({
                            "title": vuln.get('title'),
                            "cve": cve_value
                        })

        interesting_findings = content.get('interesting_findings')
        if isinstance(interesting_findings, list):
            info_list[port][tool]["interesting_findings"] = []
            for item in interesting_findings:
                if isinstance(item, dict):
                    url = item.get('url')
                    if url:
                        info_list[port][tool]["interesting_findings"].append(url)

        plugins = content.get('plugins', {})
        if isinstance(plugins, dict):
            info_list[port][tool]["plugins"] = {}

            for plugin_slug, plugin_data in plugins.items():
                if isinstance(plugin_data, dict):
                    version_info = plugin_data.get('version', {})
                    plugin_version = version_info.get('number') if isinstance(version_info, dict) else None

                    info_list[port][tool]["plugins"][plugin_slug] = {
                        "version": plugin_version,
                        "latest_version": plugin_data.get('latest_version'),
                        "outdated": plugin_data.get('outdated'),
                        "vulnerabilities": []
                    }

                    vulnerabilities = plugin_data.get("vulnerabilities", [])
                    if isinstance(vulnerabilities, list):
                        for vuln in vulnerabilities:
                            if isinstance(vuln, dict):
                                cve_refs = vuln.get('references', {})
                                cve_list = cve_refs.get('cve', []) if isinstance(cve_refs, dict) else []
                                cve_value = cve_list[0] if isinstance(cve_list, list) and cve_list else ''

                                info_list[port][tool]["plugins"][plugin_slug]["vulnerabilities"].append({
                                    "title": vuln.get('title'),
                                    "cve": cve_value
                                })

        main_theme = content.get('main_theme')
        if isinstance(main_theme, dict):
            version_info = main_theme.get('version', {})
            theme_version = version_info.get('number') if isinstance(version_info, dict) else None

            info_list[port][tool]["main_theme"] = {
                "name": main_theme.get('style_name'),
                "version": theme_version,
                "latest_version": main_theme.get('latest_version'),
                "outdated": main_theme.get('outdated'),
                "vulnerabilities": []
            }

            vulnerabilities = main_theme.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        cve_refs = vuln.get('references', {})
                        cve_list = cve_refs.get('cve', []) if isinstance(cve_refs, dict) else []
                        cve_value = cve_list[0] if isinstance(cve_list, list) and cve_list else ''

                        info_list[port][tool]["main_theme"]["vulnerabilities"].append({
                            "title": vuln.get('title'),
                            "cve": cve_value
                        })

        users = content.get('users', {})
        if isinstance(users, dict):
            info_list[port][tool]["users"] = []
            for username, user_data in users.items():
                info_list[port][tool]["users"].append(username)

        themes = content.get('themes', {})
        if isinstance(themes, dict):
            info_list[port][tool]["themes"] = {}
            for theme_slug, theme_data in themes.items():
                if isinstance(theme_data, dict):
                    version_info = theme_data.get('version', {})
                    theme_version = version_info.get('number') if isinstance(version_info, dict) else None

                    info_list[port][tool]["themes"][theme_slug] = {
                        "version": theme_version,
                        "latest_version": theme_data.get('latest_version'),
                        "outdated": theme_data.get('outdated'),
                        "vulnerabilities": []
                    }

                    vulnerabilities = theme_data.get("vulnerabilities", [])
                    if isinstance(vulnerabilities, list):
                        for vuln in vulnerabilities:
                            if isinstance(vuln, dict):
                                cve_refs = vuln.get('references', {})
                                cve_list = cve_refs.get('cve', []) if isinstance(cve_refs, dict) else []
                                cve_value = cve_list[0] if isinstance(cve_list, list) and cve_list else ''

                                info_list[port][tool]["themes"][theme_slug]["vulnerabilities"].append({
                                    "title": vuln.get('title'),
                                    "cve": cve_value
                                })

    elif tool == 'nftp' and content.get('scan_result'):
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            raw_output = scan_result.get('raw_output', {})
            if isinstance(raw_output, dict):
                host_data = raw_output.get('scan', {})
                if isinstance(host_data, dict):
                    for ip, ip_data in host_data.items():
                        if isinstance(ip_data, dict):
                            tcp = ip_data.get('tcp', {})
                            if isinstance(tcp, dict):
                                port_data = tcp.get(str(port), {})
                                if isinstance(port_data, dict):
                                    scripts = port_data.get('script', {})

                                    info_list[port][tool] = {}

                                    # Basic service information
                                    if port_data.get('product'):
                                        info_list[port][tool]['product'] = port_data['product']
                                    if port_data.get('version'):
                                        info_list[port][tool]['version'] = port_data['version']
                                    if port_data.get('extrainfo'):
                                        info_list[port][tool]['extrainfo'] = port_data['extrainfo']

                                    if isinstance(scripts, dict):
                                        ftp_bounce = scripts.get("ftp-bounce", "")
                                        if isinstance(ftp_bounce, str):
                                            info_list[port][tool][
                                                'ftp_bounce_vulnerable'] = "bounce working" in ftp_bounce.lower()

                                        ftp_vuln_cve2010_4221 = scripts.get("ftp-vuln-cve2010-4221", "")
                                        if isinstance(ftp_vuln_cve2010_4221, str):
                                            info_list[port][tool][
                                                'ftp_vuln_cve2010_4221'] = "vulnerable" in ftp_vuln_cve2010_4221.lower()

                                        ftp_libopie = scripts.get("ftp-libopie", "")
                                        if isinstance(ftp_libopie, str):
                                            info_list[port][tool][
                                                'ftp_vuln_cve2010_1938'] = "vulnerable" in ftp_libopie.lower()

                                        ftp_ls = scripts.get("ftp-ls", "")
                                        if isinstance(ftp_ls, str):
                                            info_list[port][tool]['directory_listing'] = ftp_ls.strip()

                                        ftp_proftpd_backdoor = scripts.get("ftp-proftpd-backdoor", "")
                                        if isinstance(ftp_proftpd_backdoor, str):
                                            info_list[port][tool][
                                                'proftpd_backdoor'] = "VULNERABLE" in ftp_proftpd_backdoor

                                        ftp_vsftpd_backdoor = scripts.get("ftp-vsftpd-backdoor", "")
                                        if isinstance(ftp_vsftpd_backdoor, str):
                                            info_list[port][tool][
                                                'vsftpd_backdoor'] = "VULNERABLE" in ftp_vsftpd_backdoor

    elif tool == 'nssh' and content.get('scan_result'):
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            raw_output = scan_result.get('raw_output', {})
            if isinstance(raw_output, dict):
                host_data = raw_output.get('scan', {})
                if isinstance(host_data, dict):
                    for ip, ip_data in host_data.items():
                        if isinstance(ip_data, dict):
                            tcp = ip_data.get('tcp', {})
                            if isinstance(tcp, dict):
                                port_data = tcp.get(str(port), {})
                                if isinstance(port_data, dict):
                                    scripts = port_data.get('script', {})

                                    info_list[port][tool] = {}

                                    if port_data.get('product'):
                                        info_list[port][tool]['product'] = port_data['product']
                                    if port_data.get('version'):
                                        info_list[port][tool]['version'] = port_data['version']
                                    if port_data.get('extrainfo'):
                                        info_list[port][tool]['extrainfo'] = port_data['extrainfo']

                                    if isinstance(scripts, dict):
                                        ssh_pubkey = scripts.get("ssh-publickey-acceptance", "")
                                        if isinstance(ssh_pubkey, str):
                                            info_list[port][tool][
                                                'publickey_acceptance'] = "no public keys accepted" not in ssh_pubkey.lower()

    elif tool == 'nsmb' and content.get('scan_result'):
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            raw_output = scan_result.get('raw_output', {})
            if isinstance(raw_output, dict):
                scan_data = raw_output.get('scan', {})
                if isinstance(scan_data, dict):
                    for ip, ip_data in scan_data.items():
                        if isinstance(ip_data, dict):
                            info_list[port][tool] = {}
                            tcp = ip_data.get('tcp', {})
                            if isinstance(tcp, dict):
                                port_data = tcp.get(str(port), {})
                                if isinstance(port_data, dict):
                                    if port_data.get('product'):
                                        info_list[port][tool]['product'] = port_data['product']
                                    if port_data.get('version'):
                                        info_list[port][tool]['version'] = port_data['version']

                            hostscript = ip_data.get('hostscript', [])
                            if isinstance(hostscript, list):
                                for script in hostscript:
                                    if isinstance(script, dict):
                                        output = script.get('output', "")
                                        if not isinstance(output, str):
                                            continue
                                        output = output.strip()
                                        if not output:
                                            continue
                                        sid = script.get('id')

                                        if sid == "smb-security-mode":
                                            for line in output.splitlines():
                                                if line.startswith("account_used:"):
                                                    info_list[port][tool]['account_used'] = line.split(":", 1)[
                                                        1].strip()
                                                elif line.startswith("authentication_level:"):
                                                    info_list[port][tool]['authentication_level'] = line.split(":", 1)[
                                                        1].strip()
                                                elif line.startswith("message_signing:"):
                                                    info_list[port][tool]['message_signing'] = line.split(":", 1)[
                                                        1].strip()

                                        elif sid == "smb-protocols":
                                            dialects = [l.strip() for l in output.splitlines() if
                                                        l.strip() and not l.startswith("dialects:")]
                                            if dialects:
                                                info_list[port][tool]['dialects'] = dialects

                                        elif sid and isinstance(sid, str) and sid.startswith("smb-vuln-"):
                                            info_list[port][tool].setdefault('vulnerabilities', {})
                                            if output.startswith("VULNERABLE:"):
                                                info_list[port][tool]['vulnerabilities'][sid] = "true"
                                            else:
                                                info_list[port][tool]['vulnerabilities'][sid] = output

    elif tool == 'nsmtp' and content.get('scan_result'):
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            raw_output = scan_result.get('raw_output', {})
            if isinstance(raw_output, dict):
                scan_data = raw_output.get('scan', {})
                if isinstance(scan_data, dict):
                    for ip, host_data in scan_data.items():
                        if isinstance(host_data, dict):
                            tcp_data = host_data.get("tcp", {})
                            if isinstance(tcp_data, dict):
                                port_data = tcp_data.get(str(port), {})
                                if isinstance(port_data, dict):
                                    scripts = port_data.get('script', {})

                                    commands = None
                                    if isinstance(scripts, dict) and scripts.get('smtp-commands'):
                                        smtp_commands = scripts['smtp-commands']
                                        if isinstance(smtp_commands, str):
                                            commands = [c.strip() for c in smtp_commands.split(',') if c.strip()]

                                    open_relay = None
                                    if isinstance(scripts, dict) and scripts.get('smtp-open-relay'):
                                        smtp_open_relay = scripts['smtp-open-relay']
                                        if isinstance(smtp_open_relay, str):
                                            open_relay = "Server doesn't seem to be an open relay" not in smtp_open_relay.lower()

                                    vuln_cve2010_4344 = None
                                    if isinstance(scripts, dict) and scripts.get('smtp-vuln-cve2010-4344'):
                                        smtp_vuln = scripts['smtp-vuln-cve2010-4344']
                                        if isinstance(smtp_vuln, str):
                                            vuln_cve2010_4344 = "not vulnerable" not in smtp_vuln.lower()

                                    enum_users = None
                                    if isinstance(scripts, dict) and scripts.get('smtp-enum-users'):
                                        smtp_enum = scripts['smtp-enum-users']
                                        if isinstance(smtp_enum,
                                                      str) and "couldn't find any accounts" not in smtp_enum.lower():
                                            enum_users = [u.strip() for u in smtp_enum.splitlines() if u.strip()]

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
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            raw_output = scan_result.get('raw_output', {})
            if isinstance(raw_output, dict):
                host_data = raw_output.get('scan', {})
                if isinstance(host_data, dict):
                    for ip, ip_data in host_data.items():
                        if isinstance(ip_data, dict):
                            tcp = ip_data.get('tcp', {})
                            if isinstance(tcp, dict):
                                port_data = tcp.get(str(port), {})
                                if isinstance(port_data, dict):
                                    scripts = port_data.get('script', {})

                                    info_list[port][tool] = {}

                                    # http-title
                                    if isinstance(scripts, dict) and scripts.get("http-title"):
                                        http_title = scripts.get("http-title")
                                        if isinstance(http_title, str):
                                            info_list[port][tool]['http_title'] = http_title.partition('\n')[0]

                                    # http-favicon (matched or False)
                                    if isinstance(scripts, dict) and scripts.get("http-favicon"):
                                        http_favicon = scripts.get("http-favicon")
                                        if isinstance(http_favicon, str) and "unknown" not in http_favicon.lower():
                                            info_list[port][tool]['http_favicon'] = http_favicon.strip()
                                        else:
                                            info_list[port][tool]['http_favicon'] = False
                                    else:
                                        info_list[port][tool]['http_favicon'] = False

                                    # http-git
                                    if isinstance(scripts, dict) and scripts.get("http-git"):
                                        http_git = scripts.get("http-git")
                                        if isinstance(http_git, str) and "git repository found!" in http_git.lower():
                                            info_list[port][tool]['http_git'] = {}

                                            urls = [line.strip() for line in http_git.split('\n') if
                                                    line.strip().startswith('http')]
                                            if urls:
                                                info_list[port][tool]['http_git']['url'] = urls[0].strip()

                                            type_lines = [line for line in http_git.split('\n') if
                                                          'Project type:' in line]
                                            if type_lines:
                                                info_list[port][tool]['http_git']['type'] = \
                                                type_lines[0].split('Project type:')[1].strip()
                                        else:
                                            info_list[port][tool]['http_git'] = False
                                    else:
                                        info_list[port][tool]['http_git'] = False

                                    # http-robots.txt (True if present)
                                    if isinstance(scripts, dict) and scripts.get("http-robots.txt"):
                                        text = scripts.get("http-robots.txt", "")
                                        if isinstance(text, str):
                                            disallowed = []

                                            # Split by "disallowed entry" and process each part
                                            parts = text.split('disallowed entry')
                                            for i in range(1,
                                                           len(parts)):  # Skip first part (before any "disallowed entry")
                                                part = parts[i]
                                                # Find the newline and extract what comes after it
                                                if '\n' in part:
                                                    lines_after = part.split('\n')[
                                                                  1:]  # Get all lines after the first one
                                                    for line in lines_after:
                                                        line = line.strip()
                                                        if line:  # Only add non-empty entries
                                                            disallowed.append(line)
                                                            break  # Only take the first non-empty line after each "disallowed entry"

                                            info_list[port][tool]['http_robots'] = disallowed if disallowed else False
                                        else:
                                            info_list[port][tool]['http_robots'] = False
                                    else:
                                        info_list[port][tool]['http_robots'] = False

                                    # http-auth-finder (url inside FORM or False)
                                    if isinstance(scripts, dict) and scripts.get("http-auth-finder"):
                                        http_auth_finder = scripts.get("http-auth-finder", "")
                                        if isinstance(http_auth_finder, str):
                                            lines = [l.strip() for l in http_auth_finder.splitlines() if "FORM" in l]
                                            if lines:
                                                # Extract just the URLs where FORM was detected
                                                urls = [l.split()[0] for l in lines if l.startswith("http")]
                                                info_list[port][tool]['http_auth_finder'] = urls if urls else False
                                            else:
                                                info_list[port][tool]['http_auth_finder'] = False
                                        else:
                                            info_list[port][tool]['http_auth_finder'] = False
                                    else:
                                        info_list[port][tool]['http_auth_finder'] = False

                                    # http-methods (list if PUT/DELETE/TRACE present, else False)
                                    if isinstance(scripts, dict) and scripts.get("http-methods"):
                                        methods_line = scripts.get("http-methods", "")
                                        if isinstance(methods_line, str):
                                            methods = []
                                            for verb in ["PUT", "DELETE", "TRACE"]:
                                                if verb in methods_line:
                                                    methods.append(verb)
                                            info_list[port][tool][
                                                'http_methods'] = methods if methods else "No risky methods detected"
                                        else:
                                            info_list[port][tool]['http_methods'] = False
                                    else:
                                        info_list[port][tool]['http_methods'] = False

                                    # http-waf-detect (True/False)
                                    if isinstance(scripts, dict) and scripts.get("http-waf-detect"):
                                        http_waf = scripts.get("http-waf-detect")
                                        if isinstance(http_waf, str):
                                            info_list[port][tool]['http_waf_detect'] = "detected" in http_waf.lower()
                                        else:
                                            info_list[port][tool]['http_waf_detect'] = False
                                    else:
                                        info_list[port][tool]['http_waf_detect'] = False

                                    # http-open-proxy (true, false or possible)
                                    if isinstance(scripts, dict) and scripts.get("http-open-proxy"):
                                        http_open_proxy = scripts.get("http-open-proxy")
                                        if isinstance(http_open_proxy, str):
                                            output_lower = http_open_proxy.lower()
                                            if "potentially open proxy" in output_lower:
                                                info_list[port][tool]['http_open_proxy'] = True
                                            elif "proxy might be redirecting" in output_lower:
                                                info_list[port][tool]['http_open_proxy'] = "possible"
                                            else:
                                                info_list[port][tool]['http_open_proxy'] = False
                                        else:
                                            info_list[port][tool]['http_open_proxy'] = False
                                    else:
                                        info_list[port][tool]['http_open_proxy'] = False

    elif tool == 'nmap':
        scan_result = content.get('scan_result', {})
        if isinstance(scan_result, dict):
            os_info = scan_result.get('os_info', {})
            addresses = os_info.get('addresses', {}) if isinstance(os_info, dict) else {}

            info_list[port][tool] = {
                'target_ip': scan_result.get('ip_address'),
                'open_ports': scan_result.get('open_ports', []),
                'os': os_info.get('name') if isinstance(os_info, dict) else None,
                'family': os_info.get('osfamily') if isinstance(os_info, dict) else None,
                'vendor': os_info.get('vendor') if isinstance(os_info, dict) else None,
                'type': os_info.get('type') if isinstance(os_info, dict) else None,
                'mac': addresses.get('mac') if isinstance(addresses, dict) else None
            }

    return info_list


class ResultAnalyzer:
    def __init__(self, input_dict):
        self.input_dict = input_dict
        self.results = {}

    def start(self):
        if not isinstance(self.input_dict, dict):
            return self.results

        for tool, content in self.input_dict.items():
            if not isinstance(content, dict):
                continue

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
                if useful_info and isinstance(useful_info, dict):
                    for port_num, tool_data in useful_info.items():
                        if isinstance(tool_data, dict):
                            if port_num not in self.results:
                                self.results[port_num] = {}

                            self.results[port_num].update(tool_data)

        return self.results