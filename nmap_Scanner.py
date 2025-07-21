import nmap

from nmap_ScanResult import ScanResult

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()


    def start_scan(self, ip, intensity):
        print('\nUsing Nmap versrion ', self.nm.nmap_version())
        print('\nScanning: ', ip)
        ports = ''
        args = ''

        match intensity:
            case 1:
                ports = '1-1024'
                args = '-T3 --source-port 53 -D RND:5,ME --data-length 25 --reason -sV --version-all -O --osscan-guess --open'
            case 2:
                ports = '1-65535'
                args = '-T2 --max-retries 3 -f --source-port 53 -D RND:5,ME --data-length 25 --reason -sV --version-all -O --osscan-guess --open'
            case 3:
                ports = '1-65535'
                args = '-T2 --scan-delay 1s -f --source-port 53 -D RND:5,ME --data-length 25 --reason -sV --version-all -O --osscan-guess --open'

        try:

            self.nm.scan(ip, ports, args)

            if not self.nm.all_hosts():
                print(f"\nNo host found for {ip}.")
            if self.nm[ip].state() != 'up':
                print(f"\nIs the host at {ip} down?")

            #print(self.nm.get_nmap_last_output())

            host_data = self.nm[ip]

            hostnames = []
            for hostname_entry in host_data.get('hostnames', []):
                if 'name' in hostname_entry:
                    hostnames.append(hostname_entry['name'])

            open_ports = []
            services = {}
            if 'tcp' in host_data:
                for port in host_data['tcp']:
                    port_info = host_data['tcp'][port]
                    if port_info['state'] == 'open':
                        open_ports.append(port)
                        services[port] = {
                            'name': port_info.get('name', 'N/A'),
                            'product': port_info.get('product', 'N/A'),
                            'version': port_info.get('version', 'N/A'),
                            'extrainfo': port_info.get('extrainfo', 'N/A')
                        }

            os_info = {}
            if 'osmatch' in host_data:
                for os_match in host_data['osmatch']:
                    if isinstance(os_match, dict):
                        os_info['name'] = os_match.get('name', 'N/A')
                        os_info['accuracy'] = os_match.get('accuracy', 'N/A')

                        os_classes = os_match.get('osclass')  # Recupera la lista di osclass

                        if isinstance(os_classes, list) and os_classes:  # Controlla se è una lista e non vuota
                            # Prendiamo il primo elemento della lista os_classes
                            # Generalmente è il più rilevante/accurato
                            first_os_class = os_classes[0]

                            if isinstance(first_os_class, dict):  # Assicurati che sia un dizionario
                                os_info['osfamily'] = first_os_class.get('osfamily', 'N/A')
                                os_info['vendor'] = first_os_class.get('vendor', 'N/A')
                                os_info['type'] = first_os_class.get('type', 'N/A')
                                os_info['osgen'] = first_os_class.get('osgen', 'N/A')  # Aggiunto osgen
                                os_info['cpe'] = first_os_class.get('cpe', [])  # Aggiunto cpe
                            else:
                                print(f"ATTENZIONE: Primo elemento di 'osclass' inatteso, tipo: {type(first_os_class)}")
                        elif os_classes is not None:
                            print(f"ATTENZIONE: 'osclass' inatteso, tipo: {type(os_classes)}")

                        break  # Prendiamo il primo OS match completo
                    else:
                        print(f"ATTENZIONE: Elemento 'os_match' inatteso, tipo: {type(os_match)}")

            return ScanResult(ip, hostnames, open_ports, services, os_info)


        except nmap.PortScannerError as e:
            print(f"Errore Nmap: {e}")
            print(
                "Assicurati che Nmap sia installato e nel tuo PATH, e che tu abbia i permessi necessari (es. esegui come root per scansioni SYN).")
            return None
        except Exception as e:
            print(f"Errore durante la scansione: {e}")
            return None