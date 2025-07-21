class ScanResult:
    "Nmap scans results parsing"

    def __init__(self, ip_address, hostnames=None, open_ports=None, services=None, os_info=None):
        self.ip_address = ip_address
        self.hostnames = hostnames if hostnames is not None else []
        self.open_ports = open_ports if open_ports is not None else []
        self.services = services if services is not None else {}  # {port: service_info}
        self.os_info = os_info if os_info is not None else {}

    def __str__(self):
        result_str = f"Scansione per IP: {self.ip_address}\n"
        if self.hostnames:
            result_str += f"  Hostnames: {', '.join(self.hostnames)}\n"
        if self.open_ports:
            result_str += f"  Porte Aperte: {', '.join(map(str, self.open_ports))}\n"
        if self.services:
            result_str += "  Servizi:\n"
            for port, service_info in self.services.items():
                result_str += f"    Porta {port}: Nome={service_info.get('name', 'N/A')}, Prodotto={service_info.get('product', 'N/A')}, Versione={service_info.get('version', 'N/A')}\n"
        if self.os_info:
            result_str += "  Informazioni OS:\n"
            for key, value in self.os_info.items():
                result_str += f"    {key}: {value}\n"
        return result_str

    def to_dict(self):
        """Converte l'oggetto ScanResult in un dizionario."""
        return {
            "ip_address": self.ip_address,
            "hostnames": self.hostnames,
            "open_ports": self.open_ports,
            "services": self.services,
            "os_info": self.os_info
        }