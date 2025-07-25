class ScanResult:
    "Nmap scans results parsing"

    def __init__(self, ip_address, hostnames=None, open_ports=None, services=None, os_info=None):
        self.ip_address = ip_address
        self.hostnames = hostnames if hostnames is not None else []
        self.open_ports = open_ports if open_ports is not None else []
        self.services = services if services is not None else {}  # {port: service_info}
        self.os_info = os_info if os_info is not None else {}

    def __str__(self):
        result_str = f"Scan Result for IP: {self.ip_address}\n"
        if self.hostnames:
            result_str += f"Hostnames: {', '.join(self.hostnames)}\n"
        if self.open_ports:
            result_str += f"Porte Aperte: {', '.join(map(str, self.open_ports))}\n"
            for port in sorted(self.open_ports):
                service_info = self.services.get(port, {})
                service_name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                extrainfo = service_info.get('extrainfo', '')

                # Costruisci la stringa del servizio
                service_str = service_name
                if product and product != 'N/A':
                    service_str += f" {product}"
                if version and version != 'N/A':
                    service_str += f" {version}"
                if extrainfo and extrainfo != 'N/A':
                    service_str += f" ({extrainfo})"

                result_str += f"{port:<9} open  {service_str}\n"

        if self.os_info:
            result_str += f"\nOS Detection:\n"
            result_str += "-" * 30 + "\n"
            for key, value in self.os_info.items():
                if key == 'cpe' and isinstance(value, list):
                    result_str += f"  {key}: {', '.join(value)}\n"
                else:
                    result_str += f"  {key}: {value}\n"

        return result_str

    def to_dict(self):
        """Convert ScanResult object to dictionary."""
        return {
            "ip_address": self.ip_address,
            "hostnames": self.hostnames,
            "open_ports": self.open_ports,
            "services": self.services,
            "os_info": self.os_info
        }