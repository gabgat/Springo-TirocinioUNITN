class Dispatcher:
    @staticmethod
    def analyze(service_dict):
        if not service_dict:
            return

        for service in service_dict.items():
            svc = service.copy()
            if svc['name'] == 'http':
                print(f"Found HTTP service on port {service['port']}")
                HTTPAnalyzer(svc)
            elif svc['name'] == 'ssh':
                print(f"Found SSH service on port {service['port']}")
            elif svc['name'] == 'ftp':
                print(f"Found FTP service on port {service['port']}")
            elif svc['name'] == 'https':
                print(f"Found HTTPS service on port {service['port']}")
            elif svc['name'] == 'mysql':
                print(f"Found MySQL service on port {service['port']}")
            else:
                print(f"Service {service['name']} has not been implemented yet (port {service['port']})")

class HTTPAnalyzer:
    def __init__(self, scan_result):
        self.scan_result = scan_result