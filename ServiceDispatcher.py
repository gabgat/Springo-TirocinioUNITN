class Dispatcher:
    @staticmethod
    def analyze(service_list):
        if service_list is not None:
            for service in service_list:
                if service['name'] == 'http':
                    print(f"Found HTTP service on port {service['port']}")
                elif service['name'] == 'ssh':
                    print(f"Found SSH service on port {service['port']}")
                elif service['name'] == 'ftp':
                    print(f"Found FTP service on port {service['port']}")
                elif service['name'] == 'https':
                    print(f"Found HTTPS service on port {service['port']}")
                elif service['name'] == 'mysql':
                    print(f"Found MySQL service on port {service['port']}")
                elif service['name'] == 'mssql':
                    print(f"Found MSSQL service on port {service['port']}")
                elif service['name'] == 'postgresql':
                    print(f"Found PostgreSQL service on port {service['port']}")
                elif service['name'] == 'mongodb':
                    print(f"Found MongoDB service on port {service['port']}")
                elif service['name'] == 'redis':
                    print(f"Found Redis service on port {service['port']}")
                elif service['name'] == 'memcached':
                    print(f"Found Memcached service on port {service['port']}")
                else:
                    print(f"Service {service['name']} has not been implemented yet (port {service['port']})")