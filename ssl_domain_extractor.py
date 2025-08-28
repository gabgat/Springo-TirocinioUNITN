import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from urllib.parse import urlparse
from printer import printerr, printwarn, printout


def get_domain_from_ip(url):
    domains = []

    try:
        printout(f"Trying to connect to: {url}")

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            printerr(f"Malformed URL - {url}")
            return []

        printout(f"Getting certificate from {host}:{port}")

        cert_pem = ssl.get_server_certificate((host, port), timeout=10)

        if not cert_pem:
            printwarn("No certificate received")
            return []

        printout("PEM certificate received, parsing with cryptography...")

        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())

        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value.get_values_for_type(x509.DNSName):
                domains.append(name)
                printout(f"Domain found (SAN): {name}")

        except x509.ExtensionNotFound:
            printwarn("No SAN found")
        except Exception as e:
            printerr(f"Error extracting SAN: {e}")
            try:
                for ext in cert_obj.extensions:
                    if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        for name in ext.value.get_values_for_type(x509.DNSName):
                            domains.append(name)
                            printout(f"Domain found (SAN alternative): {name}")
            except Exception as alt_e:
                printwarn(f"SAN alternative extraction failed: {alt_e}")

        if not domains:
            try:
                cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    cn = cn_attrs[0].value
                    domains.append(cn)
                    printout(f"Domain found (CN): {cn}")
            except (IndexError, AttributeError):
                printwarn("No Common Name found")

        domains = list(dict.fromkeys(domains))

        if not domains:
            printwarn("No domains found in certificate")
        else:
            printout(f"Extracted domains: {domains}")

    except ImportError as e:
        printerr(f"Cryptography library not installed - {e}")
        return []
    except socket.timeout:
        printwarn(f"Timeout while connecting to {url}")
        return []
    except socket.gaierror as e:
        printerr(f"DNS resolution failed for {url}: {e}")
        return []
    except ssl.SSLError as e:
        printerr(f"SSL error while connecting to {url}: {e}")
        return []
    except ConnectionRefusedError:
        printerr(f"Connection refused by {url}")
        return []
    except Exception as e:
        printerr(f"Error while connecting to {url}: {e}")
        return []

    return domains[0] if domains else None