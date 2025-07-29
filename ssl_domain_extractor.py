import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from urllib.parse import urlparse


def get_domain_from_ip(url):
    """
    Si connette a un IP e una porta per trovare i domini
    dal certificato SSL/TLS.
    """

    domains = []

    try:
        print(f"Tentativo di connessione a: {url}")

        # Parsing dell'URL formato https://ip:port
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            print(f"Errore: URL malformato - {url}")
            return []

        print(f"Ottenendo certificato da {host}:{port}")

        # Usa ssl.get_server_certificate() che funziona anche con certificati non validati
        cert_pem = ssl.get_server_certificate((host, port), timeout=10)

        if not cert_pem:
            print("Nessun certificato ricevuto")
            return []

        print("Certificato PEM ricevuto, parsing con cryptography...")

        # Parse del certificato PEM
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())

        # Estrai domini dal Subject Alternative Name
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

            # san_ext.value è un oggetto SubjectAlternativeName, non un iterabile diretto
            # Usa il metodo corretto per iterare sui DNS names
            for name in san_ext.value.get_values_for_type(x509.DNSName):
                domains.append(name)
                print(f"Dominio trovato (SAN): {name}")

        except x509.ExtensionNotFound:
            print("Nessun Subject Alternative Name trovato")
        except Exception as e:
            print(f"Errore durante l'estrazione del SAN: {e}")
            # Prova metodo alternativo per SAN
            try:
                for ext in cert_obj.extensions:
                    if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        for name in ext.value.get_values_for_type(x509.DNSName):
                            domains.append(name)
                            print(f"Dominio trovato (SAN alternativo): {name}")
            except Exception as alt_e:
                print(f"Metodo alternativo SAN fallito: {alt_e}")

        # Se non ci sono domini nel SAN, cerca nel Common Name
        if not domains:
            try:
                cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    cn = cn_attrs[0].value
                    domains.append(cn)
                    print(f"Dominio trovato (CN): {cn}")
            except (IndexError, AttributeError):
                print("Nessun Common Name trovato")

        # Rimuove duplicati mantenendo l'ordine
        domains = list(dict.fromkeys(domains))

        if not domains:
            print("Nessun dominio trovato nel certificato")
        else:
            print(f"Domini estratti: {domains}")

    except ImportError as e:
        print(f"Errore: libreria cryptography non installata - {e}")
        print("Installa con: pip install cryptography")
        return []
    except socket.timeout:
        print(f"Timeout durante la connessione a {url}")
        return []
    except socket.gaierror as e:
        print(f"Errore di risoluzione DNS per {url}: {e}")
        return []
    except ssl.SSLError as e:
        print(f"Errore SSL durante la connessione a {url}: {e}")
        return []
    except ConnectionRefusedError:
        print(f"Connessione rifiutata da {url}")
        return []
    except Exception as e:
        print(f"Errore imprevisto durante la connessione a {url}: {e}")
        return []

    return domains[0] if domains else None