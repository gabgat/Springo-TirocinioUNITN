import socket
import ssl


def get_domain_from_ip(url):
    """
    Si connette a un IP e una porta per trovare i domini
    dal certificato SSL/TLS.
    """
    context = ssl.create_default_context()
    domain = None

    try:
        # Crea una connessione TCP e la avvolge con SSL
        with socket.create_connection(url, timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                # Ottiene il certificato del server
                cert = ssock.getpeercert()

                # Estrae il "Subject Alternative Name" (SAN) che contiene tutti i domini validi
                if 'subjectAltName' in cert:
                    for type, value in cert['subjectAltName']:
                        if type == 'DNS':
                            domain = [value]

                # Se il SAN non è presente, prova con il "Common Name" (CN)
                if not domain and 'subject' in cert:
                    for entry in cert['subject']:
                        if entry[0][0] == 'commonName':
                            domain = [entry[0][1]]

    except Exception as e:
        print(f"Errore durante la connessione a {url} - {e}")
        return []

    return domain