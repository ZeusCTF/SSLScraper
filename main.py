import ssl
import socket

def download_ssl_certificate(hostname, port=443):
    # Create a socket connection to the server
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get the SSL certificate from the server
            certificate = ssock.getpeercert()

    return certificate

def strip_cert(cert):
    print("Other domains")
    for domain in cert['subjectAltName']:
        additional_domain = domain[1]
        try:
            # Get the primary hostname, aliases, and IP addresses, only really want the ip addr
            primary_hostname, aliases, ip_addresses = socket.gethostbyname_ex(additional_domain)
            if ip_addresses:
                print(f"IP Addresses associated with the domain {additional_domain} :", ip_addresses)

            
        except socket.gaierror as e:
            print(f"Error resolving hostname {additional_domain}: {e}")
            continue

if __name__ == "__main__":
    
    target_hostname = input('Enter target domain name: ')
    target_port = 443

    try:
        cert = download_ssl_certificate(target_hostname, target_port)
        strip_cert(cert)


    except ssl.SSLError as e:
        print(f"Error downloading SSL certificate: {e}")
    except socket.error as e:
        print(f"Socket error: {e}")

