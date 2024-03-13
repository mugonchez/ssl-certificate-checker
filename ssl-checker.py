import ssl
import socket
import datetime


def get_issuer_organization(cert):
    for field in cert['issuer']:
        for key, value in field:
            if key == 'organizationName':
                return value
    return None

def check_ssl_expiry(domain, cacert_path):
    try:
        # Create an SSL context
        context = ssl.create_default_context()

        # Load the CA certificates file into the SSL context
        context.load_verify_locations(cacert_path)

        # Establish a secure connection to the domain
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate information
                cert = ssock.getpeercert()

        # Extract the expiry date from the certificate
        expiry_date_str = cert.get('notAfter')

        # Get the issuer organization name
        issuer_organization = get_issuer_organization(cert)
        
        if expiry_date_str:
            # Parse the expiry date string
            expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')

            # Calculate days left until expiry
            today = datetime.datetime.today()
            days_left = (expiry_date - today).days

            # Format the expiry date
            formatted_expiry_date = expiry_date.strftime('%Y-%m-%d %H:%M:%S')

            return days_left, formatted_expiry_date, issuer_organization
        else:
            return "Expiry date not found in certificate"

    except ssl.SSLError as e:
        return "SSL error: {}".format(e)
    except socket.gaierror as e:
        return "Socket gaierror: {}".format(e)

# Example usage:
domain = 'example.com'
cacert_path = '/path/to/cacert.pem'  # Provide the path to your CA certificates file
result = check_ssl_expiry(domain, cacert_path)
if isinstance(result, tuple):
    days_left, formatted_expiry_date, issuer_organization = result
    print("Days left until expiry:", days_left)
    print("Formatted expiry date:", formatted_expiry_date)
    print("Issuer organization:", issuer_organization)
else:
    print(result)