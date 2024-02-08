import socket
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_certificates(hostname, port=443):
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_default_verify_paths()

    sock = socket.create_connection((hostname, port))
    client = SSL.Connection(context, sock)
    client.set_tlsext_host_name(hostname.encode())
    client.set_connect_state()
    client.do_handshake()
    
    chain = [client.get_peer_certificate()]
    chain.extend(client.get_peer_cert_chain())
    
    client.shutdown()
    sock.close()
    
    return chain

def load_cert(openssl_cert):
    return x509.load_der_x509_certificate(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, openssl_cert),
        default_backend()
    )

def print_certificate_info(cert):
    print("\nCertificate:")
    print(f"  Subject: {cert.subject}")
    print(f"  Issuer: {cert.issuer}")
    print(f"  Valid From: {cert.not_valid_before}")
    print(f"  Valid Until: {cert.not_valid_after}")

def main():
    hostname = input("Enter the domain (e.g., 'example.com'): ")
    chain = get_certificates(hostname)

    chain_certs = [load_cert(cert) for cert in chain]

    print("\nCertificate Chain Information:")
    for cert in chain_certs:
        print_certificate_info(cert)

    # Check for cross-signing
    cross_signed = False
    for i, cert in enumerate(chain_certs):
        for j, other_cert in enumerate(chain_certs):
            if i != j and cert.subject == other_cert.subject and cert.issuer != other_cert.issuer:
                cross_signed = True
                print(f"\nCross-signing detected between certificate {i+1} and {j+1} in the chain.")

    if not cross_signed:
        print("\nNo cross-signing detected in the certificate chain.")

if __name__ == "__main__":
    main()
