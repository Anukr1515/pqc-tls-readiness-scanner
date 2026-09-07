import socket
import ssl
import csv
import json
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


RESULTS_DIR = Path("results")
CSV_FILE = RESULTS_DIR / "raw_results.csv"
JSON_FILE = RESULTS_DIR / "raw_results.json"


def identify_public_key(public_key):
    """
    Identifies the certificate public key algorithm and key detail.
    """

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", str(public_key.key_size)

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECC", public_key.curve.name

    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", str(public_key.key_size)

    return "Unknown", "Unknown"


def identify_signature_algorithm(certificate, public_key_algorithm):
    """
    Creates a clearer certificate signature algorithm label.
    """

    hash_algorithm = (
        certificate.signature_hash_algorithm.name
        if certificate.signature_hash_algorithm
        else "unknown"
    )

    signature_oid = certificate.signature_algorithm_oid._name

    if "rsa" in signature_oid.lower() or public_key_algorithm == "RSA":
        return f"RSA with {hash_algorithm.upper()}"

    if "ecdsa" in signature_oid.lower() or public_key_algorithm == "ECC":
        return f"ECDSA with {hash_algorithm.upper()}"

    if "dsa" in signature_oid.lower() or public_key_algorithm == "DSA":
        return f"DSA with {hash_algorithm.upper()}"

    return f"{signature_oid} with {hash_algorithm.upper()}"


def classify_quantum_risk(
        cipher_suite,
        public_key_algorithm,
        signature_algorithm
):
    """
    Calculates post-quantum migration risk score.

    This score represents dependency on classical
    cryptographic components, not current TLS insecurity.
    """

    risk_score = 0
    breakdown = []
    findings = []

    # ---------------------------
    # Key Exchange Assessment
    # ---------------------------

    cipher_upper = cipher_suite.upper()

    if (
        "ECDHE" in cipher_upper
        or "ECDH" in cipher_upper
        or "X25519" in cipher_upper
    ):
        risk_score += 30
        breakdown.append(
            "Key Exchange: Classical elliptic curve exchange detected (+30)"
        )
        findings.append(
            "ECDHE/ECDH key exchange is vulnerable in a future quantum threat model."
        )

    elif "DHE" in cipher_upper:
        risk_score += 30
        breakdown.append(
            "Key Exchange: Classical Diffie-Hellman detected (+30)"
        )

    else:
        breakdown.append(
            "Key Exchange: Unknown or unsupported mechanism (+15)"
        )
        risk_score += 15

    # ---------------------------
    # Certificate Public Key
    # ---------------------------

    if public_key_algorithm in ["RSA", "ECC", "DSA"]:

        risk_score += 30

        breakdown.append(
            f"Certificate Key: {public_key_algorithm} classical key detected (+30)"
        )

        findings.append(
            f"{public_key_algorithm} certificate key requires PQC migration consideration."
        )

    else:

        breakdown.append(
            "Certificate Key: Unknown algorithm (+10)"
        )

        risk_score += 10

    # ---------------------------
    # Signature Algorithm
    # ---------------------------

    signature_upper = signature_algorithm.upper()

    if (
        "RSA" in signature_upper
        or "ECDSA" in signature_upper
        or "DSA" in signature_upper
    ):

        risk_score += 20

        breakdown.append(
            f"Signature: Classical signature detected (+20)"
        )

        findings.append(
            "Certificate signature uses classical cryptography."
        )

    else:

        breakdown.append(
            "Signature: Unknown algorithm (+5)"
        )

        risk_score += 5

    # ---------------------------
    # PQC Support Detection
    # ---------------------------

    if (
        "ML-KEM" in cipher_upper
        or "KYBER" in cipher_upper
    ):

        risk_score -= 20

        breakdown.append(
            "PQC Support: Hybrid post-quantum mechanism detected (-20)"
        )

    else:

        risk_score += 10

        breakdown.append(
            "PQC Support: No post-quantum mechanism detected (+10)"
        )


    # Limit score

    risk_score = max(0, min(100, risk_score))


    if risk_score >= 70:

        level = "High"
        readiness = "Not Ready"

        recommendation = (
            "The system relies heavily on classical cryptographic "
            "components. Migration planning towards hybrid post-quantum "
            "TLS should be considered."
        )

    elif risk_score >= 40:

        level = "Medium"
        readiness = "Partially Ready"

        recommendation = (
            "The system uses modern TLS but still depends on "
            "classical cryptographic algorithms."
        )

    else:

        level = "Low"
        readiness = "More Ready"

        recommendation = (
            "Lower quantum migration dependency detected."
        )


    return (
        risk_score,
        level,
        readiness,
        recommendation,
        findings,
        breakdown
    )


def scan_domain(domain, port=443):
    """
    Scans one TLS-enabled domain and returns a dictionary of results.
    """

    result = {
        "domain": domain,
        "status": "Failed",
        "error": "",
        "tls_version": "",
        "cipher_suite": "",
        "cipher_protocol": "",
        "cipher_strength": "",
        "subject": "",
        "issuer": "",
        "serial_number": "",
        "not_before": "",
        "not_after": "",
        "certificate_days_remaining": "",
        "certificate_status": "",
        "public_key_algorithm": "",
        "public_key_detail": "",
        "signature_algorithm": "",
        "risk_score": "",
        "risk_level": "",
        "pqc_readiness": "",
        "recommendation": "",
        "findings": []
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                tls_version = secure_sock.version()
                cipher = secure_sock.cipher()
                binary_cert = secure_sock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(binary_cert, default_backend())

                cipher_suite = cipher[0] if cipher else "Not available"
                cipher_protocol = cipher[1] if cipher else "Not available"
                cipher_strength = str(cipher[2]) if cipher else "Not available"

                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                serial_number = str(cert.serial_number)

                not_before = cert.not_valid_before_utc.replace(tzinfo=None)
                not_after = cert.not_valid_after_utc.replace(tzinfo=None)
                days_remaining = (not_after - datetime.now()).days

                public_key = cert.public_key()
                public_key_algorithm, public_key_detail = identify_public_key(public_key)
                signature_algorithm = identify_signature_algorithm(cert, public_key_algorithm)

                if days_remaining < 0:
                    cert_status = "Expired"
                elif days_remaining <= 30:
                    cert_status = "Expiring Soon"
                else:
                    cert_status = "Valid"

                risk_score, risk_level, readiness, recommendation, findings, breakdown = classify_quantum_risk(
                    cipher_suite,
                    public_key_algorithm,
                    signature_algorithm
                )

                result.update({
                    "status": "Success",
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "cipher_protocol": cipher_protocol,
                    "cipher_strength": cipher_strength,
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": serial_number,
                    "not_before": str(not_before),
                    "not_after": str(not_after),
                    "certificate_days_remaining": str(days_remaining),
                    "certificate_status": cert_status,
                    "public_key_algorithm": public_key_algorithm,
                    "public_key_detail": public_key_detail,
                    "signature_algorithm": signature_algorithm,
                    "risk_score": str(risk_score),
                    "risk_level": risk_level,
                    "pqc_readiness": readiness,
                    "recommendation": recommendation,
                    "findings": findings,
                    "breakdown": breakdown
                })

    except socket.timeout:
        result["error"] = "Connection timed out"

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"

    except socket.gaierror:
        result["error"] = "Domain could not be resolved"

    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


def print_result(result):
    """
    Prints scan result in a readable terminal format.
    """

    print("\nTLS Post-Quantum Readiness Scanner - Version 4")
    print("-" * 75)

    print(f"Domain: {result['domain']}")
    print(f"Scan Status: {result['status']}")

    if result["status"] == "Failed":
        print(f"Error: {result['error']}")
        print("-" * 75)
        return

    print(f"TLS Version: {result['tls_version']}")
    print(f"Cipher Suite: {result['cipher_suite']}")
    print(f"Cipher Protocol: {result['cipher_protocol']}")
    print(f"Cipher Strength: {result['cipher_strength']} bits")

    print("\nCertificate Information")
    print("-" * 75)
    print(f"Subject: {result['subject']}")
    print(f"Issuer: {result['issuer']}")
    print(f"Serial Number: {result['serial_number']}")
    print(f"Not Before: {result['not_before']}")
    print(f"Not After: {result['not_after']}")
    print(f"Certificate Days Remaining: {result['certificate_days_remaining']} days")
    print(f"Certificate Status: {result['certificate_status']}")

    print("\nCryptographic Classification")
    print("-" * 75)
    print(f"Certificate Public Key Algorithm: {result['public_key_algorithm']}")
    print(f"Public Key Detail: {result['public_key_detail']}")
    print(f"Certificate Signature Algorithm: {result['signature_algorithm']}")

    print("\nPost-Quantum Migration Readiness")
    print("-" * 75)
    print(f"Quantum Migration Risk Score: {result['risk_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"PQC Readiness Status: {result['pqc_readiness']}")

    print("\nRisk Breakdown")
    print("-" * 75)
    for item in result["breakdown"]:
        print(f"- {item}")

    print("\nFindings")
    print("-" * 75)
    for finding in result["findings"]:
        print(f"- {finding}")

    print("\nRecommendation")
    print("-" * 75)
    print(result["recommendation"])
    print("-" * 75)


def save_results(results):
    """
    Saves scan results to CSV and JSON files.
    """

    RESULTS_DIR.mkdir(exist_ok=True)

    csv_fields = [
        "domain",
        "status",
        "error",
        "tls_version",
        "cipher_suite",
        "cipher_protocol",
        "cipher_strength",
        "public_key_algorithm",
        "public_key_detail",
        "signature_algorithm",
        "certificate_days_remaining",
        "certificate_status",
        "risk_score",
        "risk_level",
        "pqc_readiness",
        "recommendation"
    ]

    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=csv_fields)
        writer.writeheader()

        for result in results:
            row = {field: result.get(field, "") for field in csv_fields}
            writer.writerow(row)

    with open(JSON_FILE, mode="w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nCSV results saved to: {CSV_FILE}")
    print(f"JSON results saved to: {JSON_FILE}")


def main():
    print("\nTLS Post-Quantum Readiness Scanner")
    print("=" * 75)
    print("1. Scan one domain")
    print("2. Scan multiple domains")
    print("=" * 75)

    choice = input("Choose option 1 or 2: ").strip()

    results = []

    if choice == "1":
        domain = input("Enter domain name, example surrey.ac.uk: ").strip()
        if domain:
            result = scan_domain(domain)
            print_result(result)
            results.append(result)

    elif choice == "2":
        domains_input = input("Enter domains separated by commas: ").strip()

        domains = [
            domain.strip()
            for domain in domains_input.split(",")
            if domain.strip()
        ]

        for domain in domains:
            print(f"\nScanning {domain}...")
            result = scan_domain(domain)
            print_result(result)
            results.append(result)

    else:
        print("Invalid option selected.")
        return

    if results:
        save_results(results)


if __name__ == "__main__":
    main()