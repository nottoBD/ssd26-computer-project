# CA helper endpoints used by the app to bootstrap and validate doctor certificates
# Backed by step-ca + OpenSSL inside the server container, not by Django crypto primitives
# Exposes root CA and signs CSRs, so keep strict input validation and rate limiting at the edge
import os
import tempfile
import subprocess

from cryptography.x509 import load_pem_x509_csr
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import ExtensionNotFound
from cryptography.x509 import RFC822Name

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.http import HttpResponse

# Step-CA connection and file paths come from env so dev/prod can mount different CA material
# STEP_ROOT and STEP_INTERMEDIATE are used for chain validation (trust anchor + untrusted intermediate)
# STEP_PASSWORD_FILE is only expected to exist in the CA container or a trusted signer container
STEP_CA_URL = os.getenv("STEP_CA_URL", "https://step-ca:9000")
STEP_ROOT = os.getenv("STEP_ROOT", "/ca/certs/root_ca.crt")
STEP_INTERMEDIATE = os.getenv("STEP_INTERMEDIATE", "/ca/certs/intermediate_ca.crt")
STEP_PROVISIONER = os.getenv("STEP_PROVISIONER", "healthsecure-provisioner")
STEP_PASSWORD_FILE = os.getenv("STEP_PASSWORD_FILE", "/home/step/secrets/password")


# Thin wrapper around the step CLI so we get consistent error messages and non-zero exit handling
# Uses capture_output to avoid leaking secrets to logs and to return readable diagnostics to the caller
def _run_step(args):
    try:
        return subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
            # stdin is present to support future interactive flows, currently not used
            stdin=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("step CLI not found in the container") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"step failed: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc


# Verifies that a presented leaf certificate chains back to our Step root via the intermediate
# Extracts CN for UI display and auditing, does not establish identity on its own
def verify_certificate(certificate):
    # Defensive parsing: only take the first PEM block to avoid concatenated input tricks
    cert = certificate.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"

    # Use a temp file because openssl verify/x509 expect a file path
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    try:
        cert_file.write(cert.encode("utf-8"))
        cert_file.flush()
        cert_file.close()
        # Verify chain: trust anchor is STEP_ROOT, intermediate provided as untrusted candidate
        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                STEP_ROOT,
                "-untrusted",
                STEP_INTERMEDIATE,
                cert_file.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        if "OK" not in verify.stdout:
            return {"valid": False, "detail": verify.stderr}

        # Read subject to extract CN for display, not used as an authorization decision
        inspect = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                cert_file.name,
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cn = None
        subject = inspect.stdout.strip()
        if "CN=" in subject:
            cn = subject.split("CN=")[-1].split(",")[0].strip()

        return {"valid": True, "cn": cn}
    except subprocess.CalledProcessError as exc:
        return {"valid": False, "detail": exc.stderr}
    # Always remove temp file to avoid leaving certificate material on disk
    finally:
        try:
            os.unlink(cert_file.name)
        except OSError:
            pass


@api_view(["GET"])
@permission_classes([AllowAny])
# Public endpoint to serve the root CA so clients can pin or bootstrap trust locally
# This returns the PEM content only, no authentication required by design
def ca_root(_request):
    try:
        with open(STEP_ROOT, "r", encoding="utf-8") as handle:
            root_pem = handle.read()
    except OSError as exc:
        return Response({"message": "Failed to retrieve root CA", "detail": str(exc)}, status=500)

    return HttpResponse(root_pem, content_type="text/plain")




@api_view(["POST"])
@permission_classes([AllowAny])
# Signs a CSR using step-ca, intended for doctor certificate issuance flows
# We bind issuance to the email SAN from the CSR to avoid relying on CN formatting conventions
def ca_sign(request):
    # Inputs come from JSON body, keep these fields narrow and validated to reduce CA abuse surface
    csr = request.data.get("csr")
    not_after = request.data.get("notAfter")
    not_before = request.data.get("notBefore")

    if not isinstance(csr, str) or "BEGIN CERTIFICATE REQUEST" not in csr:
        return Response({"message": "csr field with PEM CSR is required"}, status=400)

    csr_bytes = csr.encode("utf-8")
    try:
        csr_obj = load_pem_x509_csr(csr_bytes)
        cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs:
            raise ValueError("No Common Name in CSR")
        cn = cn_attrs[0].value

        try:
            san_ext = csr_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            email_sans = san_ext.value.get_values_for_type(RFC822Name)
        except ExtensionNotFound:
            email_sans = []

        if not email_sans:
            raise ValueError("No email SAN in CSR")
        
        # no need .value here
        subject = email_sans[0]  
        
    except Exception as exc:
        return Response({"message": "Failed to parse CSR", "detail": str(exc)}, status=400)

    # Temp files avoid shell quoting issues and keep step CLI usage predictable across environments
    token_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    csr_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    try:
        csr_file.write(csr_bytes)
        csr_file.flush()
        csr_file.close()
        cert_file.close()
        token_file.close()

        # Create a one-time step token scoped to the CSR subject, bounded by optional notBefore/notAfter
        token_args = [
            "step",
            "ca",
            "token",
            subject,
            "--password-file",
            STEP_PASSWORD_FILE,
            "--ca-url",
            STEP_CA_URL,
            "--root",
            STEP_ROOT,
            "--provisioner",
            STEP_PROVISIONER,
            "--output-file",
            token_file.name,
            "--force",  # add --force to avoid problem
        ]
        if not_after:
            token_args.extend(["--not-after", str(not_after)])
        if not_before:
            token_args.extend(["--not-before", str(not_before)])

        _run_step(token_args)

        with open(token_file.name, "r", encoding="utf-8") as handle:
            token = handle.read().strip()

        sign_args = [
            "step",
            "ca",
            "sign",
            "--token",
            token,
            "--force",
            csr_file.name,
            cert_file.name,
        ]

        _run_step(sign_args)

        with open(cert_file.name, "r", encoding="utf-8") as handle:
            certificate = handle.read()
    except RuntimeError as exc:
        return Response({"message": "Signing failed", "detail": str(exc)}, status=500)
    finally:
        for path in (csr_file.name, cert_file.name, token_file.name):
            try:
                os.unlink(path)
            except OSError:
                pass

    return Response({"certificate": certificate})


@api_view(["POST"])
@permission_classes([AllowAny])
# Public verification endpoint used by the UI/backend to validate a presented cert chain and extract CN
# Returns 500 on verify failure here because it indicates trust failure, adjust to 400 if treating as user input
def ca_verify(request):
    cert = request.data.get("cert")
    if not isinstance(cert, str) or "BEGIN CERTIFICATE" not in cert:
        return Response({"message": "cert field with PEM certificate is required"}, status=400)
    # Delegate to openssl chain verification using the configured root and intermediate
    result = verify_certificate(cert)
    if not result["valid"]:
        return Response({"message": "Verification failed", "detail": result.get("detail")}, status=500)
    return Response(result)
