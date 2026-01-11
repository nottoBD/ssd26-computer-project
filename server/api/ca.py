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

STEP_CA_URL = os.getenv("STEP_CA_URL", "https://step-ca:9000")
STEP_ROOT = os.getenv("STEP_ROOT", "/ca/certs/root_ca.crt")
STEP_INTERMEDIATE = os.getenv("STEP_INTERMEDIATE", "/ca/certs/intermediate_ca.crt")
STEP_PROVISIONER = os.getenv("STEP_PROVISIONER", "healthsecure-provisioner")
STEP_PASSWORD_FILE = os.getenv("STEP_PASSWORD_FILE", "/home/step/secrets/password")


def _run_step(args):
    try:
        return subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("step CLI not found in the container") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"step failed: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc


def verify_certificate(certificate):
    cert = certificate.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    try:
        cert_file.write(cert.encode("utf-8"))
        cert_file.flush()
        cert_file.close()

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
    finally:
        try:
            os.unlink(cert_file.name)
        except OSError:
            pass


@api_view(["GET"])
@permission_classes([AllowAny])
def ca_root(_request):
    try:
        with open(STEP_ROOT, "r", encoding="utf-8") as handle:
            root_pem = handle.read()
    except OSError as exc:
        return Response({"message": "Failed to retrieve root CA", "detail": str(exc)}, status=500)

    return HttpResponse(root_pem, content_type="text/plain")




@api_view(["POST"])
@permission_classes([AllowAny])
def ca_sign(request):
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

    token_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    csr_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    try:
        csr_file.write(csr_bytes)
        csr_file.flush()
        csr_file.close()
        cert_file.close()
        token_file.close()

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
def ca_verify(request):
    cert = request.data.get("cert")
    if not isinstance(cert, str) or "BEGIN CERTIFICATE" not in cert:
        return Response({"message": "cert field with PEM certificate is required"}, status=400)
    result = verify_certificate(cert)
    if not result["valid"]:
        return Response({"message": "Verification failed", "detail": result.get("detail")}, status=500)
    return Response(result)
