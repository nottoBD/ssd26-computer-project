import os
import tempfile
import subprocess

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
        )
    except FileNotFoundError as exc:
        raise RuntimeError("step CLI not found in the container") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"step failed: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc


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

    csr_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    try:
        csr_file.write(csr.encode("utf-8"))
        csr_file.flush()
        csr_file.close()
        cert_file.close()

        args = [
            "step",
            "ca",
            "sign",
            csr_file.name,
            cert_file.name,
            "--password-file",
            STEP_PASSWORD_FILE,
            "--ca-url",
            STEP_CA_URL,
            "--root",
            STEP_ROOT,
            "--provisioner",
            STEP_PROVISIONER,
        ]
        if not_after:
            args.extend(["--not-after", str(not_after)])
        if not_before:
            args.extend(["--not-before", str(not_before)])

        _run_step(args)

        with open(cert_file.name, "r", encoding="utf-8") as handle:
            certificate = handle.read()
    except RuntimeError as exc:
        return Response({"message": "Signing failed", "detail": str(exc)}, status=500)
    finally:
        for path in (csr_file.name, cert_file.name):
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

    cert = cert.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"

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
            return Response({"message": "Verification failed", "detail": verify.stderr}, status=500)

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

        return Response({"valid": True, "cn": cn})
    except subprocess.CalledProcessError as exc:
        return Response({"message": "Verification failed", "detail": exc.stderr}, status=500)
    finally:
        try:
            os.unlink(cert_file.name)
        except OSError:
            pass
