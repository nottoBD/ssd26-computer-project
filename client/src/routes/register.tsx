import { useState, useRef } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Shield, User, Stethoscope, Fingerprint, Upload } from "lucide-react";
import { startRegistration } from "@simplewebauthn/browser";
import { useAuth } from './__root'
import { GoogleReCaptchaProvider, useGoogleReCaptcha } from "react-google-recaptcha-v3";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import QRCode from 'qrcode';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { encryptAES, bytesToHex, hexToBytes, generateX25519Keypair, deriveEd25519FromX25519, base64ToBytes } from '../components/CryptoUtils'  // Import encryptAES for X25519 priv encryption


export const Route = createFileRoute("/register")({
  component: () => (
    <GoogleReCaptchaProvider reCaptchaKey={import.meta.env.VITE_RECAPTCHA_SITE_KEY}>
      <RegisterPage />
    </GoogleReCaptchaProvider>
  ),
});

function RegisterPage() {
  const navigate = useNavigate();
  const { refreshAuth } = useAuth();
  const { executeRecaptcha } = useGoogleReCaptcha();
  const [userType, setUserType] = useState<"patient" | "doctor">("patient");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [webauthnStarted, setWebauthnStarted] = useState(false);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [privPem, setPrivPem] = useState<string | null>(null); // Store RSA priv key temporarily for largeBlob or fallback
  const formRef = useRef<HTMLFormElement>(null);
  const [xQrModalOpen, setXQrModalOpen] = useState(false);
  const [qrModalOpen, setQrModalOpen] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [modalCloseResolve, setModalCloseResolve] = useState<(() => void) | null>(null);
  const [privInputModalOpen, setPrivInputModalOpen] = useState(false);
  const [privInput, setPrivInput] = useState('');
  const [privInputResolve, setPrivInputResolve] = useState<((value: Uint8Array | null) => void) | null>(null);
  const [privInputError, setPrivInputError] = useState<string | null>(null);

  const handleGenerateCertificate = async () => {
    try {
      if (!formRef.current) {
        throw new Error("Form not available");
      }
      const formData = new FormData(formRef.current);
      const firstName = formData.get("firstName") as string;
      const lastName = formData.get("lastName") as string;
      const email = (formData.get("email") as string).trim().toLowerCase();
      const medicalOrganization = formData.get("medicalOrganization") as string;

      if (!firstName.trim() || !lastName.trim() || !email.trim()) {
        throw new Error("Please fill in first name, last name, and email before generating certificate");
      }

      setLoading(true);
      const crypto = pkijs.getCrypto();

      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true, // Must be extractable to export for largeBlob or fallback
        ["sign", "verify"]
      );

      const csr = new pkijs.CertificationRequest();

      // Problem patch : 
      // Order of DN in CSR
      // CN is now email and not surname name
      
      const cnAttr = new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3", // CN = email address
        value: new asn1js.Utf8String({ value: email })
      });

      csr.subject.typesAndValues.push(cnAttr);

      await csr.subjectPublicKeyInfo.importKey(keyPair.publicKey);

      // Add Subject Alternative Name extension for email
      const generalNames = new pkijs.GeneralNames({
        names: [
          new pkijs.GeneralName({
            type: 1, // rfc822Name (email)
            value: email
          })
        ]
      });

      const subjectAltName = new pkijs.Extension({
        extnID: "2.5.29.17",
        critical: false,
        extnValue: generalNames.toSchema().toBER(false)
      });

      const extensions = new pkijs.Extensions({
        extensions: [subjectAltName]
      });

      csr.attributes = [
        new pkijs.Attribute({
          type: "1.2.840.113549.1.9.14", // extensionRequest
          values: [extensions.toSchema()]
        })
      ];

      await csr.sign(keyPair.privateKey, "SHA-256");

      const csrDer = csr.toSchema().toBER(false);
      const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${btoa(String.fromCharCode(...new Uint8Array(csrDer))).match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE REQUEST-----`;

      console.log("Generated CSR:", csrPem);

      const signResp = await fetch("/api/ca/sign/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csr: csrPem }),
      });

      if (!signResp.ok) {
        const err = await signResp.json();
        throw new Error(err.message || "Signing failed");
      }

      const { certificate } = await signResp.json();

      // Export PrivKey for storage (in largeBlob or fallback)
      const privRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      const privPemLocal = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(privRaw))).match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`;
      setPrivPem(privPemLocal); // Store temporarily for WebAuthn largeBlob

      // certificate as file
      const certBlob = new Blob([certificate], { type: "text/plain" });
      setCertFile(new File([certBlob], "doctor_cert.pem"));

      alert("Certificate generated! Private key will be stored securely during registration (e.g., in TouchID/Windows Hello if supported). If not, you'll be prompted to save it in a password manager.\nNote: Organization info included in CN field.");

    } catch (err) {
      console.error("Certificate generation error:", err);
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading) return;

    setLoading(true);
    setError(null);

    const formData = new FormData(e.currentTarget);
try {
  if (!executeRecaptcha) {
    throw new Error("reCAPTCHA not yet available - please try again");
  }
  const recaptcha_token = await executeRecaptcha("register");

  const payload: any = {
    email: (formData.get("email") as string).trim().toLowerCase(),
    first_name: (formData.get("firstName") as string),
    last_name: (formData.get("lastName") as string),
    type: userType,
    date_of_birth:
      userType === "patient" ? (formData.get("dateOfBirth") as string) : null,
    medical_organization:
      userType === "doctor"
        ? (formData.get("medicalOrganization") as string) : "",

    device_name: (formData.get("deviceName") as string) || "",
    recaptcha_token,
  };

  if (userType === "doctor") {
    if (!certFile) {
      throw new Error("Certificate required for doctor registration");
    }
    if (!privPem) {
      throw new Error("Private key not generated - please generate certificate first");
    }
    payload.certificate = await certFile.text();
  }

  // Check already authenticated
  const authCheck = await fetch("/api/webauthn/auth/status/", { credentials: 'include' });
  
  if (authCheck.ok) {
    const { authenticated } = await authCheck.json();
    if (authenticated) {
      setError("Already logged in - logout first to register new account");
      setLoading(false);
      return;
    }
  } 
        
  const startResp = await fetch("/api/webauthn/register/start/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!startResp.ok) {
    const err = await startResp.json();
    throw new Error(err.error || "Server error during registration start");
  }

  let options = await startResp.json();
      // Cascading secure storage for doctor priv key
      if (userType === "doctor") {
        // Prefer platform authenticator (TouchID/Hello/Chrome built-in)
        const isPlatformAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        options.authenticatorSelection = {
          ...options.authenticatorSelection,
          authenticatorAttachment: isPlatformAvailable ? 'platform' : 'cross-platform',
          residentKey: 'required', // Ensure discoverable for multi-device
          userVerification: 'preferred',
        };

        // Compute salts for PRF
        const prfSaltFirst = await window.crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode("HealthSecure Project - PRF salt v1 - first")
        );
        const prfSaltSecond = await window.crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode("HealthSecure Project - PRF salt v1 - second")
        );

        options.extensions = {
          ...options.extensions,
          prf: {
            eval: {
              first: new Uint8Array(prfSaltFirst),
              second: new Uint8Array(prfSaltSecond),
            },
          },
        };
      }

      // Generate X25519 key pair for all users (E2EE) using noble for compatibility
      const x25519KeyPair = generateX25519Keypair();

      // Public key is already raw Uint8Array (32 bytes)
      payload.x25519_public = bytesToHex(x25519KeyPair.publicKey);

      // Private key is raw Uint8Array – store temporarily
      const x25519PrivRawLocal = x25519KeyPair.privateKey;

const edPub = deriveEd25519FromX25519(x25519PrivRawLocal).publicKey;
  // 2. Show WebAuthn prompt
      setWebauthnStarted(true);

      // 2. Trigger device prompt - Wrap in { optionsJSON } to fix call structure
      const credential = await startRegistration({ optionsJSON: options });

      if (userType === "doctor") {
        const extResults: any = credential.clientExtensionResults;
        const prfResults = extResults?.prf?.results ?? {};
        let prfFirst = prfResults.first ? new Uint8Array(prfResults.first) : null;
        let prfSecond = prfResults.second ? new Uint8Array(prfResults.second) : null;
        let prfBytes: Uint8Array | null = null;

        if (prfFirst && prfSecond) {
          prfBytes = new Uint8Array(prfFirst.length);
          for (let i = 0; i < prfFirst.length; i++) {
            prfBytes[i] = prfFirst[i] ^ prfSecond[i];
          }
        } else if (prfFirst) {
          prfBytes = prfFirst;
        } else if (prfSecond) {
          prfBytes = prfSecond;
        }

        if (prfBytes) {
          // Derive KEK from PRF (AES-256 key)
          const kek = await window.crypto.subtle.importKey(
            "raw",
            prfBytes.slice(0, 32),
            { name: "AES-GCM" },
            false,
            window.__KEK__ = new Uint8Array(prfBytes.slice(0, 32)),
            ["encrypt", "decrypt"]
          );

          // Encrypt privPem
          const iv = window.crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV
          const encryptedPriv = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            kek,
            new TextEncoder().encode(privPem)
          );
          const encryptedB64 = btoa(String.fromCharCode(...new Uint8Array(encryptedPriv)));
          const ivB64 = btoa(String.fromCharCode(...iv));

          // Include in finish body
          credential.encrypted_priv = encryptedB64;
          credential.iv_b64 = ivB64;

          alert("Private key encrypted with PRF-derived KEK and stored securely on server. Accessible across synced devices!");
        } else {
          // Fallback: QR code
          alert("PRF not supported. Generating QR code for secure transfer to password manager (e.g., Bitwarden). Scan and store as a secure note.");
          const qrData = await QRCode.toDataURL(privPem, { errorCorrectionLevel: 'M', scale: 8 });  // High EC for scan reliability

          setQrDataUrl(qrData);
          setPrivPem(null); // Clear immediately after QR generation
          const modalPromise = new Promise<void>(resolve => {
            setModalCloseResolve(() => resolve);
          });
          setQrModalOpen(true);
          await modalPromise;

          // Proceed to finish after user closes modal
        }
        // Clear temp privPem after handling (prevent remanence)
        setPrivPem(null);
      }

      // Handle X25519 private key encryption for all users (using same PRF logic)
      const extResults: any = credential.clientExtensionResults;
      const prfResults = extResults?.prf?.results ?? {};
      let prfFirst = prfResults.first ? new Uint8Array(prfResults.first) : null;
      let prfSecond = prfResults.second ? new Uint8Array(prfResults.second) : null;
      let prfBytes: Uint8Array | null = null;

      if (prfFirst && prfSecond) {
        prfBytes = new Uint8Array(prfFirst.length);
        for (let i = 0; i < prfFirst.length; i++) {
          prfBytes[i] = prfFirst[i] ^ prfSecond[i];
        }
      } else if (prfFirst) {
        prfBytes = prfFirst;
      } else if (prfSecond) {
        prfBytes = prfSecond;
      }

      if (prfBytes) {
        // Derive KEK from PRF (AES-256 key)
        const kek = await window.crypto.subtle.importKey(
          "raw",
          prfBytes.slice(0, 32),
          { name: "AES-GCM" },
          false,
          ["encrypt", "decrypt"]
        );

        // Encrypt X25519 privRaw
        const iv = window.crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV
        const encryptedXPriv = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          kek,
          x25519PrivRawLocal
        );
        const encryptedXB64 = btoa(String.fromCharCode(...new Uint8Array(encryptedXPriv)));
        const ivB64 = btoa(String.fromCharCode(...iv));

        // Include in finish body
        credential.encrypted_xpriv = encryptedXB64;
        credential.xiv_b64 = ivB64;

        // Set private key in memory for the session
        window.__MY_PRIV__ = x25519PrivRawLocal;
        window.__SIGN_PRIV__ = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
      } else {
        // Fallback for X25519: QR code
        alert("PRF not supported for X25519 key storage. Generating QR code for secure transfer to password manager.");
        const xPrivB64 = btoa(String.fromCharCode(...x25519PrivRawLocal));
        const qrText = `${xPrivB64}`;
        const qrData = await QRCode.toDataURL(qrText, { errorCorrectionLevel: 'M', scale: 8 });

        setQrDataUrl(qrData);
        const modalPromise = new Promise<void>(resolve => {
          setModalCloseResolve(() => resolve);
        });
        setXQrModalOpen(true);
        await modalPromise;

        // After QR modal closes, prompt for immediate input
        const privPromise = new Promise<Uint8Array | null>(resolve => {
          setPrivInputResolve(() => resolve);
          // Validation function
          const validatePrivInput = (input: string): boolean => {
            const trimmed = input.trim();
            if (trimmed.length !== 44 || !/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
              setPrivInputError('Invalid base64 key. Must be exactly 44 characters.');
              return false;
            }
            setPrivInputError(null);
            return true;
          };
          setPrivInput('');
        });
        setPrivInputModalOpen(true);
        const privBytes = await privPromise;
        setPrivInputModalOpen(false);
        if (!privBytes) {
          throw new Error("Private key input cancelled or invalid");
        }
        window.__MY_PRIV__ = privBytes;
        window.__SIGN_PRIV__ = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
      }

      credential.public_key = bytesToHex(x25519KeyPair.publicKey);
  credential.signing_public_key = bytesToHex(edPub);
      // 3. Finish registration
      const finishResp = await fetch("/api/webauthn/register/finish/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
      });

        if (!finishResp.ok) {
            const text = await finishResp.text();
            console.log('Finish response text:', text);
            const err = JSON.parse(text); // or try/catch
            throw new Error(err.error || "Registration failed on server");
        }
      const finishData = await finishResp.json();  // Assume backend returns {status: 'OK', user_id: str} on success
      const userId = finishData.user_id;  // Get from response; if not, fetch /api/user/me/ below
      console.log(`Registration finished for user ID: ${userId}`);

      await refreshAuth();  // This sets session/cookies

      // Fetch own pubkey to verify
      const meResp = await fetch('/api/user/me/');
      if (!meResp.ok) throw new Error('Failed to fetch user ID post-reg');
      const meData = await meResp.json();
      const userIdFromMe = meData.id;  // Use this if finish doesn't provide

      const verifyKeys = await fetch(`/api/user/public_key/${userIdFromMe}`);
      if (!verifyKeys.ok || !(await verifyKeys.json()).public_key) {
        // Retry sending keys if not included (e.g., due to PRF failure)
        console.warn("Public key not saved - retrying update");
        const retryResp = await fetch("/api/user/keys/update/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            public_key: bytesToHex(x25519KeyPair.publicKey),
          }),
        });
        if (!retryResp.ok) {
          const retryErr = await retryResp.json();
          console.error(`Retry failed: ${retryErr.error}`);
          setError('Failed to save encryption keys. Please try logging in and updating in settings.');
          return;  // Don't navigate; let user retry
        }
        console.log("Public key retry successful");
      } else {
        console.log("Public key verified as saved");
      }
      navigate({ to: "/" });
    } catch (err) {
      console.error(err);
      console.error("Registration error:", err);
      setError(err instanceof Error ? err.message : "Registration failed");
      setWebauthnStarted(false);
      // Clear privPem on error
      setPrivPem(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 bg-gradient-to-br from-blue-50 to-indigo-50">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 rounded-full bg-blue-100">
            <Shield className="w-6 h-6 text-blue-600" />
          </div>
          <CardTitle className="text-2xl text-center">
            Create HealthSecure Account
          </CardTitle>
          <CardDescription className="text-center">
            Secure medical records access with WebAuthn authentication
          </CardDescription>
        </CardHeader>

        <form ref={formRef} onSubmit={handleSubmit}>
          <CardContent className="space-y-6">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* User Type Selection */}
            <div className="space-y-4">
              <Label>I am registering as a:</Label>
              <RadioGroup
                value={userType}
                onValueChange={(value: "patient" | "doctor") =>
                  setUserType(value)
                }
                className="grid grid-cols-2 gap-4"
              >
                <div>
                  <RadioGroupItem
                    value="patient"
                    id="patient"
                    className="peer sr-only"
                  />
                  <Label
                    htmlFor="patient"
                    className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-transparent p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary"
                  >
                    <User className="mb-3 h-6 w-6" />
                    <span className="text-sm font-medium">Patient</span>
                  </Label>
                </div>
                <div>
                  <RadioGroupItem
                    value="doctor"
                    id="doctor"
                    className="peer sr-only"
                  />
                  <Label
                    htmlFor="doctor"
                    className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-transparent p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary"
                  >
                    <Stethoscope className="mb-3 h-6 w-6" />
                    <span className="text-sm font-medium">Doctor</span>
                  </Label>
                </div>
              </RadioGroup>
            </div>

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="email">Email Address *</Label>
              <Input
                id="email"
                name="email"
                type="email"
                required
                placeholder={
                  userType === "doctor"
                    ? "doctor@hospital.com"
                    : "patient@example.com"
                }
                autoComplete="email"
              />
            </div>

            {/* Common Fields */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="firstName">First Name *</Label>
                <Input
                  id="firstName"
                  name="firstName"
                  required
                  placeholder="John"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="lastName">Last Name *</Label>
                <Input
                  id="lastName"
                  name="lastName"
                  required
                  placeholder="Doe"
                />
              </div>
            </div>

            {/* Patient-specific Fields */}
            {userType === "patient" && (
              <div className="space-y-2">
                <Label htmlFor="dateOfBirth">Date of Birth *</Label>
                <Input
                  id="dateOfBirth"
                  name="dateOfBirth"
                  type="date"
                  required
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Medical records will be created upon registration
                </p>
              </div>
            )}

            {/* Doctor-specific Fields */}
            {userType === "doctor" && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="medicalOrganization">
                    Medical Organization *
                  </Label>
                  <Input
                    id="medicalOrganization"
                    name="medicalOrganization"
                    required
                    placeholder="e.g., City General Hospital"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Doctor Certificate *</Label>
                  <p className="text-sm text-muted-foreground">
                    {certFile ? certFile.name : "No certificate selected"}
                  </p>
                  <Input
                    type="file"
                    accept=".pem,.crt"
                    onChange={(e) => setCertFile(e.target.files ? e.target.files[0] : null)}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleGenerateCertificate}
                    disabled={loading}
                  >
                    <Upload className="mr-2 h-4 w-4" />
                    Generate New Certificate
                  </Button>
                  <div className="p-3 mt-2 text-sm bg-blue-50 rounded-md border border-blue-200">
                    <p className="font-medium text-blue-800">
                      Trusted User Registration
                    </p>
                    <p className="text-blue-600 text-xs mt-1">
                      Doctor accounts require certificate-based authentication
                      (CA-signed certificates required). Private key will be stored securely in your device authenticator if supported, or downloaded for password manager storage.
                    </p>
                  </div>
                </div>
              </>
            )}

            <div className="space-y-2">
              <Label htmlFor="deviceName">Device Name (optional)</Label>
              <Input
                id="deviceName"
                name="deviceName"
                placeholder="e.g., My iPhone"
              />
            </div>

            {/* WebAuthn Status */}
            {webauthnStarted && (
              <Alert className="bg-blue-50 border-blue-200 border animate-pulse">
                <Fingerprint className="h-4 w-4" />
                <AlertDescription>
                  Waiting for your device… Use Face ID, Touch ID, Windows Hello,
                  or security key
                </AlertDescription>
              </Alert>
            )}

            {/* Security Notice */}
            <Alert className="bg-amber-50 border-amber-200">
              <AlertDescription className="text-xs text-amber-800">
                <strong>Security Notice:</strong> All sensitive data is
                encrypted client-side before transmission. The server never
                receives plaintext medical information or authentication
                secrets.
              </AlertDescription>
            </Alert>
          </CardContent>

          <CardFooter className="flex-col space-y-4">
            <Button
              type="submit"
              className="w-full h-12 text-base font-medium"
              disabled={loading || (userType === "doctor" && !certFile)}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-3 h-5 w-5 animate-spin" />
                  {webauthnStarted
                    ? "Waiting for your device…"
                    : "Preparing secure registration..."}
                </>
              ) : (
                "Complete Secure Registration"
              )}
            </Button>

            <div className="text-center text-sm text-muted-foreground">
              Already have an account?{" "}
              <a
                href="/login"
                className="text-blue-600 hover:text-blue-500 font-medium"
              >
                Sign in with WebAuthn
              </a>
            </div>
          </CardFooter>
        </form>
      </Card>
      <Dialog
        open={qrModalOpen}
        onOpenChange={(open) => {
          setQrModalOpen(open);
          if (!open && modalCloseResolve) { modalCloseResolve(); setModalCloseResolve(null); }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Scan Private Key QR Code</DialogTitle>
            <DialogDescription>
              Use your phone's password manager app (e.g., Bitwarden) to scan and store this as a secure note. Do not save locally—delete any traces after.
            </DialogDescription>
          </DialogHeader>
          {qrDataUrl && <img src={qrDataUrl} alt="Private Key QR" className="mx-auto" />}
        </DialogContent>
      </Dialog>
      {/* Separate modal for X25519 QR to avoid conflict */}
      <Dialog
        open={xQrModalOpen}
        onOpenChange={(open) => {
          setXQrModalOpen(open);
          if (!open && modalCloseResolve) { 
            modalCloseResolve(); 
            setModalCloseResolve(null); 
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Scan X25519 Private Key QR Code</DialogTitle>
            <DialogDescription>Use your password manager app (e.g., Bitwarden) to scan and store this as a secure note prefixed 'X25519 PRIV:'. Do not save locally—delete after.</DialogDescription>
          </DialogHeader>
          {qrDataUrl && <img src={qrDataUrl} alt="X25519 Private Key QR" className="mx-auto" />}
        </DialogContent>
      </Dialog>
      {/* Dialog for manual priv key input input */}
      <Dialog
        open={privInputModalOpen}
        onOpenChange={(open) => {
          if (!open && privInputResolve) {
            if (validatePrivInput(privInput)) {
              setPrivInputModalOpen(false);
            } else {
              // Prevent close if invalid
              setPrivInputModalOpen(true);
            }
          }
        }}
      >
        {privInputError && (
          <Alert variant="destructive"><AlertDescription>{privInputError}</AlertDescription></Alert>
        )}
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enter X25519 Private Key</DialogTitle>
            <DialogDescription>
              Paste the base64-encoded X25519 private key from your password manager secure note (after 'X25519 PRIV: '). This is required for E2EE in this session.
            </DialogDescription>
          </DialogHeader>
          <Input type="password" autoComplete="current-password" name="password" id="password" value={privInput} onChange={(e) => setPrivInput(e.target.value)} placeholder="Base64 private key..." />
          <Button onClick={() => {
            if (privInputResolve) privInputResolve(base64ToBytes(privInput.trim()));
            setPrivInputModalOpen(false);
          }}>Submit</Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
