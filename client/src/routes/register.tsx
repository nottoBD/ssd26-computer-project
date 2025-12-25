"use client";

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
  const formRef = useRef<HTMLFormElement>(null);

    const handleGenerateCertificate = async () => {
      try {
        if (!formRef.current) {
          throw new Error("Form not available");
        }
        const formData = new FormData(formRef.current);
        const firstName = formData.get("firstName") as string;
        const lastName = formData.get("lastName") as string;
        const email = formData.get("email") as string;
        const medicalOrganization = formData.get("medicalOrganization") as string;

        if (!firstName.trim() || !lastName.trim() || !email.trim() || !medicalOrganization.trim()) {
          throw new Error("Please fill in first name, last name, email, and medical organization before generating certificate");
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
          true,
          ["sign", "verify"]
        );

        const csr = new pkijs.CertificationRequest();

        const cnAttr = new pkijs.AttributeTypeAndValue({
          type: "2.5.4.3", // CN
          value: new asn1js.Utf8String({ value: `${firstName} ${lastName}` })
        });


        if (medicalOrganization.trim()) {
          const oAttr = new pkijs.AttributeTypeAndValue({
            type: "2.5.4.10", // O
            value: new asn1js.Utf8String({ value: medicalOrganization })
          });
          csr.subject.typesAndValues.push(oAttr);
        }
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

        // Export PrivKey
        const privRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privPem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(privRaw))).match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`;

        // Download PrivKey
        const privBlob = new Blob([privPem], { type: "text/plain" });
        const privUrl = URL.createObjectURL(privBlob);
        const a = document.createElement("a");
        a.href = privUrl;
        a.download = "doctor_private_key.pem";
        a.click();
        URL.revokeObjectURL(privUrl);

        // certificate as file
        const certBlob = new Blob([certificate], { type: "text/plain" });
        setCertFile(new File([certBlob], "doctor_cert.pem"));

        alert("Certificate generated! Private key downloaded - store it securely.");

      } catch (err) {
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

      const options = await startResp.json();

      // 2. Show WebAuthn prompt
      setWebauthnStarted(true);

      // 2. Trigger device prompt
      const credential = await startRegistration(options);

      // 3. Finish registration
      const finishResp = await fetch("/api/webauthn/register/finish/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
      });

      if (!finishResp.ok) {
       const err = await finishResp.json();
       throw new Error(err.error || "Registration failed on server");
      }

      // Success!
      alert("🎉 Successfully registered and logged in with passkey!");
      await refreshAuth();
      navigate({ to: "/" });
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : "Registration failed");
      setWebauthnStarted(false);
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
                      (CA-signed certificates required). If generating, save the private key securely.
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
              <Alert className="bg-blue-50 border-blue-200 animate-pulse">
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
    </div>
  );
}
