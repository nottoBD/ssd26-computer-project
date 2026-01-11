"use client";

import { useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Shield, Fingerprint, Loader2, AlertTriangle } from "lucide-react";
import { startAuthentication, startRegistration, base64URLStringToBuffer } from "@simplewebauthn/browser";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import {
  deriveKEK,
  generateX25519Keypair,
  encryptAES,
  decryptAES,
  deriveEd25519FromX25519,
  base64ToBytes,
} from "../components/CryptoUtils";
import { useAuth } from './__root'

export const Route = createFileRoute("/login")({
  component: LoginPage,
});

function LoginPage() {
  const navigate = useNavigate();
  const { refreshAuth } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState<"regular" | "authenticating" | "add" | "adding">("regular");
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [deviceName, setDeviceName] = useState('New Device');
  const [privInputModalOpen, setPrivInputModalOpen] = useState(false);
  const [privInput, setPrivInput] = useState('');
  const [privInputResolve, setPrivInputResolve] = useState<((value: Uint8Array | null) => void) | null>(null);
  const [privInputError, setPrivInputError] = useState<string | null>(null);

  const handleWebAuthnLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      // Step 1: Ask server for authentication options (discoverable credentials = no email needed)
      const resp = await fetch("/api/webauthn/login/start/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}), // empty → allow any registered device
      });

      if (!resp.ok)
        throw new Error("No registered device found for this browser");

      const options = await resp.json();

      // PRF salts from base64url to ArrayBuffer (necessary for Android Bitwaden)
      const prfEval = options.extensions?.prf?.eval;
      if (prfEval) {
        prfEval.first = base64URLStringToBuffer(prfEval.first);
        if (prfEval.second) {
          prfEval.second = base64URLStringToBuffer(prfEval.second);
        }
      }

      // Step 2: Trigger browser native prompt
      const credential = await startAuthentication({ optionsJSON: options })

      // Step 3: Send back to server
      const finishResp = await fetch("/api/webauthn/login/finish/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
      });

      const result = await finishResp.json();

      if (!finishResp.ok)
        throw new Error(result.error || "Authentication failed");
      
      //INFO: Update local last login time for anomaly detection in settings
      localStorage.setItem('last_login_time', new Date().toISOString());

      // // PRF SUCCESS KEK AVAILABLE IN MEMORY
      if (result.prf_hex) {
        const prfBytes = Uint8Array.from(
          result.prf_hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
        );
        const kek = await deriveKEK(prfBytes);

        // Zero out PRF bytes (data remanence)
        prfBytes.fill(0);

        // Fetch encrypted priv + pub
        const keysResp = await fetch("/api/user/me/keys/");
        const { encrypted_priv, pub_key } = await keysResp.json();

        if (!pub_key) {
          // First login ever – generate + encrypt + store
          const { publicKey, privateKey } = generateX25519Keypair();
          const encryptedPriv = encryptAES(
            privateKey,
            new Uint8Array(await crypto.subtle.exportKey("raw", kek)),
          );

          await fetch("/api/user/keys/update/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              public_key: Array.from(publicKey),
              encrypted_priv: {
                ciphertext: Array.from(encryptedPriv.ciphertext),
                iv: Array.from(encryptedPriv.iv),
                tag: Array.from(encryptedPriv.tag),
              },
            }),
          });

          window.__MY_PRIV__ = privateKey;
        } else {
          // Decrypt priv
          const priv = decryptAES(
            new Uint8Array(encrypted_priv.ciphertext),
            new Uint8Array(await crypto.subtle.exportKey("raw", kek)),
            new Uint8Array(encrypted_priv.iv),
            new Uint8Array(encrypted_priv.tag),
          );
          window.__MY_PRIV__ = priv;
        }

        // Derive Ed25519 for signatures
        window.__SIGN_PRIV__ = deriveEd25519FromX25519(
          window.__MY_PRIV__,
        ).privateKey;

        console.log("✅ PRF KEK derived and ready for encryption");
      } else {
        // Fallback: Prompt for manual private key input from Bitwarden
        alert("PRF not available on this device. Please paste your X25519 private key base64 from Bitwarden secure note.");
        const privPromise = new Promise<Uint8Array | null>(resolve => {
          setPrivInputResolve(() => resolve);
          setPrivInput('');
        });
        setPrivInputModalOpen(true);
        const privBytes = await privPromise;
        setPrivInputModalOpen(false);
        if (!privBytes) {
          throw new Error("Private key input cancelled or invalid");
        }
        window.__MY_PRIV__ = privBytes;

        // Derive Ed25519 for signatures
        window.__SIGN_PRIV__ = deriveEd25519FromX25519(
          window.__MY_PRIV__,
        ).privateKey;

        console.log("✅ Manual X25519 private key loaded");
      }

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

      await refreshAuth();
      navigate({ to: "/" });
    } catch (err: any) {
      console.error(err);
      let errorMsg = err.message || "Authentication failed - try another device or register first";
      
      //INFO: Handling for clone/anomaly errors
      if (errorMsg.includes("cloned authenticator")) {
        errorMsg = "Possible cloned device detected! Check your activity in settings and contact support if suspicious.";
      }
      setError(errorMsg);
      setStage("regular");
    } finally {
      setLoading(false);
    }
  };


  const handleAddDevice = async () => {
    setLoading(true);
    setError(null);
    try {
      const addStart = await fetch("/api/webauthn/add/start/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code, device_name: deviceName }),
      });
      if (!addStart.ok) {
        const err = await addStart.json();
        throw new Error(err.error || "Add start failed");
      }
      const addOptions = await addStart.json();
      const addCred = await startRegistration(addOptions);
      const addFinish = await fetch("/api/webauthn/credential/add/finish/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addCred),
      });
      if (!addFinish.ok) throw new Error("Add failed");

      await refreshAuth();
      navigate({ to: "/" });
    } catch (err: any) {
      setError(err.message || "Device add failed - check code and try again");
      setStage("add");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 bg-gradient-to-br from-gray-50 to-slate-100">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 rounded-full bg-gradient-to-r from-blue-500 to-indigo-600">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl text-center">
            HealthSecure Login
          </CardTitle>
          <CardDescription className="text-center">
            Secure authentication using WebAuthn with PRF extension
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" /> {/* Primary/Secondary Alerts */}
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-4">
            {stage === "regular" ? (
              <>
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 mb-4">
                    <Fingerprint className="w-8 h-8 text-blue-600" />
                  </div>
                  <h3 className="text-lg font-semibold">
                    Biometric / Security Key Login
                  </h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Use your registered security key, fingerprint, or face
                    recognition
                  </p>
                </div>

                <Button
                  onClick={() => {
                    setStage("authenticating");
                    handleWebAuthnLogin();
                  }}
                  className="w-full h-12 text-base bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                >
                  <Fingerprint className="mr-2 h-5 w-5" />
                  Login with WebAuthn
                </Button>
                <Button variant="link" onClick={() => setStage("add")}>
                  Add this device to an existing account
                </Button>
              </>
            ) : stage === "authenticating" ? (
              <div className="py-12 text-center space-y-6">
                <div className="mx-auto w-20 h-20 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 flex items-center justify-center animate-pulse">
                  <Fingerprint className="h-10 w-10 text-white" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold">
                    Confirm your identity
                  </h3>
                  <p className="text-muted-foreground mt-2">
                    Use Face ID, Touch ID, Windows Hello, or security key
                  </p>
                </div>
              </div>
            ) : stage === "add" ? (
              <div className="space-y-4">
                <Input
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
                <Input
                  placeholder="Add Code from primary device"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <Input
                  placeholder="Device Name"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                />
                <Button 
                  onClick={() => {
                    setStage("adding");
                    handleAddDevice();
                  }} 
                  disabled={loading} 
                  className="w-full"
                >
                  {loading ? <Loader2 className="animate-spin" /> : 'Add Device'}
                </Button>
                <Button variant="link" onClick={() => setStage("regular")}>
                  Back to regular login
                </Button>
              </div>
            ) : (
              <div className="py-12 text-center space-y-6">
                <div className="mx-auto w-20 h-20 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 flex items-center justify-center animate-pulse">
                  <Fingerprint className="h-10 w-10 text-white" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold">
                    Add this device
                  </h3>
                  <p className="text-muted-foreground mt-2">
                    Use Face ID, Touch ID, Windows Hello, or security key to create a new passkey
                  </p>
                </div>
              </div>
            )}
          </div>

          <Alert className="bg-blue-50 border-blue-200">
            <AlertDescription className="text-sm text-blue-800">
              <strong>How it works:</strong> WebAuthn uses public key
              cryptography. Your private key never leaves your device. Server
              authentication is verified before login.
            </AlertDescription>
          </Alert>
        </CardContent>

        <CardFooter className="flex-col space-y-4 border-t pt-6">
          <div className="text-center text-sm">
            <p className="text-muted-foreground">
              Don't have an account?{" "}
              <a
                href="/register"
                className="font-medium text-blue-600 hover:text-blue-500"
              >
                Register with WebAuthn
              </a>
            </p>
          </div>

          <div className="w-full text-xs text-center text-muted-foreground space-y-1">
            <p>Medical records are encrypted end-to-end</p>
            <p>Server cannot access plaintext data</p>
            <p className="font-medium">No passwords stored on server</p>
          </div>
        </CardFooter>
      </Card>
            {/* Dialog for manual priv key input */}
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
              Paste the base64-encoded X25519 private key from your password manager. This is required for E2EE on this device.
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
