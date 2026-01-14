"use client";
/**
 * Login route (WebAuthn + PRF + E2EE bootstrap).
 *
 * Purpose:
 * - Perform passwordless authentication using WebAuthn discoverable credentials.
 * - If available, use the WebAuthn PRF extension to derive a KEK used to encrypt/decrypt the
 *   user's X25519 private key (client-side E2EE bootstrap).
 * - Fallback path: allow manual import of an X25519 private key from a password manager when
 *   PRF is not available on the current authenticator/device.
 * - Support enrollment of a secondary device via an "add device" code issued by a primary device.
 *
 * Notes:
 * - The PRF evaluation inputs (extensions.prf.eval.{first,second}) must be ArrayBuffer/TypedArray
 *   when passed to navigator.credentials.get(); this file normalizes base64url inputs accordingly.
 * - The derived KEK and decrypted private key are held in memory for the session; the PRF byte array
 *   is explicitly zeroed to reduce data remanence.
 * - After login/bootstrap, the client verifies the private key corresponds to the server-stored public
 *   key to detect mismatches (wrong key import, stale server state, etc.).
 */

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
  hexToBytes,
  getX25519PublicFromPrivate
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


  /**
   * FUNCTION: handleWebAuthnLogin
   * 
   *  PURPOSE:
   *      Authenticates the user using WebAuthn (discoverable credentials).
   *
   * FLOW:
   * 1) Fetch authentication options from the backend.
   * 2) Normalize PRF extension inputs into ArrayBuffer (browser requirement).
   * 3) Trigger the platform authenticator prompt and send assertion to backend.
   * 4) If backend returns PRF output, derive a KEK and decrypt (or generate+encrypt) the user's
   *    X25519 private key used for end-to-end encryption, then derive an Ed25519 signing key.
   * 5) If PRF is unavailable, prompt user to import the X25519 private key manually.
   * 6) Verify private key matches server public key before proceeding.
   *
   * SIDE EFFECTS:
   * - Writes last_login_time in localStorage for settings/anomaly UI.
   * - Stores session keys in window globals (debug/prototype; should be treated as sensitive).
   */

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
        window.__PRF_BYTES__ = prfBytes;
        const kek = await deriveKEK(prfBytes);

        // Zero out PRF bytes (data remanence)
        prfBytes.fill(0);

        // Fetch encrypted priv + pub
        const keysResp = await fetch("/api/user/me/keys/");

        window.__KEK__ = new Uint8Array(await crypto.subtle.exportKey("raw", kek));
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
        const priv = await promptForPrivateKey();
        if (!priv) {
          throw new Error("Private key input cancelled");
        }
        window.__MY_PRIV__ = priv;

        // Derive Ed25519 for signatures
        window.__SIGN_PRIV__ = deriveEd25519FromX25519(
          window.__MY_PRIV__,
        ).privateKey;

        console.log("✅ Manual X25519 private key loaded");
      }

      // Common: Verify loaded private key matches server public key (prevents mismatch issues)
      const meResp = await fetch('/api/user/me/');
      if (!meResp.ok) throw new Error('Failed to fetch user info');
      const me = await meResp.json();
      const userId = me.id;

      const rPub = await fetch(`/api/user/public_key/${userId}`);
      if (!rPub.ok) throw new Error('Failed to fetch public key');
      const { public_key } = await rPub.json();
      if (!public_key) throw new Error('No public key on server');

      const serverPub = hexToBytes(public_key);
      const derivedPub = getX25519PublicFromPrivate(window.__MY_PRIV__);
      const match = derivedPub.every((val, i) => val === serverPub[i]);

      if (!match) {
        window.__MY_PRIV__ = null;
        window.__SIGN_PRIV__ = null;
        if (result.prf_hex) {
          // PRF mismatch rare, fallback to manual
          alert('Decrypted private key does not match server public key. Falling back to manual input.');
          const priv = await promptForPrivateKey();
          if (!priv) throw new Error('Private key input cancelled');
          window.__MY_PRIV__ = priv;
          window.__SIGN_PRIV__ = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
        } else {
          // Fallback case, re-prompt
          throw new Error('Entered private key does not match server public key. Please try again.');
        }
      }
      console.log('Private key verified successfully');

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


  /**
   * FUNCTION: promptForPrivateKey
   *
   * PURPOSE:
   *      Prompts the user to manually provide an X25519 private key when the
   *      PRF extension is unavailable on the current authenticator/device.
   *
   * FLOW:
   *  1) Open a modal dialog requesting a base64-encoded private key.
   *  2) Validate the user input format before resolving.
   *  3) Resolve with the decoded key bytes or null if cancelled.
   *
   * SIDE EFFECTS:
   *  - Temporarily stores user input in component state until resolved.
   */

  const promptForPrivateKey = async (): Promise<Uint8Array | null> => {
    return new Promise((resolve) => {
      setPrivInputResolve(() => resolve);
      setPrivInput('');
      setPrivInputModalOpen(true);
    });
  };





  /**
   * FUNCTION: handleAddDevice
   *
   * PURPOSE:
   *      Registers the current device as a secondary WebAuthn authenticator
   *      for an existing user account.
   *
   * FLOW:
   *  1) Send the user's email, add-code, and device name to the backend.
   *  2) Receive WebAuthn registration options bound to the add-code.
   *  3) Trigger credential creation on the current device.
   *  4) Submit the attestation response to the backend to persist the credential.
   *
   * SIDE EFFECTS:
   *  - Creates a new WebAuthn credential associated with the user account.
   */

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

    /**
   * FUNCTION: validatePrivInput
   *
   * PURPOSE:
   *      Validates the format of a base64-encoded X25519 private key provided
   *      manually by the user.
   *
   * FLOW:
   *  1) Trim user input and check expected length.
   *  2) Validate base64 character set.
   *  3) Set validation error state on failure.
   *
   * RETURNS:
   *  - true if the input is valid.
   *  - false otherwise.
   */


  const validatePrivInput = (input: string): boolean => {
    const trimmed = input.trim();
    if (trimmed.length !== 44 || !/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
      setPrivInputError('Invalid base64 key. Must be exactly 44 characters.');
      return false;
    }
    setPrivInputError(null);
    return true;
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
              privInputResolve(base64ToBytes(privInput.trim()));
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
            if (validatePrivInput(privInput) && privInputResolve) {
              privInputResolve(base64ToBytes(privInput.trim()));
              setPrivInputModalOpen(false);
            }
          }}>Submit</Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
