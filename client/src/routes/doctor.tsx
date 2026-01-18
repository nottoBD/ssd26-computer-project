/**
 * FILE: doctor.tsx
 *
 * ROLE:
 *      Unified portal for doctor-side workflows and patient-side approval
 *      of appointment requests.
 *
 * MAIN FEATURES:
 *  - Doctor:
 *      • View appointed patients and navigate to /record?patient=...
 *      • Search patients and submit signed appointment requests (PKI-backed)
 *  - Patient (when routed here):
 *      • Review and approve/deny incoming appointment requests from doctors
 *      • Review and approve/deny incoming file change requests from doctors
 *
 * SECURITY:
 *  - Authentication: enforced via beforeLoad() calling /api/webauthn/auth/status/.
 *  - Authorization: backend must enforce that doctors can only act on patients they are allowed to access.
 *  - E2EE: doctor/patient record access relies on X25519 private key presence in-memory (window.__MY_PRIV__),
 *          and key wrapping via ECDH (X25519) + AES-GCM for DEKs.
 *  - Signed actions: doctor requests are signed with their PKI-signed X509 private key.
 *  - PKI: doctor actions attach a CA chain (root/intermediate/doctor) fetched from /api/ca/my_chain/.
 *
 * SENSITIVE STATE:
 *  - Uses IndexedDB and window.__MY_PRIV__ for E2EE functionality.
 */
import { useState, useEffect } from "react";
import {
  createFileRoute,
  Link,
  useNavigate,
  redirect,
} from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import {
  Plus,
  User,
  Calendar,
  Stethoscope,
  Search,
  Key,
  ShieldCheck,
  Edit,
  Trash,
  Upload,
  Folder,
  Check,
  X,
} from "lucide-react";
import { useAuth } from "./__root";
import {
  bytesToBase64,
  signEd25519,
  deriveEd25519FromX25519,
  encryptAES,
  randomBytes,
  base64ToBytes,
  hexToBytes,
  ecdhSharedSecret,
  decryptAES,
} from "../components/CryptoUtils";
import { saveKey, getKey } from "../lib/key-store";
import { generateMetadata, prepareMetadata } from '../lib/metadata'; // New import for metadata

/**
 * FUNCTION: getCookie
 *
 * PURPOSE:
 *      Reads a cookie value (e.g., csrftoken) required for CSRF-protected POST requests.
 *
 * RETURNS:
 *      Cookie value (decoded) or undefined if not present.
 */

function getCookie(name: string): string | undefined {
  const matches = document.cookie.match(
    new RegExp(
      "(?:^|; )" +
        name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, "\\$1") +
        "=([^;]*)",
    ),
  );
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

interface Patient {
  id: string;
  name: string;
  dob: string;
  appointedDate: string;
}

interface SearchedPatient {
  id: string;
  name: string;
  dob: string;
}

interface PendingRequest {
  id: string;
  type: string;
  status: string;
  patient_id: string;
  patient_name: string;
  timestamp: string;
  details: any;
}

interface PendingFileRequest {
  id: string;
  type: string;
  requester: { id: string; name: string };
  details: any;
  timestamp: string;
}

interface PendingAppointment {
  id: string;
  requester: { id: string; name: string };
  timestamp: string;
}

interface CertChain {
  root: string;
  intermediate: string;
  doctor: string;
}

interface User {
  id: string;
  type: "patient" | "doctor";
  name: string;
}

/**
 * FUNCTION: deriveMasterKEK
 *
 * PURPOSE:
 *      Derives a local “master key” from the user’s X25519 private key.
 *      Used to decrypt the patient’s self-wrapped DEK when approving appointment requests.
 *
 * METHOD:
 *      SHA-256(priv) → 32-byte key.
 *
 * SECURITY NOTES:
 *  - This is a deterministic derivation; compromise of priv implies compromise of this KEK.
 *  - Works only if the patient’s record is self-wrapped under this same derivation.
 */

const deriveMasterKEK = async (priv: Uint8Array): Promise<Uint8Array> => {
  const digest = await crypto.subtle.digest("SHA-256", priv);
  return new Uint8Array(digest);
};

/**
 * FUNCTION: decryptDEK
 *
 * PURPOSE:
 *      Decrypts an encrypted DEK blob using AES-GCM.
 *
 * INPUT FORMAT:
 *  - encDekStr is base64 of: [12-byte IV | 32-byte ciphertext | 16-byte tag] = 60 bytes total.
 *
 * RETURNS:
 *      32-byte DEK (raw).
 *
 * SECURITY NOTES:
 *  - Throws on format mismatch or invalid authentication tag.
 */

const decryptDEK = async (
  encDekStr: string,
  key: Uint8Array,
): Promise<Uint8Array> => {
  const dekBytes = base64ToBytes(encDekStr);
  if (dekBytes.length !== 60) {
    throw new Error(`Invalid encrypted DEK length: ${dekBytes.length}`);
  }
  const iv = dekBytes.slice(0, 12);
  const tag = dekBytes.slice(-16);
  const ciphertext = dekBytes.slice(12, -16);
  return await decryptAES(ciphertext, key, iv, tag);
};

export const Route = createFileRoute("/doctor")({
  beforeLoad: async () => {
    try {
      // Generate metadata for auth status check (auth-specific, no tree depth)
      const authPayload = {}; // Empty body
      const authMetadata = generateMetadata(authPayload, ['user', 'auth_status'], 'GET');
      const authMetadataHeader = await prepareMetadata(authMetadata, window.__SIGN_PRIV__); // Sign if available

      const response = await fetch("/api/webauthn/auth/status/", {
        method: "GET",
        credentials: "include",
        headers: { "X-Metadata": authMetadataHeader } // Attach as header
      });
      if (!response.ok) {
        throw new Error("Not authenticated");
      }
      const data = await response.json();
      if (!data.authenticated) {
        throw new Error("Not authenticated");
      }
    } catch (err) {
      throw redirect({ to: "/login" });
    }
  },
  component: UserPortal,
});

function UserPortal() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [user, setUser] = useState<User | null>(null);
  const [appointedPatients, setAppointedPatients] = useState<Patient[]>([]);
  const [searchedPatients, setSearchedPatients] = useState<SearchedPatient[]>(
    [],
  );
  const [pendingRequests, setPendingRequests] = useState<PendingRequest[]>([]);
  const [pendingAppointments, setPendingAppointments] = useState<
    PendingAppointment[]
  >([]);
  const [pendingFileRequests, setPendingFileRequests] = useState<
    PendingFileRequest[]
  >([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [addPatientDialogOpen, setAddPatientDialogOpen] = useState(false);
  const [certChain, setCertChain] = useState<CertChain | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [inputPrivOpen, setInputPrivOpen] = useState(false);
  const [inputPriv, setInputPriv] = useState("");
  const [inputCertPrivOpen, setInputCertPrivOpen] = useState(false);
  const [inputCertPriv, setInputCertPriv] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    async function loadKeys() {
      const storedX = sessionStorage.getItem("x25519_priv_b64");
      if (storedX) {
        window.__MY_PRIV__ = base64ToBytes(storedX);
      }
      const storedCert = await getKey('cert_priv');
      if (storedCert) {
        window.__MY_CERT_PRIV__ = storedCert as Uint8Array;
      }
      fetchUser();
    }
    loadKeys();
  }, []);

  useEffect(() => {
    if (!user) return;
    if (user.type === "doctor") {
      fetchAppointedPatients();
      fetchPendingRequests();
      fetchCertChain();
    } else if (user.type === "patient") {
      fetchPendingAppointments();
      fetchPendingFileRequests();
    }
    setLoading(false);
  }, [user, refreshKey]);

  const fetchUser = async () => {
    try {
      // Generate metadata for user me fetch (user-specific, no tree depth)
      const meMetadata = generateMetadata({}, ['user', 'get_me'], 'GET');
      const meMetadataHeader = await prepareMetadata(meMetadata, window.__SIGN_PRIV__); // Sign if available

      const r = await fetch("/api/user/me/", {
        headers: { "X-Metadata": meMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      setUser(data);
    } catch (err) {
      console.error("User fetch failed:", err);
      setError("Failed to load user info");
    }
  };

  const handlePrivInput = async () => {
    try {
      const newPriv = base64ToBytes(inputPriv);
      window.__MY_PRIV__ = newPriv;
      sessionStorage.setItem("x25519_priv_b64", inputPriv);

      // Generate metadata for own public key fetch (user-specific, no tree depth)
      const ownPubMetadata = generateMetadata({}, ['user', 'get_public_key'], 'GET');
      const ownPubMetadataHeader = await prepareMetadata(ownPubMetadata); // No signing yet

      // Verify private key matches server public key
      const rPub = await fetch(`/api/user/public_key/${user!.id}`, {
        headers: { "X-Metadata": ownPubMetadataHeader } // Attach as header
      });
      if (!rPub.ok) throw new Error('Failed to fetch own public key');
      const { public_key } = await rPub.json();
      if (!public_key) throw new Error('No public key on server');
      const serverPub = hexToBytes(public_key);
      const derivedPub = getX25519PublicFromPrivate(newPriv);  // Derive pub from entered priv
      const match = derivedPub.every((val, i) => val === serverPub[i]);
      if (!match) {
        throw new Error('Private key does not match the public key on the server. Please enter the correct key or rotate if needed.');
      }
      console.log('Private key verified successfully');

      if (window.__KEK__) {
        const encryptedPriv = await encryptAES(newPriv, window.__KEK__);
        const encryptedPrivStr = bytesToBase64(
          new Uint8Array([
            ...encryptedPriv.iv,
            ...encryptedPriv.ciphertext,
            ...encryptedPriv.tag,
          ]),
        );

        // Generate metadata for keys update (user-specific, tree depth 0)
        const updatePayload = { encrypted_priv: encryptedPrivStr };
        const updateMetadata = generateMetadata(updatePayload, ['user', 'update_keys'], 'POST', 0);
        const updateMetadataHeader = await prepareMetadata(updateMetadata, window.__SIGN_PRIV__); // Sign available

        const r = await fetch("/api/user/keys/update/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken") || "",
            "X-Metadata": updateMetadataHeader // Attach as header
          },
          credentials: "include",
          body: JSON.stringify(updatePayload),
        });
        if (!r.ok) console.error("Failed to update encrypted priv");
      }

      setInputPrivOpen(false);
      setInputPriv("");
    } catch (err) {
      setError("Invalid private key");
    }
  };

  const handleCertPrivInput = async () => {
    try {
      const newCertPriv = base64ToBytes(inputCertPriv);
      window.__MY_CERT_PRIV__ = newCertPriv;
      await saveKey('cert_priv', newCertPriv);
      setInputCertPrivOpen(false);
      setInputCertPriv("");
    } catch (err) {
      setError("Invalid certificate private key");
    }
  };

  const fetchAppointedPatients = async () => {
    try {
      // Generate metadata for appointed patients fetch (doctor-specific, no tree depth)
      const patientsMetadata = generateMetadata({}, ['doctor', 'get_appointed_patients'], 'GET');
      const patientsMetadataHeader = await prepareMetadata(patientsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch("/api/appoint/patients/", {
        headers: { "X-Metadata": patientsMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const { patients } = await r.json();
      setAppointedPatients(patients);
    } catch (err) {
      console.error("Patients fetch failed:", err);
      setError(err.message);
    }
  };

  const fetchPendingRequests = async () => {
    try {
      // Generate metadata for pending requests fetch (doctor-specific, no tree depth)
      const requestsMetadata = generateMetadata({}, ['doctor', 'get_pending_requests'], 'GET');
      const requestsMetadataHeader = await prepareMetadata(requestsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch("/api/pending/my_requests/", {
        headers: { "X-Metadata": requestsMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const { requests } = await r.json();
      setPendingRequests(requests);
    } catch (err) {
      console.error("Pending requests fetch failed:", err);
      setError(err.message);
    }
  };

  const fetchCertChain = async () => {
    try {
      // Generate metadata for cert chain fetch (doctor-specific, no tree depth)
      const certMetadata = generateMetadata({}, ['doctor', 'get_cert_chain'], 'GET');
      const certMetadataHeader = await prepareMetadata(certMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch("/api/ca/my_chain/", {
        headers: { "X-Metadata": certMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      setCertChain({
        root: data.root_pem,
        intermediate: data.intermediate_pem,
        doctor: data.doctor_pem,
      });
    } catch (err) {
      console.error("Cert chain fetch failed:", err);
      setError("Failed to load PKI chain. Signing disabled.");
    }
  };

  const searchPatients = async (q: string) => {
    if (!q) {
      setSearchedPatients([]);
      return;
    }
    try {
      // Generate metadata for patients search (doctor-specific, no tree depth)
      const searchMetadata = generateMetadata({}, ['doctor', 'search_patients'], 'GET');
      const searchMetadataHeader = await prepareMetadata(searchMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch(`/api/patients/search/?q=${encodeURIComponent(q)}`, {
        headers: { "X-Metadata": searchMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const { patients } = await r.json();
      setSearchedPatients(patients);
    } catch (err) {
      console.error("Search patients failed:", err);
      setError(err.message);
    }
  };

  const requestAppointment = async (patientId: string) => {
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true);
      return;
    }
    if (!window.__MY_CERT_PRIV__) {
      setInputCertPrivOpen(true);
      return;
    }
    if (!certChain) {
      setError("PKI chain missing");
      return;
    }

    const existing = pendingRequests.find(
      r => r.patient_id === patientId && r.status === "pending" && r.type === "appointment"
    );
    if (existing) {
      alert("You already have a pending appointment request for this patient.");
      return;
    }

    try {
      const timestamp = new Date().toISOString();
      const requestMsg = new TextEncoder().encode(
        JSON.stringify({
          type: "appointment_request",
          patient_id: patientId,
          timestamp: timestamp,
        }),
      );

      // Import RSA private key (matches generation in register.tsx)
      const certPrivKey = await crypto.subtle.importKey(
        "pkcs8",
        window.__MY_CERT_PRIV__,
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        false,
        ["sign"],
      );

      // Sign using RSASSA-PKCS1-v1_5 (standard for your key)
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",  // No extra params needed for PKCS#1 v1.5
        certPrivKey,
        requestMsg,
      );
      const signatureB64 = bytesToBase64(new Uint8Array(signature));

      const body = {
        signature: signatureB64,
        cert: certChain.doctor,  // Leaf cert PEM (backend can trust via its CA config)
        patient_id: patientId,
        timestamp: timestamp,
      };

      // Generate metadata for appointment request (doctor-specific, no tree depth)
      const appointPayload = body;
      const appointMetadata = generateMetadata(appointPayload, ['doctor', 'request_appointment'], 'POST');
      const appointMetadataHeader = await prepareMetadata(appointMetadata, window.__SIGN_PRIV__); // Sign available

      const res = await fetch("/api/appoint/request/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken") || "",
          "X-Metadata": appointMetadataHeader // Attach as header
        },
        credentials: "include",
        body: JSON.stringify(appointPayload),
      });
      if (!res.ok) throw new Error(await res.text());
      alert("Appointment request sent. Awaiting patient approval.");
      fetchPendingRequests();
      setAddPatientDialogOpen(false);
    } catch (err) {
      console.error("Appointment request failed:", err);
      setError((err as Error).message || "Failed to send appointment request");
    }
  };

  const viewPatientRecord = (patientId: string) => {
    navigate({ to: "/record", search: { patient: patientId } });
  };

  const fetchPendingAppointments = async () => {
    try {
      // Generate metadata for pending appointments fetch (patient-specific, no tree depth)
      const appointmentsMetadata = generateMetadata({}, ['patient', 'get_pending_appointments'], 'GET');
      const appointmentsMetadataHeader = await prepareMetadata(appointmentsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch("/api/pending/appointments/", {
        headers: { "X-Metadata": appointmentsMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const { requests } = await r.json();
      setPendingAppointments(requests);
    } catch (err) {
      console.error("Pending appointments fetch failed:", err);
      setError(err.message);
    }
  };

  const fetchPendingFileRequests = async () => {
    try {
      // Generate metadata for pending file requests fetch (patient-specific, no tree depth)
      const fileRequestsMetadata = generateMetadata({}, ['patient', 'get_pending_file_requests'], 'GET');
      const fileRequestsMetadataHeader = await prepareMetadata(fileRequestsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch("/api/pending/file_requests/", {
        headers: { "X-Metadata": fileRequestsMetadataHeader } // Attach as header
      });
      if (!r.ok) throw new Error(await r.text());
      const { requests } = await r.json();
      setPendingFileRequests(requests);
    } catch (err) {
      console.error("Pending file requests fetch failed:", err);
      setError(err.message);
    }
  };

  const approveAppointment = async (req: PendingAppointment) => {
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true);
      return;
    }
    try {
      // Generate metadata for record fetch (patient-specific, tree depth 0 for root)
      const recordMetadata = generateMetadata({}, ['patient', 'get_record'], 'GET', 0);
      const recordMetadataHeader = await prepareMetadata(recordMetadata, window.__SIGN_PRIV__); // Sign available

      // Load current DEK from patient's record
      const recordRes = await fetch("/api/record/my/", {
        headers: { "X-Metadata": recordMetadataHeader } // Attach as header
      });
      if (!recordRes.ok) throw new Error("Failed to fetch record");
      const recordData = await recordRes.json();
      const encDekSelf = recordData.encrypted_deks["self"];
      if (!encDekSelf) throw new Error("No self DEK found");
      const masterKEK = await deriveMasterKEK(window.__MY_PRIV__);
      const dek = await decryptDEK(encDekSelf, masterKEK);

      // Generate metadata for doctor public key fetch (patient-specific, no tree depth)
      const docPubMetadata = generateMetadata({}, ['patient', 'get_doctor_public_key'], 'GET');
      const docPubMetadataHeader = await prepareMetadata(docPubMetadata, window.__SIGN_PRIV__); // Sign available

      // Fetch doctor's public key
      const pubRes = await fetch(`/api/user/public_key/${req.requester.id}`, {
        headers: { "X-Metadata": docPubMetadataHeader } // Attach as header
      });
      if (!pubRes.ok) throw new Error("Failed to fetch doctor public key");
      const { public_key } = await pubRes.json();
      const docPub = hexToBytes(public_key);
      const shared = await ecdhSharedSecret(window.__MY_PRIV__, docPub);

      // Encrypt DEK for doctor
      const encryptedDek = await encryptAES(dek, shared);
      const encDekStr = bytesToBase64(
        new Uint8Array([
          ...encryptedDek.iv,
          ...encryptedDek.ciphertext,
          ...encryptedDek.tag,
        ]),
      );

      // Generate metadata for approve (patient-specific, no tree depth)
      const approvePayload = { encrypted_dek: encDekStr };
      const approveMetadata = generateMetadata(approvePayload, ['patient', 'approve_appointment'], 'POST');
      const approveMetadataHeader = await prepareMetadata(approveMetadata, window.__SIGN_PRIV__); // Sign available

      // Send to backend for approval
      const approveRes = await fetch(`/api/pending/${req.id}/approve/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken") || "",
          "X-Metadata": approveMetadataHeader // Attach as header
        },
        credentials: "include",
        body: JSON.stringify(approvePayload),
      });
      if (!approveRes.ok) throw new Error(await approveRes.text());
      alert("Appointment approved successfully!");
      fetchPendingAppointments();
    } catch (err) {
      console.error("Approval failed:", err);
      setError((err as Error).message);
    }
  };

  const denyAppointment = async (reqId: string) => {
    if (!confirm("Deny this appointment request?")) return;
    try {
      // Generate metadata for deny (patient-specific, no tree depth)
      const denyMetadata = generateMetadata({}, ['patient', 'deny_appointment'], 'POST');
      const denyMetadataHeader = await prepareMetadata(denyMetadata, window.__SIGN_PRIV__); // Sign available

      const res = await fetch(`/api/pending/${reqId}/deny/`, {
        method: "POST",
        headers: { 
          "X-CSRFToken": getCookie("csrftoken") || "",
          "X-Metadata": denyMetadataHeader // Attach as header
        },
        credentials: "include",
      });
      if (!res.ok) throw new Error(await res.text());
      alert("Request denied.");
      fetchPendingAppointments();
    } catch (err) {
      setError((err as Error).message);
    }
  };


const approveFileRequest = async (req: PendingFileRequest) => {
  if (!window.__MY_PRIV__) {
    setInputPrivOpen(true);
    return;
  }
  try {
    // Generate metadata for record fetch (patient-specific, tree depth 0 for root)
    const recordMetadata = generateMetadata({}, ['patient', 'get_record'], 'GET', 0);
    const recordMetadataHeader = await prepareMetadata(recordMetadata, window.__SIGN_PRIV__); // Sign available

    // Fetch current record
    const recordRes = await fetch("/api/record/my/", {
      headers: { "X-Metadata": recordMetadataHeader } // Attach as header
    });
    if (!recordRes.ok) throw new Error("Failed to fetch record");
    const recordData = await recordRes.json();
    const encDekSelf = recordData.encrypted_deks["self"];
    if (!encDekSelf) throw new Error("No self DEK found");
    const masterKEK = await deriveMasterKEK(window.__MY_PRIV__);
    let recordDek = await decryptDEK(encDekSelf, masterKEK);
    let encryptedData = base64ToBytes(recordData.encrypted_data || "");
    const iv = encryptedData.slice(0, 12);
    const tag = encryptedData.slice(-16);
    const ciphertext = encryptedData.slice(12, -16);
    let dirJson = await decryptAES(ciphertext, recordDek, iv, tag);
    let dir = JSON.parse(new TextDecoder().decode(dirJson)) || { name: "Root", type: "folder", children: [], metadata: { created: new Date().toISOString(), size: 0 } };
    // Normalize path
    let pathStr = (req.details.path || '').trim();
    if (pathStr.startsWith('/')) pathStr = pathStr.slice(1);
    if (pathStr.startsWith('Root/')) pathStr = pathStr.slice(5);
    else if (pathStr.startsWith('Root')) pathStr = pathStr.slice(4);
    let pathParts = pathStr.split('/').filter(part => part.length > 0);
    // For add_folder without name, assume last part is name
    if (req.type === "add_folder" && !req.details.name && pathParts.length > 0) {
      req.details.name = pathParts.pop();
    }
    let current = dir;
    for (let i = 0; i < pathParts.length; i++) {
      const part = pathParts[i];
      if (!current.children) throw new Error(`Path not found: no children for '${part}'`);
      const child = current.children.find((c: RecordNode) => c.name.toLowerCase() === part.toLowerCase());
      if (!child) throw new Error(`Path not found: '${part}' missing`);
      current = child;
    }
    if (req.type === "add_folder") {
      if (req.details.name) {
        if (!current.children) current.children = [];
        current.children.push({
          name: req.details.name,
          type: "folder",
          children: [],
          metadata: { created: new Date().toISOString(), size: 0 },
          addedBy: req.requester.id
        });
      } else {
        throw new Error("Name required for folder");
      }
    } else if (req.type === "delete") {
      if (req.details.name) {
        if (!current.children) throw new Error("No children to delete from");
        const index = current.children.findIndex((c: RecordNode) => c.name.toLowerCase() === req.details.name.toLowerCase());
        if (index === -1) throw new Error("Item not found for delete");
        current.children.splice(index, 1);
      } else if (pathParts.length > 0) {
        const parentPath = pathParts.slice(0, -1);
        const parent = getParent(dir, parentPath);
        if (!parent || !parent.children) throw new Error("Parent not found");
        const lastName = pathParts[pathParts.length - 1];
        const index = parent.children.findIndex((c: RecordNode) => c.name === lastName);
        if (index === -1) throw new Error("Item not found for delete");
        parent.children.splice(index, 1);
      } else {
        throw new Error("Cannot delete root");
      }
    } else {
      // File types: add_text, add_binary, edit_text, edit_binary
      // Generate metadata for doctor public key fetch (patient-specific, no tree depth)
      const docPubMetadata = generateMetadata({}, ['patient', 'get_doctor_public_key'], 'GET');
      const docPubMetadataHeader = await prepareMetadata(docPubMetadata, window.__SIGN_PRIV__); // Sign available

      // Fetch doctor's public key for shared secret
      const pubRes = await fetch(`/api/user/public_key/${req.requester.id}`, {
        headers: { "X-Metadata": docPubMetadataHeader } // Attach as header
      });
      if (!pubRes.ok) throw new Error("Failed to fetch doctor public key");
      const { public_key } = await pubRes.json();
      const docPub = hexToBytes(public_key);
      const shared = await ecdhSharedSecret(window.__MY_PRIV__, docPub);
      const encDekReq = req.details.encrypted_dek;
      const reqDekBytes = base64ToBytes(encDekReq);
      
      if (reqDekBytes.length !== 60) {
        throw new Error(`Invalid encrypted DEK length: ${reqDekBytes.length} (expected 60)`);
      }
      
      const reqIv = reqDekBytes.slice(0, 12);
      const reqTag = reqDekBytes.slice(-16);
      const reqCipher = reqDekBytes.slice(12, -16);
      const reqDek = await decryptAES(reqCipher, shared, reqIv, reqTag);
      const encContent = base64ToBytes(req.details.encrypted_data);
      const contentIv = encContent.slice(0, 12);
      const contentTag = encContent.slice(-16);

      if (encContent.length < 28) {
        throw new Error(`Invalid encrypted content length: ${encContent.length} (min 28)`);
      }
      
      const contentCipher = encContent.slice(12, -16);
      const contentBytes = await decryptAES(contentCipher, reqDek, contentIv, contentTag);
      const content = bytesToBase64(contentBytes);
      const fileObj = {
        name: req.details.name || pathParts[pathParts.length - 1], // Fallback to last path part if no name
        type: "file",
        content: content,
        mime: req.details.mime,
        metadata: { created: new Date().toISOString(), size: contentBytes.length },
        addedBy: req.requester.id
      };
      if (!current.children) current.children = [];
      if (req.type.startsWith("add")) {
        current.children.push(fileObj);
      } else if (req.type.startsWith("edit")) {
        let index: number;
        if (req.details.name) {
          index = current.children.findIndex((c: RecordNode) => c.name === req.details.name);
        } else if (pathParts.length > 0) {
          const parentPath = pathParts.slice(0, -1);
          const parent = getParent(dir, parentPath);
          if (!parent || !parent.children) throw new Error("Parent not found for edit");
          const lastName = pathParts[pathParts.length - 1];
          index = parent.children.findIndex((c: RecordNode) => c.name === lastName);
          if (index === -1) throw new Error("File not found for edit");
          parent.children[index] = { ...fileObj, name: lastName }; // Keep original name
          current = parent; // Update current to parent for re-encryption
        } else {
          throw new Error("Path required for edit without name");
        }
        if (index === -1) throw new Error("File not found for edit");
        current.children[index] = fileObj;
      }
    }
    // Re-encrypt updated dir
    const newJson = new TextEncoder().encode(JSON.stringify(dir));
    const newEncrypted = await encryptAES(newJson, recordDek);
    const newConcat = new Uint8Array([...newEncrypted.iv, ...newEncrypted.ciphertext, ...newEncrypted.tag]);
    const newEncB64 = bytesToBase64(newConcat);
    // Sign
    const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
    const newSig = signEd25519(newConcat, edPriv);
    const newSigB64 = bytesToBase64(newSig);
    const metadata = {
      time: new Date().toISOString(),
      size: newConcat.length,
      privileges: 'patient',
      tree_depth: calculateMaxDepth(dir),
    };

    // Generate metadata for record update (patient-specific, tree depth from max)
    const updatePayload = {
      encrypted_data: newEncB64,
      encrypted_deks: recordData.encrypted_deks,
      signature: newSigB64,
      metadata,
    };
    const updateMetadataObj = generateMetadata(updatePayload, ['patient', 'update_record'], 'POST', calculateMaxDepth(dir));
    const updateMetadataHeader = await prepareMetadata(updateMetadataObj, window.__SIGN_PRIV__); // Sign available

    // Update record
    const updateRes = await fetch("/api/record/update/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken") || "",
        "X-Metadata": updateMetadataHeader // Attach as header
      },
      credentials: "include",
      body: JSON.stringify(updatePayload),
    });
    if (!updateRes.ok) throw new Error("Failed to update record");
    // Generate metadata for approve (patient-specific, no tree depth)
    const approveMetadata = generateMetadata({}, ['patient', 'approve_file_request'], 'POST');
    const approveMetadataHeader = await prepareMetadata(approveMetadata, window.__SIGN_PRIV__); // Sign available

    // Approve request
    const approveRes = await fetch(`/api/pending/${req.id}/approve/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken") || "",
        "X-Metadata": approveMetadataHeader // Attach as header
      },
      credentials: "include",
    });
    if (!approveRes.ok) throw new Error(await approveRes.text());
    alert("File change approved and applied!");
    fetchPendingFileRequests();
    // Refresh the record view if open
    setRefreshKey(prev => prev + 1);
  } catch (err) {
    console.error("File approval failed:", err);
    setError((err as Error).message);
  }
};

// Add this function (used in metadata and delete)
function calculateMaxDepth(node: any, current = 0): number {
  if (node.type !== 'folder' || !node.children || node.children.length === 0) return current;
  return Math.max(...node.children.map((child: any) => calculateMaxDepth(child, current + 1)), current);
}

// Updated getParent (replace the existing one)
function getParent(root: any, parts: string[]): any {
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    if (!current.children) return null;
    const child = current.children.find((c: any) => c.name.toLowerCase() === parts[i].toLowerCase());
    if (!child) return null;
    current = child;
  }
  return current;
}

  function calculateMaxDepth(node: any, current = 0): number {
    if (node.type !== 'folder' || !node.children) return current;
    return Math.max(...node.children.map((child: any) => calculateMaxDepth(child, current + 1)), current);
  }

  const denyFileRequest = async (reqId: string) => {
    if (!confirm("Deny this file change request?")) return;
    try {
      // Generate metadata for deny (patient-specific, no tree depth)
      const denyMetadata = generateMetadata({}, ['patient', 'deny_file_request'], 'POST');
      const denyMetadataHeader = await prepareMetadata(denyMetadata, window.__SIGN_PRIV__); // Sign available

      const res = await fetch(`/api/pending/${reqId}/deny/`, {
        method: "POST",
        headers: { 
          "X-CSRFToken": getCookie("csrftoken") || "",
          "X-Metadata": denyMetadataHeader // Attach as header
        },
        credentials: "include",
      });
      if (!res.ok) throw new Error(await res.text());
      alert("Request denied.");
      fetchPendingFileRequests();
    } catch (err) {
      setError((err as Error).message);
    }
  };

function getParent(root: any, parts: string[]): any {
  if (parts.length === 0) return null;
  let current = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!current.children) throw new Error("No children");
    const child = current.children.find((c: any) => c.name === part);
    if (!child) throw new Error("Path not found");
    current = child;
  }
  return current;
}

  if (error) return <div>Error: {error}</div>;
  if (!user || loading) return <div>Loading...</div>;

  return (
    <div className="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold flex items-center">
          {user.type === "doctor" ? (
            <Stethoscope className="w-8 h-8 mr-2 text-blue-600" />
          ) : (
            <User className="w-8 h-8 mr-2 text-blue-600" />
          )}
          {user.type === "doctor" ? "Doctor Portal" : "Doctor Requests"}
        </h1>
      </div>

      {user.type === "doctor" ? (
        <>
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Appointed Patients</CardTitle>
            </CardHeader>
            <CardContent>
              {appointedPatients.length === 0 ? (
                <p>No appointed patients yet. Search and request below.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>DOB</TableHead>
                      <TableHead>Appointed</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {appointedPatients.map((pat) => (
                      <TableRow key={pat.id}>
                        <TableCell>{pat.name}</TableCell>
                        <TableCell>{pat.dob}</TableCell>
                        <TableCell>{pat.appointedDate}</TableCell>
                        <TableCell className="space-x-2">
                          <Button
                            variant="outline"
                            onClick={() => viewPatientRecord(pat.id)}
                          >
                            View Record
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
            <CardFooter>
              <Dialog
                open={addPatientDialogOpen}
                onOpenChange={setAddPatientDialogOpen}
              >
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="w-4 h-4 mr-2" /> Request New Patient
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Search and Request Appointment</DialogTitle>
                  </DialogHeader>
                  <Input
                    placeholder="Search by name, DOB..."
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      searchPatients(e.target.value);
                    }}
                    className="mb-4"
                  />
                  <div className="max-h-48 overflow-y-auto">
                    {searchedPatients.map((pat) => (
                      <div
                        key={pat.id}
                        className="flex justify-between items-center py-2 border-b"
                      >
                        <span>
                          {pat.name} (DOB: {pat.dob})
                        </span>
                        <Button onClick={() => requestAppointment(pat.id)}>
                          Request
                        </Button>
                      </div>
                    ))}
                  </div>
                </DialogContent>
              </Dialog>
            </CardFooter>
          </Card>

          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Pending Requests</CardTitle>
            </CardHeader>
            <CardContent>
              {pendingRequests.length === 0 ? (
                <p>No pending requests.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Patient</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Timestamp</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pendingRequests.map((req) => (
                      <TableRow key={req.id}>
                        <TableCell>
                          {req.type
                            .replace("file_", "File ")
                            .replace("_", " ")
                            .toUpperCase()}
                        </TableCell>
                        <TableCell>
                          {req.patient_name || "N/A"}
                        </TableCell>
                        <TableCell
                          className={
                            req.status === "pending"
                              ? "text-yellow-600"
                              : req.status === "approved"
                                ? "text-green-600"
                                : req.status === "revoked"
                                ? "text-purple-600"
                                : "text-red-600"
                          }
                        >
                          {req.status.toUpperCase()}
                        </TableCell>
                        <TableCell>
                          {req.timestamp ? new Date(req.timestamp).toLocaleString() : "N/A"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
            <CardFooter>
              <Button variant="outline" onClick={fetchPendingRequests}>Refresh</Button>
            </CardFooter>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Key className="w-6 h-6 mr-2 text-green-600" />
                PKI Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              {certChain ? (
                <p>
                  CA-signed x509 chain loaded (root/intermediate/doctor). Ready
                  for signed actions.
                </p>
              ) : (
                <p>Loading PKI chain...</p>
              )}
            </CardContent>
          </Card>

        </>
      ) : (
        <>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Pending Appointment Requests</CardTitle>
          </CardHeader>
          <CardContent>
            {pendingAppointments.length === 0 ? (
              <p>No pending appointment requests from doctors.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Doctor</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pendingAppointments.map((req) => (
                    <TableRow key={req.id}>
                      <TableCell>{req.requester.name}</TableCell>
                      <TableCell>
                        {new Date(req.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="space-x-2">
                        <Button
                          variant="default"
                          onClick={() => approveAppointment(req)}
                        >
                          <Check className="w-4 h-4 mr-2" /> Approve
                        </Button>
                        <Button
                          variant="destructive"
                          onClick={() => denyAppointment(req.id)}
                        >
                          <X className="w-4 h-4 mr-2" /> Deny
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Pending File Change Requests</CardTitle>
          </CardHeader>
          <CardContent>
            {pendingFileRequests.length === 0 ? (
              <p>No pending file change requests from doctors.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Doctor</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pendingFileRequests.map((req) => (
                    <TableRow key={req.id}>
                      <TableCell>{req.type.replace("_", " ").toUpperCase()}</TableCell>
                      <TableCell>{req.requester.name}</TableCell>
                      <TableCell>{`${req.details.path || ""}${req.details.name ? `/${req.details.name}` : ""}`}</TableCell>
                      <TableCell>
                        {new Date(req.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="space-x-2">
                        <Button
                          variant="default"
                          onClick={() => approveFileRequest(req)}
                        >
                          <Check className="w-4 h-4 mr-2" /> Approve
                        </Button>
                        <Button
                          variant="destructive"
                          onClick={() => denyFileRequest(req.id)}
                        >
                          <X className="w-4 h-4 mr-2" /> Deny
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
        </>
      )}

      {/* Input Priv Dialog */}
      <Dialog open={inputPrivOpen} onOpenChange={setInputPrivOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enter Private Key</DialogTitle>
            <DialogDescription>
              Paste the base64-encoded X25519 private key from your password
              manager. This is required for E2EE on this device.
            </DialogDescription>
          </DialogHeader>
          <Input
            type="password"
            value={inputPriv}
            onChange={(e) => setInputPriv(e.target.value)}
            placeholder="Base64 private key..."
          />
          <DialogFooter>
            <Button onClick={handlePrivInput}>Submit</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Input Cert Priv Dialog */}
      <Dialog open={inputCertPrivOpen} onOpenChange={setInputCertPrivOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enter Certificate Private Key</DialogTitle>
            <DialogDescription>
              Paste the PKI-signed Certificate Private Key from your password
              manager. This is required for signing file change requests.
            </DialogDescription>
          </DialogHeader>
          <Input
            type="password"
            value={inputCertPriv}
            onChange={(e) => setInputCertPriv(e.target.value)}
            placeholder="Base64 certificate private key..."
          />
          <DialogFooter>
            <Button onClick={handleCertPrivInput}>Submit</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
