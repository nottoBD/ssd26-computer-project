/**
 * FILE: record.tsx
 *
 * PURPOSE:
 *      Implements the Medical Record page 
 *      Provides a patient-facing portal to manage an encrypted record tree,
 *      and a doctor-facing portal to view a patient record and submit encrypted change requests
 *
 * CORE SECURITY GOALS:
 *  - End-to-End Encryption (E2EE): server stores ciphertext only
 *  - Fine-grained sharing: patient selectively grants doctors access to the Data Encryption Key (DEK)
 *  - Integrity + authenticity: Ed25519 signatures protect record ciphertext from tampering
 *  - Zero-knowledge server: the backend cannot decrypt medical content
 *
 * CRYPTO DESIGN OVERVIEW:
 *  - Record payload is JSON serialized then encrypted with a random DEK (AES-GCM)
 *  - The encrypted record blob is signed using an Ed25519 key derived from the user X25519 private key
 *  - The DEK is wrapped (encrypted) multiple times:
 *      (a) For patient self-access: DEK wrapped under masterKEK = SHA256(patient_x25519_priv)
 *      (b) For each appointed doctor: DEK wrapped under shared_secret = X25519(patient_priv, doctor_pub)
 *  - Doctors never receive plaintext record content unless they can derive the shared_secret for DEK unwrap
 *
 * KEY MATERIAL HANDLING:
 *  - X25519 private key is expected in memory (window.__MY_PRIV__) or sessionStorage fallback
 *  - The page verifies that the supplied private key matches the public key stored server-side
 *    to prevent accidental key mismatch and signature verification failures
 *
 * ROLE-BASED BEHAVIOR:
 *  - Patient:
 *      - Can add/edit/delete record nodes locally, then "Save Record" to re-encrypt and upload ciphertext
 *      - Can appoint/revoke doctors; appointing includes sending a DEK wrapped for that doctor
 *      - Can rotate keys (new X25519 identity + new DEK) and re-encrypt everything
 *  - Doctor:
 *      - Can list appointed patients and view a selected patient record (read-only)
 *      - Cannot directly modify record; instead submits encrypted "pending requests" to patient
 */
import { useState, useEffect, useMemo } from 'react'
import { createFileRoute, Link, useNavigate, useSearch, Outlet } from '@tanstack/react-router'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { redirect } from '@tanstack/react-router'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from '@/components/ui/dialog'
import { Card, CardContent, CardDescription, CardFooter, CardTitle, CardHeader} from "@/components/ui/card";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuPortal, DropdownMenuLabel } from '@/components/ui/dropdown-menu'
import { ChevronDown, ChevronRight, Folder, FileText, MoreVertical, Plus, Upload, Edit, Trash, User, Calendar, Shield, Key, Stethoscope } from 'lucide-react'
import { encryptAES, decryptAES, signEd25519, verifyEd25519, ecdhSharedSecret, deriveEd25519FromX25519, randomBytes, bytesToHex, hexToBytes, generateX25519Keypair, getX25519PublicFromPrivate, bytesToBase64, base64ToBytes } from '../components/CryptoUtils'
import { useAuth } from './__root'
import { Document, Page, pdfjs } from 'react-pdf';
import { saveKey, getKey } from "../lib/key-store";
import { generateMetadata, prepareMetadata } from '../lib/metadata'; // New import for metadata


interface RecordNode {
  name: string
  type: 'folder' | 'file'
  children?: RecordNode[]
  content?: string // base64 encoded
  mime?: string
  metadata: { created: string; size: number }
  addedBy?: string // 'self' or doctorId
}

interface User {
  id: string
  type: 'patient' | 'doctor'
  name: string
  dob?: string
  org?: string
}

interface Patient {
  id: string
  name: string
  dob: string
  appointedDate: string
}

interface AppointedDoctor {
  id: string
  email: string
}

interface CertChain {
  root: string;
  intermediate: string;
  doctor: string;
}

/**
 * ROUTE GUARD: beforeLoad
 *
 * PURPOSE:
 *      Enforces that /record is only accessible to authenticated users
 *
 * FLOW:
 *  1) Call backend /api/webauthn/auth/status/ with session cookies
 *  2) If not authenticated, redirect to /login
 *
 * SECURITY NOTE:
 *  - This is a UI guard only. The backend must still enforce authorization on every API endpoint
 */

export const Route = createFileRoute('/record')({
  beforeLoad: async () => {
    try {
      // Generate metadata for auth status check (auth-specific, no tree depth)
      const authPayload = {}; // Empty body
      const authMetadata = generateMetadata(authPayload, ['user', 'auth_status'], 'GET');
      const authMetadataHeader = await prepareMetadata(authMetadata, window.__SIGN_PRIV__); // Sign if available

      const response = await fetch('/api/webauthn/auth/status/', {
        method: 'GET',
        credentials: 'include',
        headers: { "X-Metadata": authMetadataHeader } // Attach as header
      });
      if (!response.ok) {
        throw new Error('Not authenticated');
      }
      const data = await response.json();
      if (!data.authenticated) {
        throw new Error('Not authenticated');
      }
    } catch (err) {
      throw redirect({ to: '/login' });
    }
  },
  component: RecordPage,
});

/**
 * FUNCTION: deriveMasterKEK
 *
 * PURPOSE:
 *      Derives a patient-local “master key encryption key” used to wrap/unwrap
 *      the record DEK for patient self-access
 *
 * INPUT:
 *  - priv: patient's X25519 private key bytes
 *
 * OUTPUT:
 *  - 32-byte key = SHA-256(priv)
 *
 * SECURITY RATIONALE:
 *  - Enables the patient to decrypt their own DEK without involving any doctor keys.
 *  - Note: hashing a private key into a KEK is a pragmatic derivation; in a hardened design,
 *    HKDF with context info would be preferable to avoid key reuse across domains across domains
 */
async function deriveMasterKEK(priv: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', priv);
  return new Uint8Array(digest);
}


/**
 * FUNCTION: getCookie
 *
 * PURPOSE:
 *      Reads CSRF token (or other cookie values) from document.cookie to attach
 *      to state-changing requests
 *
 * SECURITY NOTE:
 *  - Used for X-CSRFToken header on write operations
 */

function getCookie(name: string): string | undefined {
  const matches = document.cookie.match(new RegExp(
    "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
  ));
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function RecordPage() {
  const { isAuthenticated } = useAuth()
  const navigate = useNavigate()
  const search = useSearch({ from: '/record' })
  const patientId = search.patient as string | undefined

  const [user, setUser] = useState<User | null>(null)
  const [record, setRecord] = useState<RecordNode | null>(null)
  const [isDirty, setIsDirty] = useState(false)
  const [numPages, setNumPages] = useState<number | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [selectedPath, setSelectedPath] = useState<string[]>([])
  const [appointedDoctors, setAppointedDoctors] = useState<AppointedDoctor[]>([])
  const [appointedPatients, setAppointedPatients] = useState<Patient[]>([])
  const [patientInfo, setPatientInfo] = useState<{ name: string; dob: string } | null>(null)
  const [openFolders, setOpenFolders] = useState<Set<string>>(new Set())
  const [addDoctorDialogOpen, setAddDoctorDialogOpen] = useState(false)
  const [addRecordOpen, setAddRecordOpen] = useState(false)
  const [addType, setAddType] = useState<'folder' | 'text' | 'binary' | null>(null)
  const [addName, setAddName] = useState('')
  const [addContent, setAddContent] = useState('')
  const [addFile, setAddFile] = useState<File | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchedDoctors, setSearchedDoctors] = useState<AppointedDoctor[]>([])
  const [requestDialogOpen, setRequestDialogOpen] = useState(false)
  const [requestType, setRequestType] = useState<'add_folder' | 'add_text' | 'add_binary' | 'edit_text' | 'edit_binary' | 'delete' | null>(null)
  const [requestName, setRequestName] = useState('')
  const [requestContent, setRequestContent] = useState('')
  const [requestFile, setRequestFile] = useState<File | null>(null)
  const [patientPub, setPatientPub] = useState<Uint8Array | null>(null)
  const [patientSignPub, setPatientSignPub] = useState<Uint8Array | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [rotateOpen, setRotateOpen] = useState(false)
  const [inputPrivOpen, setInputPrivOpen] = useState(false)
  const [inputPriv, setInputPriv] = useState('')
  const [certChain, setCertChain] = useState<CertChain | null>(null);
  const [inputCertPrivOpen, setInputCertPrivOpen] = useState(false);
  const [inputCertPriv, setInputCertPriv] = useState("");
  const [rawRecordData, setRawRecordData] = useState<{ encrypted_data: string; signature: string; encrypted_deks: Record<string, string>; encrypted_dek?: string } | null>(null)
  const [refreshKey, setRefreshKey] = useState(0);

  const doctorEmails = useMemo(() => {
    return appointedDoctors.reduce((acc: Record<string, string>, d) => {
      acc[d.id] = d.email;
      return acc;
    }, {});
  }, [appointedDoctors]);

const fixTree = (node: RecordNode): RecordNode => {
      if (!node.name) {
        node.name = 'untitled';
      }
      if (node.children && Array.isArray(node.children)) {
        node.children = node.children
          .filter(child => child != null && typeof child === 'object')
          .map(fixTree);
      }
      return node;
    }

  useEffect(() => {
    pdfjs.GlobalWorkerOptions.workerSrc = new URL(
      'pdfjs-dist/build/pdf.worker.min.mjs',
      import.meta.url
    ).toString();
  }, []);

  useEffect(() => {
    setNumPages(null);
    setCurrentPage(1);
  }, [selectedPath]);

  useEffect(() => {
    const stored = sessionStorage.getItem('x25519_priv_b64');
    if (stored) {
      window.__MY_PRIV__ = base64ToBytes(stored);
    }
    async function loadCertKey() {
      if (user?.type === "doctor") {
        const storedCert = await getKey('cert_priv');
        if (storedCert) {
          window.__MY_CERT_PRIV__ = storedCert as Uint8Array;
        }
      }
    }
    loadCertKey();
  }, [user]);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        // Generate metadata for user me fetch (user-specific, no tree depth)
        const meMetadata = generateMetadata({}, ['user', 'get_me'], 'GET');
        const meMetadataHeader = await prepareMetadata(meMetadata, window.__SIGN_PRIV__); // Sign if available

        const r = await fetch('/api/user/me/', {
          headers: { "X-Metadata": meMetadataHeader } // Attach as header
        });
        if (!r.ok) throw new Error(await r.text());
        const data = await r.json();
        setUser(data);
      } catch (err) {
        console.error('User fetch failed:', err);
        setError(err.message);
      }
    };
    fetchUser();
  }, []);

useEffect(() => {
  if (!user) return

  (async () => {
    if (window.__MY_PRIV__) {
      try {
        // Generate metadata for own public key fetch (user-specific, no tree depth)
        const ownPubMetadata = generateMetadata({}, ['user', 'get_public_key'], 'GET');
        const ownPubMetadataHeader = await prepareMetadata(ownPubMetadata, window.__SIGN_PRIV__); // Sign available

        const rOwnPub = await fetch(`/api/user/public_key/${user.id}`, {
          headers: { "X-Metadata": ownPubMetadataHeader } // Attach as header
        });
        if (!rOwnPub.ok) throw new Error('Failed to fetch own public key');
        const ownData = await rOwnPub.json();
        const ownPub = hexToBytes(ownData.public_key);
        const derivedPub = getX25519PublicFromPrivate(window.__MY_PRIV__);
        const match = derivedPub.every((val, i) => val === ownPub[i]);
        if (!match) {
          throw new Error('Loaded private key does not match server public key.');
        }
        console.log(`${user.type.charAt(0).toUpperCase() + user.type.slice(1)} private key verified successfully`);
      } catch (err) {
        console.warn(err.message + ' Forcing re-entry.');
        window.__MY_PRIV__ = null;
        sessionStorage.removeItem('x25519_priv_b64');
        setInputPrivOpen(true);
        return;
      }
    } else {
      setInputPrivOpen(true);
      return;
    }

    if (user.type === 'doctor') {
      fetchCertChain();
      if (!window.__MY_CERT_PRIV__) {
        setInputCertPrivOpen(true);
      }
    }

    if (user.type === 'patient') {
      fetchRecord('/api/record/my/', true)
      fetchAppointedDoctors()
    } else if (user.type === 'doctor') {
      if (patientId) {
        // Fetch patient pub first, then record
        // Generate metadata for patient public key fetch (doctor-specific, no tree depth)
        const patientPubMetadata = generateMetadata({}, ['doctor', 'get_patient_public_key'], 'GET');
        const patientPubMetadataHeader = await prepareMetadata(patientPubMetadata, window.__SIGN_PRIV__); // Sign available

        const rPub = await fetch(`/api/user/public_key/${patientId}?_=${refreshKey}`, {
          headers: { "X-Metadata": patientPubMetadataHeader } // Attach as header
        }); // Cache bust
        if (!rPub.ok) {
          const errText = await rPub.text();
          throw new Error('Failed to fetch patient public key: ' + errText);
        }
        const pubData = await rPub.json();
        const { public_key, signing_public_key } = pubData;
        if (!public_key || typeof public_key !== 'string') {
          throw new Error('Invalid or missing encryption public key');
        }
        if (!signing_public_key || typeof signing_public_key !== 'string') {
          throw new Error('Invalid or missing signing public key');
        }
        const pubBytes = hexToBytes(public_key);
        const signPubBytes = hexToBytes(signing_public_key);
        setPatientPub(pubBytes);
        setPatientSignPub(signPubBytes);

        await fetchRecord(`/api/record/patient/${patientId}/`, false, pubBytes, signPubBytes);
      } else {
        fetchAppointedPatients()
      }
    }
  })();
}, [user, patientId, refreshKey])

/**
 * FUNCTION: fetchRecord
 *
 * PURPOSE:
 *      Fetches encrypted medical record data from backend and triggers
 *      client-side decryption + signature verification.
 *
 * INPUTS:
 *  - url: API endpoint to fetch record
 *  - isSelf: true for patient accessing own record; false for doctor accessing patient record
 *  - patientPubBytes / patientSignPubBytes: required for doctor case (shared secret + signature verify)
 *
 * FLOW:
 *  1) Fetch encrypted record blob + signature + DEK wrapper(s).
 *  2) Determine which encrypted DEK wrapper applies:
 *      - patient self: encrypted_deks["self"]
 *      - doctor view: encrypted_dek (already pre-selected by backend)
 *  3) Store raw data in state (rawRecordData) for debugging/inspection.
 *  4) If ciphertext exists, call processRawRecord(...). Otherwise initialize empty record tree.
 *
 * FAILURE MODE:
 *  - If fetch fails or data missing, surface error to UI and avoid partial decrypt states.
 */

  const fetchRecord = async (url: string, isSelf: boolean, patientPubBytes?: Uint8Array, patientSignPubBytes?: Uint8Array) => {
    try {
      // Generate metadata for record fetch (role-specific, tree depth 0 for root)
      const recordMetadata = generateMetadata({}, [user?.type || 'user', 'get_record'], 'GET', 0);
      const recordMetadataHeader = await prepareMetadata(recordMetadata, window.__SIGN_PRIV__); // Sign if available

      const r = await fetch(url, {
        headers: { "X-Metadata": recordMetadataHeader } // Attach as header
      })
      if (!r.ok) {
        const errorText = await r.text()
        throw new Error('Fetch record failed: ' + errorText)
      }
      const res = await r.json()
      const encrypted_data = res.encrypted_data
      const signature = res.signature
      const patient = res.patient
      if (patient) setPatientInfo({ name: patient.name, dob: patient.dob })

      let encDek: string | undefined
      if (isSelf) {
        const encrypted_deks = res.encrypted_deks || {}
        encDek = encrypted_deks['self']
      } else {
        encDek = res.encrypted_dek
      }

      setRawRecordData({ encrypted_data, signature, encrypted_deks: res.encrypted_deks, encrypted_dek: res.encrypted_dek })

      if (encrypted_data && encDek) {
        await processRawRecord(isSelf, encrypted_data, signature, encDek, patientPubBytes, patientSignPubBytes)
      } else {
        setRecord({ name: 'Root', type: 'folder', children: [], metadata: { created: new Date().toISOString(), size: 0 } })
        setIsDirty(false)
        window.__CURRENT_DEK__ = null
      }
    } catch (err) {
      console.error('Record fetch failed:', err)
      setError(err.message)
    }
  }

/**
 * FUNCTION: processRawRecord
 *
 * PURPOSE:
 *      Decrypts and validates an encrypted record blob, then loads it into the UI.
 *
 * FLOW:
 *  1) Split encrypted record blob into (iv | ciphertext | tag) for AES-GCM.
 *  2) Obtain DEK:
 *      - patient self: decryptDEK(encDek, masterKEK) where masterKEK = SHA256(patient_priv)
 *      - doctor view: decryptDEK(encDek, shared_secret) where shared_secret = X25519(doctor_priv, patient_pub)
 *  3) Verify integrity/authenticity:
 *      - verifyEd25519(signature, rawBytes, edPub)
 *      - patient case uses Ed25519 derived from local priv
 *      - doctor case uses patient signing public key fetched from server
 *  4) AES-GCM decrypt ciphertext → JSON parse → setRecord(...)
 *  5) Cache the active DEK into window.__CURRENT_DEK__ for later edits/saves.
 *
 * SECURITY NOTES:
 *  - Signature verification is essential: AES-GCM already provides integrity for ciphertext,
 *    but signature ties the record to the patient's identity key and defends against server-side swapping.
 *  - If signature fails in self-mode, the UI forces private-key re-entry (reduces “wrong key” confusion).
 */

  const processRawRecord = async (isSelf: boolean, encrypted_data: string, signature: string, encDek: string, patientPubBytes?: Uint8Array, patientSignPubBytes?: Uint8Array) => {
    const rawBytes = base64ToBytes(encrypted_data)
    const iv = rawBytes.slice(0, 12)
    const tag = rawBytes.slice(-16)
    const ciphertext = rawBytes.slice(12, -16)

    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true)
      return
    }

    let dek: Uint8Array
    try {
      if (isSelf) {
        const masterKEK = await deriveMasterKEK(window.__MY_PRIV__)
        dek = await decryptDEK(encDek, masterKEK)
      } else {
        if (!patientPubBytes) throw new Error('Patient public key required')
        const shared = await ecdhSharedSecret(window.__MY_PRIV__, patientPubBytes)
        const sharedHash = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', shared)));
console.log(`Doctor-side shared hash for patient ${patientId}: ${sharedHash}`);
        
        dek = await decryptDEK(encDek, shared)
      }

      // Verify signature
      const edPub = isSelf ? deriveEd25519FromX25519(window.__MY_PRIV__).publicKey : patientSignPubBytes!;
      const verified = verifyEd25519(base64ToBytes(signature), rawBytes, edPub)
      if (!verified) {
        if (isSelf) {
          setInputPrivOpen(true)
          return
        } else {
          throw new Error('Signature verification failed')
        }
      }

      const decrypted = await decryptAES(ciphertext, dek, iv, tag)
      const parsed = JSON.parse(new TextDecoder().decode(decrypted)) as RecordNode
      setRecord(parsed)
      setIsDirty(false)
      window.__CURRENT_DEK__ = dek
    } catch (err) {
      console.error('Decryption failed:', err)
      if (isSelf) {
        setInputPrivOpen(true)
      } else {
        setError('Failed to decrypt patient record')
      }
      return
    }
  }



  /**
 * FUNCTION: decryptDEK
 *
 * PURPOSE:
 *      Unwraps (decrypts) an encrypted DEK using AES-GCM with a provided key
 *      (either masterKEK for self-access or ECDH shared secret for doctor access).
 *
 * INPUT:
 *  - encDekStr: base64 string encoding (iv | ciphertext | tag)
 *  - key: 32-byte symmetric key to decrypt the DEK wrapper
 *
 * VALIDATION:
 *  - Enforces expected wrapped length: 60 bytes = 12 IV + 32 ciphertext + 16 tag
 *    (because DEK is exactly 32 bytes).
 *
 * OUTPUT:
 *  - plaintext DEK (32 bytes)
 */

  const decryptDEK = async (encDekStr: string, key: Uint8Array): Promise<Uint8Array> => {
    const dekBytes = base64ToBytes(encDekStr)
    console.log('Encrypted DEK length:', dekBytes.length);  // Should be 60 (12 IV + 32 ciphertext + 16 tag)
    if (dekBytes.length !== 60) {
      throw new Error(`Invalid encrypted DEK length: ${dekBytes.length} (expected 60)`);
  }
    const iv = dekBytes.slice(0, 12)
    const tag = dekBytes.slice(-16)
    const ciphertext = dekBytes.slice(12, -16)
    console.log('DEK ciphertext length:', ciphertext.length);  // Should be 32
    return await decryptAES(ciphertext, key, iv, tag)
  }



/**
 * FUNCTION: handlePrivInput
 *
 * PURPOSE:
 *      Allows manual import of the X25519 private key (password manager fallback),
 *      verifies it against server public key, and optionally re-encrypts it using PRF KEK.
 *
 * FLOW:
 *  1) Decode base64 → newPriv.
 *  2) Store to window.__MY_PRIV__ and sessionStorage for the session.
 *  3) Verify consistency:
 *      - derivedPub(newPriv) must equal server public_key for this user.
 *      - If mismatch, reject and instruct user to input correct key or rotate.
 *  4) If window.__KEK__ is available (PRF-supported login), encrypt and upload encrypted_priv
 *     to server so future logins can decrypt automatically.
 *  5) Reload record using correct role path (self or doctor patient view).
 *
 * SECURITY NOTES:
 *  - Verification step prevents accidental usage of wrong key (would break decrypt + signatures).
 *  - Storing private keys in sessionStorage is a tradeoff; acceptable for prototype/demo,
 *    but should be minimized in production.
 */

const handlePrivInput = async () => {
try {
  const newPriv = base64ToBytes(inputPriv)
  window.__MY_PRIV__ = newPriv
  sessionStorage.setItem('x25519_priv_b64', inputPriv);

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

  // If has KEK (PRF), encrypt and update on server
  if (window.__KEK__) {
    const encryptedPriv = await encryptAES(newPriv, window.__KEK__)
    const encryptedPrivStr = bytesToBase64(new Uint8Array([...encryptedPriv.iv, ...encryptedPriv.ciphertext, ...encryptedPriv.tag]))

    // Generate metadata for keys update (user-specific, tree depth 0)
    const updatePayload = { encrypted_priv: encryptedPrivStr };
    const updateMetadata = generateMetadata(updatePayload, ['user', 'update_keys'], 'POST', 0);
    const updateMetadataHeader = await prepareMetadata(updateMetadata, window.__SIGN_PRIV__); // Sign available

    const r = await fetch('/api/user/keys/update/', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        'X-CSRFToken': getCookie('csrftoken') || '',
        "X-Metadata": updateMetadataHeader // Attach as header
      },
      credentials: 'include',
      body: JSON.stringify(updatePayload)
    })
    if (!r.ok) console.error('Failed to update encrypted priv')
  }

  setInputPrivOpen(false)
  setInputPriv('')

  // Trigger fetch after setting priv
  const isSelf = user!.type === 'patient'
  if (isSelf) {
    await fetchRecord('/api/record/my/', true)
  } else if (patientId) {
    // Generate metadata for patient public key fetch (doctor-specific, no tree depth)
    const patientPubMetadata = generateMetadata({}, ['doctor', 'get_patient_public_key'], 'GET');
    const patientPubMetadataHeader = await prepareMetadata(patientPubMetadata, window.__SIGN_PRIV__); // Sign available

    const rPub = await fetch(`/api/user/public_key/${patientId}`, {
      headers: { "X-Metadata": patientPubMetadataHeader } // Attach as header
    });
    if (!rPub.ok) throw new Error('Failed to fetch patient public key');
    const pubData = await rPub.json();
    const pubBytes = hexToBytes(pubData.public_key);
    const signPubBytes = hexToBytes(pubData.signing_public_key);
    setPatientPub(pubBytes);
    setPatientSignPub(signPubBytes);
    await fetchRecord(`/api/record/patient/${patientId}/`, false, pubBytes, signPubBytes);
  }
} catch (err) {
  setError((err as Error).message)  // Now shows the mismatch error
}
}

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

const fetchCertChain = async () => {
  try {
    // Generate metadata for cert chain fetch (doctor-specific, no tree depth)
    const certMetadata = generateMetadata({}, ['doctor', 'get_cert_chain'], 'GET');
    const certMetadataHeader = await prepareMetadata(certMetadata, window.__SIGN_PRIV__); // Sign if available

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

/**
 * FUNCTION: fetchAppointedDoctors
 *
 * PURPOSE:
 *      Retrieves the list of doctors currently appointed by the authenticated patient.
 *      This list is used for:
 *        - Displaying "Appointed Doctors" in the UI
 *        - Computing DEK wrapping targets during updateRecord() (sharing DEK with each)
 *
 * FLOW:
 *  1) GET /api/appoint/doctors/ with session cookies.
 *  2) Expect JSON: { doctors: [...] }.
 *  3) Store doctors in appointedDoctors state.
 *
 * SECURITY / AUTHZ NOTES:
 *  - Endpoint must enforce that only the patient can read their own appointment list.
 *  - updateRecord() relies on this list to decide who receives encrypted DEKs.
 *    If this list is stale, DEK sharing may be incomplete (doctor can lose access) or overly broad
 *    (revoked doctor might still be included until next refresh + re-encrypt).
 */

  const fetchAppointedDoctors = async () => {
    try {
      // Generate metadata for appointed doctors fetch (patient-specific, no tree depth)
      const doctorsMetadata = generateMetadata({}, ['patient', 'get_appointed_doctors'], 'GET');
      const doctorsMetadataHeader = await prepareMetadata(doctorsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch('/api/appoint/doctors/', {
        headers: { "X-Metadata": doctorsMetadataHeader } // Attach as header
      })
      if (!r.ok) throw new Error(await r.text())
      const { doctors } = await r.json()
      setAppointedDoctors(doctors)
    } catch (err) {
      console.error('Doctors fetch failed:', err)
      setError(err.message)
    }
  }


/**
 * FUNCTION: fetchAppointedPatients
 *
 * PURPOSE:
 *      Retrieves the list of patients that have appointed the authenticated doctor.
 *      Used in the doctor portal to populate the "Appointed Patients" table to allow
 *      navigation to a specific patient record view.
 *
 * FLOW:
 *  1) GET /api/appoint/patients/ with session cookies.
 *  2) Expect JSON: { patients: [...] }.
 *  3) Store patients in appointedPatients state.
 *
 * SECURITY / AUTHZ NOTES:
 *  - Endpoint must enforce that only doctors see their own appointed patients.
 *  - This list represents an access-control boundary: a doctor should only be able to fetch
 *    /api/record/patient/{id}/ for patients returned by this endpoint (or otherwise authorized).
 */
  const fetchAppointedPatients = async () => {
    try {
      // Generate metadata for appointed patients fetch (doctor-specific, no tree depth)
      const patientsMetadata = generateMetadata({}, ['doctor', 'get_appointed_patients'], 'GET');
      const patientsMetadataHeader = await prepareMetadata(patientsMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch('/api/appoint/patients/', {
        headers: { "X-Metadata": patientsMetadataHeader } // Attach as header
      })
      if (!r.ok) throw new Error(await r.text())
      const { patients } = await r.json()
      setAppointedPatients(patients)
    } catch (err) {
      console.error('Patients fetch failed:', err)
      setError(err.message)
    }
  }


/**
 * FUNCTION: updateRecord
 *
 * PURPOSE:
 *      Encrypts and signs the current record tree, wraps the DEK for all authorized readers,
 *      and uploads only ciphertext to the server.
 *
 * INPUT:
 *  - rotate (default false):
 *      - false: reuse current identity key (X25519 priv) and current DEK (if available)
 *      - true: generate a new X25519 keypair AND a new DEK, then re-encrypt and re-share
 *
 * FLOW:
 *  1) Refresh appointedDoctors to ensure sharing list is current.
 *  2) Select DEK:
 *      - rotate: randomBytes(32)
 *      - else: reuse window.__CURRENT_DEK__ if present, otherwise generate random
 *  3) (Optional rotate) Generate new X25519 identity keypair and derived Ed25519 signing key.
 *  4) Encrypt record JSON with AES-GCM under DEK → concatenated = (iv|ciphertext|tag).
 *  5) Sign concatenated blob using Ed25519 derived from current/rotated X25519 private key.
 *  6) Build DEK wrappers (encrypted_deks):
 *      - self wrapper: encryptAES(DEK, masterKEK = SHA256(patient_priv))
 *      - doctor wrappers: for each appointed doctor:
 *          shared = X25519(patient_priv, doctor_pub)
 *          encryptAES(DEK, shared)
 *  7) POST encrypted_data + encrypted_deks + signature + metadata to /api/record/update/.
 *  8) If rotate:
 *      - update server public keys (/api/user/keys/update/)
 *      - optionally store encrypted_priv if window.__KEK__ exists
 *      - update local window.__MY_PRIV__ and sessionStorage
 *
 * SECURITY NOTES:
 *  - The server never receives the plaintext record or plaintext DEK.
 *  - Rotation re-keys both identity and content, invalidating access for any party
 *    not included in the newly wrapped encrypted_deks map.
 */
const updateRecord = async (rotate = false) => {
  if (!record) return alert('No record to update.')
  if (!window.__MY_PRIV__) {
    setInputPrivOpen(true)
    return
  }
  try {
    await fetchAppointedDoctors();  // Refresh appointed doctors to ensure latest list before computing DEKs
    let dek = rotate ? randomBytes(32) : (window.__CURRENT_DEK__ || randomBytes(32))
    let priv = window.__MY_PRIV__
    let pubUpdate: string | undefined
    let signPubUpdate: string | undefined
    if (rotate) {
      const newKeypair = generateX25519Keypair()
      priv = newKeypair.privateKey
      const newEdPair = deriveEd25519FromX25519(priv)
      pubUpdate = bytesToHex(newKeypair.publicKey)
      signPubUpdate = bytesToHex(newEdPair.publicKey)
    }
    const masterKEK = await deriveMasterKEK(priv)
    const raw = new TextEncoder().encode(JSON.stringify(record))
    const encrypted = await encryptAES(raw, dek)
    const concatenated = new Uint8Array([...encrypted.iv, ...encrypted.ciphertext, ...encrypted.tag])
    const edPriv = deriveEd25519FromX25519(priv).privateKey
    const sig = signEd25519(concatenated, edPriv)
    const deks: Record<string, string> = {}
    // Self
    const encryptedSelfDek = await encryptAES(dek, masterKEK)
    deks['self'] = bytesToBase64(new Uint8Array([...encryptedSelfDek.iv, ...encryptedSelfDek.ciphertext, ...encryptedSelfDek.tag]))
    // Doctors
    for (const doc of appointedDoctors) {
      // Generate metadata for doctor public key fetch (patient-specific, no tree depth)
      const docPubMetadata = generateMetadata({}, ['patient', 'get_doctor_public_key'], 'GET');
      const docPubMetadataHeader = await prepareMetadata(docPubMetadata, window.__SIGN_PRIV__); // Sign available

      const docPubRes = await fetch(`/api/user/public_key/${doc.id}`, {
        headers: { "X-Metadata": docPubMetadataHeader } // Attach as header
      })
      if (!docPubRes.ok) continue
      const { public_key } = await docPubRes.json()
      const docPubBytes = hexToBytes(public_key)
      const shared = await ecdhSharedSecret(priv, docPubBytes)
      const encryptedDek = await encryptAES(dek, shared)
      deks[doc.id] = bytesToBase64(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))
    }
    const metadata = {
      time: new Date().toISOString(),
      size: concatenated.length,
      privileges: 'patient',
      tree_depth: calculateMaxDepth(record),
    }

    // Generate metadata for record update (patient-specific, tree depth from max)
    const updatePayload = {
      encrypted_data: bytesToBase64(concatenated),
      encrypted_deks: deks,
      signature: bytesToBase64(sig),
      metadata,
    };
    const updateMetadataObj = generateMetadata(updatePayload, ['patient', 'update_record'], 'POST', calculateMaxDepth(record));
    const updateMetadataHeader = await prepareMetadata(updateMetadataObj, window.__SIGN_PRIV__); // Sign available

    const r = await fetch('/api/record/update/', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        'X-CSRFToken': getCookie('csrftoken') || '',
        "X-Metadata": updateMetadataHeader // Attach as header
      },
      credentials: 'include',
      body: JSON.stringify(updatePayload),
    })
    if (!r.ok) throw new Error('Update error: ' + await r.text())
    if (rotate) {
      let body: any = { public_key: pubUpdate, signing_public_key: signPubUpdate }
      if (window.__KEK__) {
        const encryptedPriv = await encryptAES(priv, window.__KEK__)
        body.encrypted_priv = bytesToBase64(new Uint8Array([...encryptedPriv.iv, ...encryptedPriv.ciphertext, ...encryptedPriv.tag]))
      }

      // Generate metadata for keys update (patient-specific, tree depth 0)
      const keysUpdateMetadata = generateMetadata(body, ['patient', 'update_keys'], 'POST', 0);
      const keysUpdateMetadataHeader = await prepareMetadata(keysUpdateMetadata, window.__SIGN_PRIV__); // Sign available

      const kr = await fetch('/api/user/keys/update/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'X-CSRFToken': getCookie('csrftoken') || '',
          "X-Metadata": keysUpdateMetadataHeader // Attach as header
        },
        credentials: 'include',
        body: JSON.stringify(body)
      })
      if (!kr.ok) throw new Error('Key update failed')
      window.__MY_PRIV__ = priv
      sessionStorage.setItem('x25519_priv_b64', bytesToBase64(priv));
      alert(`Keys rotated successfully. Update your password manager with the new private key: ${bytesToBase64(priv)}`)
    }
    window.__CURRENT_DEK__ = dek
    setIsDirty(false)
    if (rotate) {
      // Refresh record to verify
      fetchRecord('/api/record/my/', true)
    }
  } catch (err) {
    console.error('Update failed:', err)
    setError(err.message)
  }
}
  

/**
 * FUNCTION: handleRotate
 *
 * PURPOSE:
 *      UI wrapper for key rotation. Confirms user intent then calls updateRecord(true).
 *
 * SECURITY NOTE:
 *  - Rotation is disruptive: user must update password manager with new private key
 *    if PRF is not available.
 */

  const handleRotate = () => {
    if (confirm('Rotate encryption keys? This will generate a new identity key and DEK.')) {
      updateRecord(true)
    }
    setRotateOpen(false)
  }

  const handleRefresh = async () => {
    if (user?.type === 'doctor' && patientId) {
      setRefreshKey(prev => prev + 1); // Trigger useEffect re-run with new key for cache bust
    }
  };


  /**
 * FUNCTION: calculateMaxDepth
 *
 * PURPOSE:
 *      Computes maximum tree depth of the record structure.
 *
 * USE:
 *  - Included as metadata to help demonstrate structural constraints and for auditing/debug.
 */

  const calculateMaxDepth = (node: RecordNode, current = 0): number => {
    if (node.type !== 'folder' || !node.children) return current
    return Math.max(...node.children.map((child) => calculateMaxDepth(child, current + 1)), current)
  }


  /**
 * FUNCTION: removeDoctor
 *
 * PURPOSE:
 *      Revokes doctor appointment from the patient side (server-side authorization).
 *
 * SECURITY NOTE:
 *  - Revocation removes the appointment relation, but effective cryptographic revocation
 *    requires a subsequent updateRecord() / rotation to stop sharing future DEKs with that doctor.
 */

  const removeDoctor = async (doctorId: string) => {
    if (!confirm('Remove this doctor? You may need to rotate keys to fully revoke access.')) return;
    try {
      // Generate metadata for remove doctor (patient-specific, no tree depth)
      const removeMetadata = generateMetadata({}, ['patient', 'remove_doctor'], 'DELETE');
      const removeMetadataHeader = await prepareMetadata(removeMetadata, window.__SIGN_PRIV__); // Sign available

      const res = await fetch(`/api/appoint/remove/${doctorId}/`, { 
        method: 'DELETE',
        headers: { 
          'X-CSRFToken': getCookie('csrftoken') || '',
          "X-Metadata": removeMetadataHeader // Attach as header
        },
        credentials: 'include'
      })
      if (!res.ok) throw new Error('Remove failed: ' + await res.text())
      fetchAppointedDoctors()
    } catch (err) {
      console.error('Remove doctor failed:', err)
      setError(err.message)
    }
  }

  const searchDoctors = async (q: string) => {
    if (!q) return
    try {
      // Generate metadata for doctors search (patient-specific, no tree depth)
      const searchMetadata = generateMetadata({}, ['patient', 'search_doctors'], 'GET');
      const searchMetadataHeader = await prepareMetadata(searchMetadata, window.__SIGN_PRIV__); // Sign available

      const r = await fetch(`/api/doctors/search/?q=${encodeURIComponent(q)}`, {
        headers: { "X-Metadata": searchMetadataHeader } // Attach as header
      })
      if (!r.ok) throw new Error(await r.text())
      const { doctors } = await r.json()
      setSearchedDoctors(doctors)
    } catch (err) {
      console.error('Search doctors failed:', err)
      setError(err.message)
    }
  }

  /**
 * FUNCTION: appointDoctor
 *
 * PURPOSE:
 *      Grants a doctor access to decrypt the record by sharing the DEK encrypted under
 *      the patient-doctor ECDH shared secret.
 *
 * FLOW:
 *  1) Fetch doctor encryption public key from server.
 *  2) Derive shared secret = X25519(patient_priv, doctor_pub).
 *  3) Ensure a DEK exists (if not, updateRecord() to create one).
 *  4) Wrap DEK using encryptAES(DEK, shared_secret).
 *  5) Send encrypted_dek to backend appointment endpoint.
 *
 * SECURITY NOTES:
 *  - This implements the “capability” model: doctor can decrypt only if they can derive the shared_secret.
 *  - No plaintext DEK is ever sent.
 */

  const appointDoctor = async (doctorId: string) => {
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true)
      return
    }

    try {
      // Generate metadata for doctor public key fetch (patient-specific, no tree depth)
      const docPubMetadata = generateMetadata({}, ['patient', 'get_doctor_public_key'], 'GET');
      const docPubMetadataHeader = await prepareMetadata(docPubMetadata, window.__SIGN_PRIV__); // Sign available

      const docPubRes = await fetch(`/api/user/public_key/${doctorId}`, {
        headers: { "X-Metadata": docPubMetadataHeader } // Attach as header
      })
      if (docPubRes.status === 404) {
        throw new Error('Doctor not found')
      }

      if (docPubRes.ok) {
        const { public_key } = await docPubRes.json()
        if (!public_key) {
          throw new Error('Doctor public key missing')
        }
        const docPubBytes = hexToBytes(public_key)
        const shared = await ecdhSharedSecret(window.__MY_PRIV__, docPubBytes)
        const sharedHash = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', shared)));
console.log(`Patient-side shared hash for doctor ${doctorId}: ${sharedHash}`); 
        let dek = window.__CURRENT_DEK__;
        if (!dek) {
          await updateRecord();  
          dek = window.__CURRENT_DEK__;
        }
        
        const encryptedDek = await encryptAES(dek, shared)
        const encryptedDekStr = bytesToBase64(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))

        // Generate metadata for appoint doctor (patient-specific, no tree depth)
        const appointPayload = { encrypted_dek: encryptedDekStr };
        const appointMetadata = generateMetadata(appointPayload, ['patient', 'appoint_doctor'], 'POST');
        const appointMetadataHeader = await prepareMetadata(appointMetadata, window.__SIGN_PRIV__); // Sign available

        const res = await fetch(`/api/appoint/${doctorId}/`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json', 
            'X-CSRFToken': getCookie('csrftoken') || '',
            "X-Metadata": appointMetadataHeader // Attach as header
          },
          credentials: 'include',
          body: JSON.stringify(appointPayload)
        })
        if (!res.ok) throw new Error('Appoint failed: ' + await res.text())
        fetchAppointedDoctors()
        setAddDoctorDialogOpen(false)
      }
    } catch (err) {
      console.error('Appoint doctor failed:', err)
      setError(err.message)
    }
  }

  const findNode = (root: RecordNode, path: string[]): RecordNode | null => {
    let current = root
    for (const p of path) {
      if (!current.children || !Array.isArray(current.children)) return null
      const child = current.children.find((c) => c.name === p)
      if (!child) return null
      current = child
    }
    return current
  }

  const cloneRecord = () => JSON.parse(JSON.stringify(record)) as RecordNode

  
  /**
 * FUNCTION: handleAdd
 *
 * PURPOSE:
 *      Adds a new folder or file node into the local record tree (client-side only).
 *      Marks state as dirty; encryption/upload happens only when user clicks Save Record.
 *
 * NOTES:
 *  - For text files, content is stored base64-encoded in the tree.
 *  - For binary files, raw base64 is stored along with mime type and size metadata.
 */

  const handleAdd = async (type: 'folder' | 'text' | 'binary', name: string, content?: string, mime?: string) => {
    if (!record || !name) return
    const newRecord = cloneRecord()
    const parent = findNode(newRecord, selectedPath) || newRecord
    if (parent.type !== 'folder' || !parent.children) return
    if (selectedPath.length >= 5 && type === 'folder') return alert('Max tree depth 5 reached')
    let size = 0
    if (type === 'text' && content) {
      const contentBytes = new TextEncoder().encode(content)
      content = bytesToBase64(contentBytes)
      size = contentBytes.length
    } else if (type === 'binary' && content) {
      size = base64ToBytes(content).length
    }
    const newNode: RecordNode = {
      name,
      type: type === 'folder' ? 'folder' : 'file',
      children: type === 'folder' ? [] : undefined,
      content,
      mime,
      metadata: { created: new Date().toISOString(), size },
      addedBy: 'self',
    }
    parent.children.push(newNode)
    setRecord(newRecord)
    setIsDirty(true)
    setAddRecordOpen(false)
    setAddName('')
    setAddType(null)
    setAddContent('')
    setAddFile(null)
  }

  const handleDelete = (path: string[]) => {
    if (!record || !confirm('Delete this item?')) return
    const newRecord = cloneRecord()
    const parentPath = path.slice(0, -1)
    const parent = findNode(newRecord, parentPath) || newRecord
    if (parent.type !== 'folder' || !parent.children) return
    const lastName = path[path.length - 1]
    const index = parent.children.findIndex((c) => c.name === lastName)
    if (index > -1) parent.children.splice(index, 1)
    setRecord(newRecord)
    setIsDirty(true)
    setSelectedPath([])
  }

  const handleEditContent = (newContent: string) => {
    if (!record) return
    const newRecord = cloneRecord()
    const node = findNode(newRecord, selectedPath)
    if (!node || node.type !== 'file') return
    const contentBytes = new TextEncoder().encode(newContent)
    node.content = bytesToBase64(contentBytes)
    node.metadata.size = contentBytes.length
    setRecord(newRecord)
    setIsDirty(true)
  }

  const handleReplaceFile = async (file: File) => {
    if (!record) return
    const base64 = await readFileAsBase64(file)
    const newRecord = cloneRecord()
    const node = findNode(newRecord, selectedPath)
    if (!node || node.type !== 'file') return
    node.content = base64
    node.mime = file.type
    node.metadata.size = file.size
    setRecord(newRecord)
    setIsDirty(true)
  }

  const readFileAsBase64 = (file: File): Promise<string> =>
    new Promise((resolve) => {
      const reader = new FileReader()
      reader.onload = () => resolve((reader.result as string).split(',')[1])
      reader.readAsDataURL(file)
    })

  const toggleFolder = (pathKey: string) => {
    const newOpen = new Set(openFolders)
    if (openFolders.has(pathKey)) newOpen.delete(pathKey)
    else newOpen.add(pathKey)
    setOpenFolders(newOpen)
  }

  const RenderTree = ({ node, path, level }: { node: RecordNode; path: string[]; level: number }) => {
    const isFolder = node.type === 'folder'
    const pathKey = path.join('/')
    const isOpen = openFolders.has(pathKey)
    const isSelected = JSON.stringify(path) === JSON.stringify(selectedPath)
    const isRoot = path.length === 0
    const indentClass = level > 0 ? `ml-${level * 4}` : ''
    return (
      <div className={indentClass}>
        <div
        className={`flex items-center cursor-pointer py-1 px-2 rounded ${isSelected ? 'bg-blue-100' : 'hover:bg-gray-100'} ${node.addedBy && node.addedBy !== 'self' ? 'text-gray-500' : ''}`}
          onClick={() => {
            setSelectedPath(path)
            if (isFolder) toggleFolder(pathKey)
          }}
        >
          {isFolder && (isOpen ? <ChevronDown className="w-4 h-4 mr-1" /> : <ChevronRight className="w-4 h-4 mr-1" />)}
          {isFolder ? <Folder className="w-4 h-4 mr-2" /> : <FileText className="w-4 h-4 mr-2" />}
          {node.name}
          <div className="ml-auto">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm">
                  <MoreVertical className="w-4 h-4" />
                </Button>
              </DropdownMenuTrigger>
              {user?.type === 'patient' ? (
                <DropdownMenuContent className="w-56">
                  {node.addedBy && node.addedBy !== 'self' && (
                    <>
                      <DropdownMenuLabel className="font-bold">
                        Dr. {doctorEmails[node.addedBy] || 'Unknown'}
                      </DropdownMenuLabel>
                      <DropdownMenuSeparator />
                    </>
                  )}
                  {isFolder && (
                    <>
                      <DropdownMenuSub>
                        <DropdownMenuSubTrigger>
                          <Plus className="mr-2 h-4 w-4" /> Add
                        </DropdownMenuSubTrigger>
                        <DropdownMenuPortal>
                          <DropdownMenuSubContent>
                            <DropdownMenuItem onClick={() => { setAddType('folder'); setAddRecordOpen(true) }}>
                              <Folder className="mr-2 h-4 w-4" /> Folder
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setAddType('text'); setAddRecordOpen(true) }}>
                              <FileText className="mr-2 h-4 w-4" /> Text File
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setAddType('binary'); setAddRecordOpen(true) }}>
                              <Upload className="mr-2 h-4 w-4" /> File
                            </DropdownMenuItem>
                          </DropdownMenuSubContent>
                        </DropdownMenuPortal>
                      </DropdownMenuSub>
                      <DropdownMenuSeparator />
                    </>
                  )}
                  {!isRoot && (
                    <DropdownMenuItem onClick={() => handleDelete(path)}>
                      <Trash className="mr-2 h-4 w-4" /> Delete
                    </DropdownMenuItem>
                  )}
                  {node.addedBy && node.addedBy !== 'self' && !isRoot && (
                    <>
                      <DropdownMenuSeparator />
                    </>
                  )}
                </DropdownMenuContent>
              ) : (
                <DropdownMenuContent className="w-56">
                  {isFolder && (
                    <>
                      <DropdownMenuSub>
                        <DropdownMenuSubTrigger>
                          <Plus className="mr-2 h-4 w-4" /> Request Add
                        </DropdownMenuSubTrigger>
                        <DropdownMenuPortal>
                          <DropdownMenuSubContent>
                            <DropdownMenuItem onClick={() => { setRequestType('add_folder'); setRequestDialogOpen(true) }}>
                              <Folder className="mr-2 h-4 w-4" /> Folder
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setRequestType('add_text'); setRequestDialogOpen(true) }}>
                              <FileText className="mr-2 h-4 w-4" /> Text File
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setRequestType('add_binary'); setRequestDialogOpen(true) }}>
                              <Upload className="mr-2 h-4 w-4" /> File
                            </DropdownMenuItem>
                          </DropdownMenuSubContent>
                        </DropdownMenuPortal>
                      </DropdownMenuSub>
                    </>
                  )}
                  {node.type === 'file' && (
                    <>
                      {!isFolder && <DropdownMenuSeparator />}
                      <DropdownMenuItem onClick={() => { setRequestType(node.mime?.startsWith('text/') ? 'edit_text' : 'edit_binary'); setRequestDialogOpen(true) }}>
                        <Edit className="mr-2 h-4 w-4" /> Request {node.mime?.startsWith('text/') ? 'Edit' : 'Replace'}
                      </DropdownMenuItem>
                    </>
                  )}

                  {!isRoot && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => { setRequestType('delete'); setRequestDialogOpen(true) }}>
                        <Trash className="mr-2 h-4 w-4" /> Request Delete
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              )}
            </DropdownMenu>
          </div>
        </div>
        {isFolder && isOpen && node.children?.filter(child => child && child.name && typeof child.name === 'string').map((child, i) => (
          <RenderTree key={i} node={child} path={[...path, child.name]} level={level + 1} />
        ))}
      </div>
    )
  }


const handleRequest = async () => {
  if (!patientId || !requestType) {
    setError("Selection missing");
    return
  }
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
    return
  }

  if ((requestType.startsWith('add') || requestType.startsWith('edit')) && !requestName?.trim()) {
    if (requestType.includes('binary') && requestFile && requestFile.name) {
      setRequestName(requestFile.name);
      } else {
        setError("Name is required");
        return;
  }
  }
  try {
    let details: any = {};
    let treeDepth = requestType.startsWith('add') ? selectedPath.length + 1 : selectedPath.length;
    if (requestType.startsWith("add")) {
      details.path = selectedPath.join('/');
      details.name = requestName;
    } else {
      details.path = selectedPath.join('/');
    }

    let encryptedDataLength = 0;
    if (requestType.includes("text") || requestType.includes("binary")) {
      const dek = randomBytes(32);
      let rawContent: Uint8Array;
      let mime: string;
      if (requestType.includes("binary")) {
        if (!requestFile) return setError("File required");
        const base64 = await readFileAsBase64(requestFile);
        rawContent = base64ToBytes(base64);
        mime = requestFile.type;
      } else {
        rawContent = new TextEncoder().encode(requestContent);
        mime = "text/plain";
      }
      const encrypted = await encryptAES(rawContent, dek);
      const concatenated = new Uint8Array([
        ...encrypted.iv,
        ...encrypted.ciphertext,
        ...encrypted.tag,
      ]);
      details.encrypted_data = bytesToBase64(concatenated);
      encryptedDataLength = concatenated.length;
      details.mime = mime;
      // Encrypt DEK with patient's pub
      const shared = await ecdhSharedSecret(
        window.__MY_PRIV__,
        patientPub!
      );
      const encryptedDek = await encryptAES(dek, shared);
      details.encrypted_dek = bytesToBase64(
        new Uint8Array([
          ...encryptedDek.iv,
          ...encryptedDek.ciphertext,
          ...encryptedDek.tag,
        ])
      );
    }

    const timestamp = new Date().toISOString();
    const metadata = {
      time: timestamp,
      size: encryptedDataLength,
      privileges: 'doctor',
      tree_depth: treeDepth,
    };

    const requestMsg = new TextEncoder().encode(
      JSON.stringify({
        type: requestType,
        patient_id: patientId,
        details,
        timestamp: timestamp,
      }),
    );

    const certPrivKey = await crypto.subtle.importKey(
      "pkcs8",
      window.__MY_CERT_PRIV__,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      certPrivKey,
      requestMsg
    );
    const signatureB64 = bytesToBase64(new Uint8Array(signature));

    const body = {
      signature: signatureB64,
      cert: certChain.doctor,
      type: requestType,
      patient: patientId,
      timestamp: timestamp,
      details,
      metadata,
    };

    // Generate metadata for pending create (doctor-specific, tree depth from selection)
    const pendingPayload = body;
    const pendingMetadata = generateMetadata(pendingPayload, ['doctor', 'create_pending'], 'POST', treeDepth);
    const pendingMetadataHeader = await prepareMetadata(pendingMetadata, window.__SIGN_PRIV__); // Sign available

    const res = await fetch("/api/pending/create/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken") || "",
        "X-Metadata": pendingMetadataHeader // Attach as header
      },
      credentials: "include",
      body: JSON.stringify(pendingPayload),
    });
    if (!res.ok) throw new Error(await res.text());
    alert("File request sent. Awaiting patient approval.");
    setRequestDialogOpen(false);
    setRequestType(null);
    setRequestName("");
    setRequestContent("");
    setRequestFile(null);
  } catch (err) {
    console.error("File request failed:", err);
    setError((err as Error).message);
  }
}
  if (error) {
    return <div>Error: {error}</div>
  }

  if (!user) return <div>Loading...</div>

  const isPatient = user.type === 'patient'
  const header = isPatient ? `Medical Record ${patientInfo?.name || ''}` : patientId ? `Patient Record: ${patientInfo?.name || ''} (DOB: ${patientInfo?.dob || ''})` : 'My Appointed Patients'
  const selectedNode = record ? findNode(record, selectedPath) : null

  return (
    <div className="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">{header}</h1>
        {patientId && <Button asChild variant="outline"><Link to="/record">Back to Patient List</Link></Button>}
      </div>

      {user.type === 'doctor' && !patientId ? (
        <Card>
          <CardHeader>
            <CardTitle>Appointed Patients</CardTitle>
          </CardHeader>
          <CardContent>
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
                    <TableCell>
                      <Button asChild variant="outline">
                        <Link to="/record" search={{ patient: pat.id }}>View Record</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <>
          {!record ? <div>Loading record...</div> : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-12">
              <Card>
                <CardHeader>
                  <CardTitle>Record Tree</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-auto h-96 border rounded-md p-4 bg-white">
                    <RenderTree node={record} path={[]} level={0} />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>{selectedNode ? selectedNode.name : 'Select an item'}</CardTitle>
                </CardHeader>
                <CardContent>
                  {selectedNode?.type === 'file' && selectedNode.content ? (
                    <>
                      {selectedNode.mime?.startsWith('text/') ? (
                        <Textarea
                          value={atob(selectedNode.content)}
                          onChange={(e) => isPatient ? handleEditContent(e.target.value) : undefined}
                          disabled={!isPatient}
                          className="min-h-[200px]"
                        />
                      ) : selectedNode.mime?.startsWith('image/') ? (
                        <img src={`data:${selectedNode.mime};base64,${selectedNode.content}`} alt={selectedNode.name} className="max-w-full" />
                      ) : selectedNode.mime === 'application/pdf' ? (
                        <div className="flex flex-col items-center">
{numPages && (
                            <div className="flex items-center space-x-2 mt-2">
                              <Button 
                                variant="outline" 
                                size="sm" 
                                disabled={currentPage <= 1} 
                                onClick={() => setCurrentPage(prev => prev - 1)}
                              >
                                Prev
                              </Button>
                              <span>{currentPage} / {numPages}</span>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                disabled={currentPage >= numPages} 
                                onClick={() => setCurrentPage(prev => prev + 1)}
                              >
                                Next
                              </Button>
                            </div>
                          )}

                          <Document
                            file={`data:application/pdf;base64,${selectedNode.content}`}
                            onLoadSuccess={({ numPages: np }) => {
                              setNumPages(np)
                              setCurrentPage(1)
                            }}
                          >
                            <div className="mb-0 pb-0"> {/* Remove bottom margin */}
                              <Page pageNumber={currentPage} renderTextLayer={false} renderAnnotationLayer={false} className="m-0 p-0" />
                            </div>
                          </Document>
                                                  </div>
                      ) : (
                        <p>Unsupported file type</p>
                      )}
                      {isPatient && selectedNode.mime && !selectedNode.mime.startsWith('text/') && (
                        <div className="mt-4">
                          <Input type="file" onChange={(e) => e.target.files?.[0] && handleReplaceFile(e.target.files[0])} />
                        </div>
                      )}
                    </>
                  ) : selectedNode?.type === 'folder' ? (
                    <p>This is a folder. Select a file to view or edit.</p>
                  ) : (
                    <p>No item selected.</p>
                  )}
                </CardContent>
                {isPatient && <CardFooter className="flex justify-between">
                  <Button onClick={() => updateRecord()} className={isDirty ? 'bg-blue-500 animate-pulse' : ''}>Save Record</Button>
                  <Dialog open={rotateOpen} onOpenChange={setRotateOpen}>
                    <DialogTrigger asChild>
                      <Button variant="outline"><Key className="w-4 h-4 mr-2" /> Rotate Keys</Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Rotate Encryption Keys</DialogTitle>
                        <DialogDescription>
                          This will generate a new DEK and identity key, re-encrypt everything, and require updating your password manager.
                        </DialogDescription>
                      </DialogHeader>
                      <DialogFooter>
                        <Button onClick={handleRotate}>Confirm Rotate</Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </CardFooter>}
                {!isPatient && <CardFooter>
                  <Button variant="outline" onClick={handleRefresh}>Refresh Record</Button>
                </CardFooter>}
              </Card>
            </div>
          )}
        </>
      )}

      {isPatient && (
        <Card>
          <CardHeader>
            <CardTitle>Appointed Doctors</CardTitle>
          </CardHeader>
          <CardContent>
            {appointedDoctors.length === 0 ? (
              <p>No doctors appointed yet.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Email</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {appointedDoctors.map((doc) => (
                    <TableRow key={doc.id}>
                      <TableCell>{doc.email}</TableCell>
                      <TableCell>
                        <Button variant="destructive" onClick={() => removeDoctor(doc.id)}>Revoke</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
          <CardFooter className="flex justify-between">
            <Dialog open={addDoctorDialogOpen} onOpenChange={setAddDoctorDialogOpen}>
              <DialogTrigger asChild>
                <Button><Plus className="w-4 h-4 mr-2" /> Add Doctor</Button>
              </DialogTrigger>
              <DialogContent aria-describedby={undefined}>
                <DialogHeader>
                  <DialogTitle>Add Doctor</DialogTitle>
                </DialogHeader>
                <Input placeholder="Search doctors..." value={searchQuery} onChange={(e) => { setSearchQuery(e.target.value); searchDoctors(e.target.value) }} />
                <div className="mt-4">
                  {searchedDoctors.map((doc) => (
                    <div key={doc.id} className="flex justify-between items-center py-2 border-b">
                      <span>{doc.email}</span>
                      <Button onClick={() => appointDoctor(doc.id)}>Appoint</Button>
                    </div>
                  ))}
                </div>
              </DialogContent>
            </Dialog>
                      <Button variant="outline" onClick={() => navigate({ to: '/doctor' })}><Stethoscope className="mr-2 h-4 w-4" /> View Doctor Requests</Button>
          </CardFooter>
        </Card>
      )}

      {/* Add Record Dialog for Patients */}
      {isPatient && (
        <Dialog open={addRecordOpen} onOpenChange={(open) => {
          setAddRecordOpen(open)
          if (!open) {
            setAddType(null)
            setAddName('')
            setAddContent('')
            setAddFile(null)
          }
        }}>
          <DialogContent aria-describedby={undefined}>
            <DialogHeader>
              <DialogTitle>Add {addType?.charAt(0).toUpperCase() + addType?.slice(1)}</DialogTitle>
            </DialogHeader>
            <Input placeholder="Name" value={addName} onChange={(e) => setAddName(e.target.value)} />
            {addType === 'text' && (
              <Textarea placeholder="Content" value={addContent} onChange={(e) => setAddContent(e.target.value)} />
            )}
            {addType === 'binary' && (
              <Input type="file" onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) {
                  setAddName(file.name)
                  setAddFile(file)
                }
              }} />
            )}
            <DialogFooter>
              <Button onClick={async () => {
                let content: string | undefined
                let mime: string | undefined
                if (addType === 'text') {
                  mime = 'text/plain'
                  content = addContent
                } else if (addType === 'binary' && addFile) {
                  content = await readFileAsBase64(addFile)
                  mime = addFile.type
                }
                handleAdd(addType!, addName, content, mime)
              }}>Add</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* Request Dialog for Doctors */}
      <Dialog open={requestDialogOpen} onOpenChange={(open) => {
        setRequestDialogOpen(open)
        if (!open) {
          setRequestType(null)
          setRequestName('')
          setRequestContent('')
          setRequestFile(null)
        }
      }}>
        <DialogContent aria-describedby={undefined}>
  <DialogHeader>
    <DialogTitle>Request {requestType?.replace('_', ' ').replace('add', 'Add').replace('edit', 'Edit')}</DialogTitle>
  </DialogHeader>
  {requestType && (requestType.startsWith('add') || requestType.startsWith('edit')) ? (
    <>
      {requestType.startsWith('add') && <Input placeholder="Name" value={requestName} onChange={(e) => setRequestName(e.target.value)} />}
      {(requestType === 'add_text' || requestType === 'edit_text') && (
        <Textarea placeholder="Content" value={requestContent} onChange={(e) => setRequestContent(e.target.value)} />
      )}
      {(requestType === 'add_binary' || requestType === 'edit_binary') && (
        <Input type="file" onChange={(e) => {
          const file = e.target.files?.[0]
          if (file) {
            if (requestType.startsWith('add')) setRequestName(file.name)
            setRequestFile(file)
          }
        }} />
      )}
    </>
  ) : requestType === 'delete' ? (
    <p>Request to delete {selectedNode?.name}?</p>
  ) : null}
  <DialogFooter>
    <Button onClick={handleRequest}>Submit Request</Button>
  </DialogFooter>
</DialogContent>
      </Dialog>

      {/* Input Priv Dialog */}
      <Dialog open={inputPrivOpen} onOpenChange={setInputPrivOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enter Private Key</DialogTitle>
            <DialogDescription>
              Paste the base64-encoded X25519 private key from your password manager. This is required for E2EE on this device.
            </DialogDescription>
          </DialogHeader>
          <Input type="password" value={inputPriv} onChange={(e) => setInputPriv(e.target.value)} placeholder="Base64 private key..." />
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

      <div className="mt-8 p-4 bg-amber-50 rounded-lg flex items-start space-x-4">
        <Shield className="w-6 h-6 text-amber-600" />
        <p className="text-amber-700">Data encrypted end-to-end. Signature verified.</p>
      </div>
    </div>
  )
}
