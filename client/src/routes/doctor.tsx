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
  details: any;
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

export const Route = createFileRoute("/doctor")({
  beforeLoad: async () => {
    try {
      const response = await fetch("/api/webauthn/auth/status/", {
        method: "GET",
        credentials: "include",
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
  const [pendingRequests, setPendingRequests] = useState<PendingRequest[]>([]); // Doctor's own requests
  const [pendingAppointments, setPendingAppointments] = useState<
    PendingAppointment[]
  >([]); // Patient's incoming requests
  const [searchQuery, setSearchQuery] = useState("");
  const [addPatientDialogOpen, setAddPatientDialogOpen] = useState(false);
  const [fileRequestDialogOpen, setFileRequestDialogOpen] = useState(false);
  const [selectedPatientId, setSelectedPatientId] = useState<string | null>(
    null,
  );
  const [requestType, setRequestType] = useState<
    | "add_folder"
    | "add_text"
    | "add_binary"
    | "edit_text"
    | "edit_binary"
    | "delete"
    | null
  >(null);
  const [requestName, setRequestName] = useState("");
  const [requestContent, setRequestContent] = useState("");
  const [requestFile, setRequestFile] = useState<File | null>(null);
  const [requestPath, setRequestPath] = useState("");
  const [certChain, setCertChain] = useState<CertChain | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [inputPrivOpen, setInputPrivOpen] = useState(false);
  const [inputPriv, setInputPriv] = useState("");

  const deriveMasterKEK = async (priv: Uint8Array): Promise<Uint8Array> => {
    const digest = await crypto.subtle.digest("SHA-256", priv);
    return new Uint8Array(digest);
  };

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

  useEffect(() => {
    const stored = sessionStorage.getItem("x25519_priv_b64");
    if (stored) {
      window.__MY_PRIV__ = base64ToBytes(stored);
    }
    fetchUser();
  }, []);

  useEffect(() => {
    if (!user) return;
    if (user.type === "doctor") {
      fetchAppointedPatients();
      fetchPendingRequests();
      fetchCertChain();
    } else if (user.type === "patient") {
      fetchPendingAppointments();
    }
    setLoading(false);
  }, [user]);

  const fetchUser = async () => {
    try {
      const r = await fetch("/api/user/me/");
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

      if (window.__KEK__) {
        const encryptedPriv = await encryptAES(newPriv, window.__KEK__);
        const encryptedPrivStr = bytesToBase64(
          new Uint8Array([
            ...encryptedPriv.iv,
            ...encryptedPriv.ciphertext,
            ...encryptedPriv.tag,
          ]),
        );
        const r = await fetch("/api/user/keys/update/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken") || "",
          },
          credentials: "include",
          body: JSON.stringify({ encrypted_priv: encryptedPrivStr }),
        });
        if (!r.ok) console.error("Failed to update encrypted priv");
      }

      setInputPrivOpen(false);
      setInputPriv("");
    } catch (err) {
      setError("Invalid private key");
    }
  };

  const fetchAppointedPatients = async () => {
    try {
      const r = await fetch("/api/appoint/patients/");
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
      const r = await fetch("/api/pending/my_requests/");
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
      const r = await fetch("/api/ca/my_chain/");
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
      const r = await fetch(`/api/patients/search/?q=${encodeURIComponent(q)}`);
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
    if (!certChain) {
      setError("PKI chain missing");
      return;
    }

    try {
      const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
      const requestMsg = new TextEncoder().encode(
        JSON.stringify({
          type: "appointment_request",
          patient_id: patientId,
          timestamp: new Date().toISOString(),
        }),
      );
      const signature = bytesToBase64(signEd25519(requestMsg, edPriv));

      const body = {
        signature,
        cert_chain: certChain,
        patient_id: patientId,
      };

      const res = await fetch("/api/appoint/request/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken") || "",
        },
        credentials: "include",
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      alert("Appointment request sent. Awaiting patient approval.");
      fetchPendingRequests();
      setAddPatientDialogOpen(false);
    } catch (err) {
      console.error("Appointment request failed:", err);
      setError(err.message);
    }
  };

  const requestFileChange = async () => {
    if (!selectedPatientId || !requestType) {
      setError("Selection missing");
      return;
    }
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true);
      return;
    }
    if (!certChain) {
      setError("PKI chain missing");
      return;
    }

    try {
      let details: any = { path: requestPath };
      if (requestType.startsWith("add") || requestType.startsWith("edit")) {
        details.name = requestName;
        if (requestType.includes("text") || requestType.includes("binary")) {
          const dek = randomBytes(32);
          let rawContent: string;
          if (requestType.includes("binary")) {
            if (!requestFile) return setError("File required");
            rawContent = await readFileAsBase64(requestFile);
            details.mime = requestFile.type;
          } else {
            rawContent = requestContent;
            details.mime = "text/plain";
          }
          const raw = new TextEncoder().encode(rawContent);
          const encrypted = await encryptAES(raw, dek);
          const concatenated = new Uint8Array([
            ...encrypted.iv,
            ...encrypted.ciphertext,
            ...encrypted.tag,
          ]);
          details.encrypted_data = bytesToBase64(concatenated);
          // Encrypt DEK with patient's pub (fetch if needed)
          const patPubRes = await fetch(
            `/api/user/public_key/${selectedPatientId}`,
          );
          if (!patPubRes.ok) throw new Error("Patient pub fetch failed");
          const { public_key } = await patPubRes.json();
          const patPubBytes = hexToBytes(public_key);
          const shared = await ecdhSharedSecret(
            window.__MY_PRIV__,
            patPubBytes,
          );
          const encryptedDek = await encryptAES(dek, shared);
          details.encrypted_dek = bytesToBase64(
            new Uint8Array([
              ...encryptedDek.iv,
              ...encryptedDek.ciphertext,
              ...encryptedDek.tag,
            ]),
          );
        }
      }

      const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
      const requestMsg = new TextEncoder().encode(
        JSON.stringify({
          type: requestType,
          patient_id: selectedPatientId,
          details,
          timestamp: new Date().toISOString(),
        }),
      );
      const signature = bytesToBase64(signEd25519(requestMsg, edPriv));

      const body = {
        signature,
        cert_chain: certChain,
        type: requestType,
        patient: selectedPatientId,
        details,
      };

      const res = await fetch("/api/pending/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken") || "",
        },
        credentials: "include",
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      alert("File request sent. Awaiting patient approval.");
      fetchPendingRequests();
      setFileRequestDialogOpen(false);
      setRequestType(null);
      setRequestName("");
      setRequestContent("");
      setRequestFile(null);
      setRequestPath("");
    } catch (err) {
      console.error("File request failed:", err);
      setError(err.message);
    }
  };

  const readFileAsBase64 = (file: File): Promise<string> =>
    new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve((reader.result as string).split(",")[1]);
      reader.readAsDataURL(file);
    });

  const viewPatientRecord = (patientId: string) => {
    navigate({ to: "/record", search: { patient: patientId } });
  };

  // New: Patient functions
  const fetchPendingAppointments = async () => {
    try {
      const r = await fetch("/api/pending/appointments/");
      if (!r.ok) throw new Error(await r.text());
      const { requests } = await r.json();
      setPendingAppointments(requests);
    } catch (err) {
      console.error("Pending appointments fetch failed:", err);
      setError(err.message);
    }
  };

  const approveAppointment = async (req: PendingAppointment) => {
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true);
      return;
    }
    try {
      // Load current DEK from patient's record
      const recordRes = await fetch("/api/record/my/");
      if (!recordRes.ok) throw new Error("Failed to fetch record");
      const recordData = await recordRes.json();
      const encDekSelf = recordData.encrypted_deks["self"];
      if (!encDekSelf) throw new Error("No self DEK found");
      const masterKEK = await deriveMasterKEK(window.__MY_PRIV__);
      const dek = await decryptDEK(encDekSelf, masterKEK);

      // Fetch doctor's public key
      const pubRes = await fetch(`/api/user/public_key/${req.requester.id}`);
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

      // Send to backend for approval
      const approveRes = await fetch(`/api/pending/${req.id}/approve/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken") || "",
        },
        credentials: "include",
        body: JSON.stringify({ encrypted_dek: encDekStr }),
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
      const res = await fetch(`/api/pending/${reqId}/deny/`, {
        method: "POST",
        headers: { "X-CSRFToken": getCookie("csrftoken") || "" },
        credentials: "include",
      });
      if (!res.ok) throw new Error(await res.text());
      alert("Request denied.");
      fetchPendingAppointments();
    } catch (err) {
      setError((err as Error).message);
    }
  };

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
                          <Button
                            variant="secondary"
                            onClick={() => {
                              setSelectedPatientId(pat.id);
                              setFileRequestDialogOpen(true);
                            }}
                          >
                            Request File Change
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
                      <TableHead>Details</TableHead>
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
                          {req.details.patient_name || "N/A"}
                        </TableCell>
                        <TableCell
                          className={
                            req.status === "pending"
                              ? "text-yellow-600"
                              : req.status === "approved"
                                ? "text-green-600"
                                : "text-red-600"
                          }
                        >
                          {req.status.toUpperCase()}
                        </TableCell>
                        <TableCell>
                          {JSON.stringify(req.details, null, 2).slice(0, 50)}...
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
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

          {/* File Request Dialog */}
          <Dialog
            open={fileRequestDialogOpen}
            onOpenChange={setFileRequestDialogOpen}
          >
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Request File Change for Patient</DialogTitle>
              </DialogHeader>
              <select
                value={requestType || ""}
                onChange={(e) => setRequestType(e.target.value as any)}
                className="mb-2 p-2 border rounded"
              >
                <option value="">Select Action</option>
                <option value="add_folder">Add Folder</option>
                <option value="add_text">Add Text File</option>
                <option value="add_binary">Add Binary File</option>
                <option value="edit_text">Edit Text File</option>
                <option value="edit_binary">Replace Binary File</option>
                <option value="delete">Delete Item</option>
              </select>
              <Input
                placeholder="Path (e.g., folder/subfolder)"
                value={requestPath}
                onChange={(e) => setRequestPath(e.target.value)}
                className="mb-2"
              />
              {requestType &&
                requestType !== "delete" &&
                requestType !== "add_folder" && (
                  <Input
                    placeholder="File Name"
                    value={requestName}
                    onChange={(e) => setRequestName(e.target.value)}
                    className="mb-2"
                  />
                )}
              {requestType &&
                (requestType === "add_text" || requestType === "edit_text") && (
                  <Textarea
                    placeholder="Content"
                    value={requestContent}
                    onChange={(e) => setRequestContent(e.target.value)}
                    className="mb-2"
                  />
                )}
              {requestType &&
                (requestType === "add_binary" ||
                  requestType === "edit_binary") && (
                  <Input
                    type="file"
                    onChange={(e) =>
                      setRequestFile(e.target.files?.[0] || null)
                    }
                    className="mb-2"
                  />
                )}
              <DialogFooter>
                <Button onClick={requestFileChange}>Send Signed Request</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      ) : (
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
    </div>
  );
}
