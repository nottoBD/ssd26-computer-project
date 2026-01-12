import { useState, useEffect } from 'react'
import { createFileRoute, Link, useNavigate, redirect } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from '@/components/ui/dialog'
import { Plus, User, Calendar, Stethoscope, Search, Key, ShieldCheck, Edit, Trash, Upload, Folder } from 'lucide-react'
import { useAuth } from './__root'
import { bytesToBase64, signEd25519, deriveEd25519FromX25519, encryptAES, randomBytes } from '../components/CryptoUtils'

function getCookie(name: string): string | undefined {
  const matches = document.cookie.match(new RegExp(
    "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
  ));
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

export const Route = createFileRoute('/doctor')({
  beforeLoad: async () => {
    try {
      const response = await fetch('/api/webauthn/auth/status/', {
        method: 'GET',
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error('Not authenticated');
      }
      const data = await response.json();
      if (!data.authenticated) {
        throw new Error('Not authenticated');
      }
      // Additional check for doctor
      const userRes = await fetch('/api/user/me/');
      if (!userRes.ok) throw new Error('User fetch failed');
      const user = await userRes.json();
      if (user.type !== 'doctor') {
        throw new Error('Access denied: Doctors only');
      }
    } catch (err) {
      throw redirect({ to: '/login' });
    }
  },
  component: DoctorPortal,
});

function DoctorPortal() {
  const { isAuthenticated } = useAuth()
  const navigate = useNavigate()

  const [appointedPatients, setAppointedPatients] = useState<Patient[]>([])
  const [searchedPatients, setSearchedPatients] = useState<SearchedPatient[]>([])
  const [pendingRequests, setPendingRequests] = useState<PendingRequest[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [addPatientDialogOpen, setAddPatientDialogOpen] = useState(false)
  const [fileRequestDialogOpen, setFileRequestDialogOpen] = useState(false)
  const [selectedPatientId, setSelectedPatientId] = useState<string | null>(null)
  const [requestType, setRequestType] = useState<'add_folder' | 'add_text' | 'add_binary' | 'edit_text' | 'edit_binary' | 'delete' | null>(null)
  const [requestName, setRequestName] = useState('')
  const [requestContent, setRequestContent] = useState('')
  const [requestFile, setRequestFile] = useState<File | null>(null)
  const [requestPath, setRequestPath] = useState('')
  const [certChain, setCertChain] = useState<CertChain | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const stored = sessionStorage.getItem('x25519_priv_b64')
    if (stored) {
      window.__MY_PRIV__ = base64ToBytes(stored)
    }
    fetchAppointedPatients()
    fetchPendingRequests()
    fetchCertChain()
  }, [])

  const fetchAppointedPatients = async () => {
    try {
      setLoading(true)
      const r = await fetch('/api/appoint/patients/')
      if (!r.ok) throw new Error(await r.text())
      const { patients } = await r.json()
      setAppointedPatients(patients)
    } catch (err) {
      console.error('Patients fetch failed:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const fetchPendingRequests = async () => {
    try {
      const r = await fetch('/api/pending/my_requests/')
      if (!r.ok) throw new Error(await r.text())
      const { requests } = await r.json()
      setPendingRequests(requests)
    } catch (err) {
      console.error('Pending requests fetch failed:', err)
      setError(err.message)
    }
  }

  const fetchCertChain = async () => {
    try {
      const r = await fetch('/api/ca/my_chain/')
      if (!r.ok) throw new Error(await r.text())
      const data = await r.json()
      setCertChain({
        root: data.root_pem,
        intermediate: data.intermediate_pem,
        doctor: data.doctor_pem,
      })
    } catch (err) {
      console.error('Cert chain fetch failed:', err)
      setError('Failed to load PKI chain. Signing disabled.')
    }
  }

  const searchPatients = async (q: string) => {
    if (!q) {
      setSearchedPatients([])
      return
    }
    try {
      const r = await fetch(`/api/patients/search/?q=${encodeURIComponent(q)}`)
      if (!r.ok) throw new Error(await r.text())
      const { patients } = await r.json()
      setSearchedPatients(patients)
    } catch (err) {
      console.error('Search patients failed:', err)
      setError(err.message)
    }
  }

  const requestAppointment = async (patientId: string) => {
    if (!window.__MY_PRIV__ || !certChain) {
      setError('Private key or PKI chain missing')
      return
    }

    try {
      const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey
      const requestMsg = new TextEncoder().encode(JSON.stringify({
        type: 'appointment_request',
        patient_id: patientId,
        timestamp: new Date().toISOString(),
      }))
      const signature = bytesToBase64(signEd25519(requestMsg, edPriv))

      const body = {
        signature,
        cert_chain: certChain,
        patient_id: patientId,
      }

      const res = await fetch('/api/appoint/request/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
        credentials: 'include',
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(await res.text())
      alert('Appointment request sent. Awaiting patient approval.')
      fetchPendingRequests()
      setAddPatientDialogOpen(false)
    } catch (err) {
      console.error('Appointment request failed:', err)
      setError(err.message)
    }
  }

  const requestFileChange = async () => {
    if (!selectedPatientId || !requestType || !window.__MY_PRIV__ || !certChain) {
      setError('Selection or keys missing')
      return
    }

    try {
      let details: any = { path: requestPath }
      if (requestType.startsWith('add') || requestType.startsWith('edit')) {
        details.name = requestName
        if (requestType.includes('text') || requestType.includes('binary')) {
          const dek = randomBytes(32)
          let rawContent: string
          if (requestType.includes('binary')) {
            if (!requestFile) return setError('File required')
            rawContent = await readFileAsBase64(requestFile)
            details.mime = requestFile.type
          } else {
            rawContent = requestContent
            details.mime = 'text/plain'
          }
          const raw = new TextEncoder().encode(rawContent)
          const encrypted = await encryptAES(raw, dek)
          const concatenated = new Uint8Array([...encrypted.iv, ...encrypted.ciphertext, ...encrypted.tag])
          details.encrypted_data = bytesToBase64(concatenated)
          // Encrypt DEK with patient's pub (fetch if needed)
          const patPubRes = await fetch(`/api/user/${selectedPatientId}/public_key/`)
          if (!patPubRes.ok) throw new Error('Patient pub fetch failed')
          const { public_key } = await patPubRes.json()
          const patPubBytes = hexToBytes(public_key)
          const shared = await ecdhSharedSecret(window.__MY_PRIV__, patPubBytes)
          const encryptedDek = await encryptAES(dek, shared)
          details.encrypted_dek = bytesToBase64(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))
        }
      }

      const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey
      const requestMsg = new TextEncoder().encode(JSON.stringify({
        type: requestType,
        patient_id: selectedPatientId,
        details,
        timestamp: new Date().toISOString(),
      }))
      const signature = bytesToBase64(signEd25519(requestMsg, edPriv))

      const body = {
        signature,
        cert_chain: certChain,
        type: requestType,
        patient: selectedPatientId,
        details,
      }

      const res = await fetch('/api/pending/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
        credentials: 'include',
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(await res.text())
      alert('File request sent. Awaiting patient approval.')
      fetchPendingRequests()
      setFileRequestDialogOpen(false)
      setRequestType(null)
      setRequestName('')
      setRequestContent('')
      setRequestFile(null)
      setRequestPath('')
    } catch (err) {
      console.error('File request failed:', err)
      setError(err.message)
    }
  }

  const readFileAsBase64 = (file: File): Promise<string> => new Promise((resolve) => {
    const reader = new FileReader()
    reader.onload = () => resolve((reader.result as string).split(',')[1])
    reader.readAsDataURL(file)
  })

  const viewPatientRecord = (patientId: string) => {
    navigate({ to: '/record', search: { patient: patientId } })
  }

  if (error) return <div>Error: {error}</div>

  if (loading) return <div>Loading...</div>

  return (
    <div className="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold flex items-center">
          <Stethoscope className="w-8 h-8 mr-2 text-blue-600" />
          Doctor Portal
        </h1>
      </div>

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
                      <Button variant="outline" onClick={() => viewPatientRecord(pat.id)}>
                        View Record
                      </Button>
                      <Button variant="secondary" onClick={() => {
                        setSelectedPatientId(pat.id)
                        setFileRequestDialogOpen(true)
                      }}>
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
          <Dialog open={addPatientDialogOpen} onOpenChange={setAddPatientDialogOpen}>
            <DialogTrigger asChild>
              <Button><Plus className="w-4 h-4 mr-2" /> Request New Patient</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Search and Request Appointment</DialogTitle>
              </DialogHeader>
              <Input
                placeholder="Search by name, DOB..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); searchPatients(e.target.value) }}
                className="mb-4"
              />
              <div className="max-h-48 overflow-y-auto">
                {searchedPatients.map((pat) => (
                  <div key={pat.id} className="flex justify-between items-center py-2 border-b">
                    <span>{pat.name} (DOB: {pat.dob})</span>
                    <Button onClick={() => requestAppointment(pat.id)}>Request</Button>
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
                    <TableCell>{req.type.replace('file_', 'File ').replace('_', ' ').toUpperCase()}</TableCell>
                    <TableCell>{req.details.patient_name || 'N/A'}</TableCell>
                    <TableCell className={req.status === 'pending' ? 'text-yellow-600' : req.status === 'approved' ? 'text-green-600' : 'text-red-600'}>
                      {req.status.toUpperCase()}
                    </TableCell>
                    <TableCell>{JSON.stringify(req.details, null, 2).slice(0, 50)}...</TableCell>
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
            <p>CA-signed x509 chain loaded (root/intermediate/doctor). Ready for signed actions.</p>
          ) : (
            <p>Loading PKI chain...</p>
          )}
        </CardContent>
      </Card>

      {/* File Request Dialog (expanded with inputs) */}
      <Dialog open={fileRequestDialogOpen} onOpenChange={setFileRequestDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request File Change for Patient</DialogTitle>
          </DialogHeader>
          <select value={requestType || ''} onChange={(e) => setRequestType(e.target.value as any)} className="mb-2 p-2 border rounded">
            <option value="">Select Action</option>
            <option value="add_folder">Add Folder</option>
            <option value="add_text">Add Text File</option>
            <option value="add_binary">Add Binary File</option>
            <option value="edit_text">Edit Text File</option>
            <option value="edit_binary">Replace Binary File</option>
            <option value="delete">Delete Item</option>
          </select>
          <Input placeholder="Path (e.g., folder/subfolder)" value={requestPath} onChange={(e) => setRequestPath(e.target.value)} className="mb-2" />
          {(requestType && requestType !== 'delete' && requestType !== 'add_folder') && (
            <Input placeholder="File Name" value={requestName} onChange={(e) => setRequestName(e.target.value)} className="mb-2" />
          )}
          {(requestType && (requestType === 'add_text' || requestType === 'edit_text')) && (
            <Textarea placeholder="Content" value={requestContent} onChange={(e) => setRequestContent(e.target.value)} className="mb-2" />
          )}
          {(requestType && (requestType === 'add_binary' || requestType === 'edit_binary')) && (
            <Input type="file" onChange={(e) => setRequestFile(e.target.files?.[0] || null)} className="mb-2" />
          )}
          <DialogFooter>
            <Button onClick={requestFileChange}>Send Signed Request</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
