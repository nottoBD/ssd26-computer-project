import { useState, useEffect } from 'react'
import { createFileRoute, Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { redirect } from '@tanstack/react-router'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuPortal } from '@/components/ui/dropdown-menu'
import { ChevronDown, ChevronRight, Folder, FileText, MoreVertical, Plus, Upload, Edit, Trash, User, Calendar, Shield, Key } from 'lucide-react'
import { encryptAES, decryptAES, signEd25519, verifyEd25519, ecdhSharedSecret, deriveEd25519FromX25519, randomBytes, bytesToHex, hexToBytes, generateX25519Keypair } from '../components/CryptoUtils'
import { useAuth } from './__root'
import { Document, Page, pdfjs } from 'react-pdf';


interface RecordNode {
  name: string
  type: 'folder' | 'file'
  children?: RecordNode[]
  content?: string // base64 encoded
  mime?: string
  metadata: { created: string; size: number }
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
  name: string
  org: string
}

export const Route = createFileRoute('/record')({
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
    } catch (err) {
      throw redirect({ to: '/login' });
    }
  },
  component: RecordPage,
});

async function deriveMasterKEK(priv: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', priv);
  return new Uint8Array(digest);
}

function bytesToBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binString);
}

function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  return new Uint8Array(binString.length).map((_, i) => binString.charCodeAt(i));
}

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
  const [error, setError] = useState<string | null>(null)
  const [rotateOpen, setRotateOpen] = useState(false)
  const [inputPrivOpen, setInputPrivOpen] = useState(false)
  const [inputPriv, setInputPriv] = useState('')
  const [rawRecordData, setRawRecordData] = useState<{ encrypted_data: string; signature: string; encrypted_deks: Record<string, string>; encrypted_dek?: string } | null>(null)

  useEffect(() => {
    pdfjs.GlobalWorkerOptions.workerSrc = new URL(
      'pdfjs-dist/build/pdf.worker.min.mjs',
      import.meta.url
    ).toString();
  }, []);

  useEffect(() => {
    const stored = sessionStorage.getItem('x25519_priv_b64');
    if (stored) {
      window.__MY_PRIV__ = base64ToBytes(stored);
    }
  }, []);

  useEffect(() => {
    setNumPages(null);
  }, [selectedPath]);

  useEffect(() => {
    // Fetch user info
    fetch('/api/user/me/')
      .then(async (r) => {
        if (!r.ok) throw new Error(await r.text())
        return r.json()
      })
      .then((data: User) => setUser(data))
      .catch((err) => {
        console.error('User fetch failed:', err)
        setError(err.message)
      })
  }, [])

  useEffect(() => {
    if (!user) return

    if (user.type === 'patient') {
      fetchRecord('/api/record/my/', true)
      fetchAppointedDoctors()
    } else if (user.type === 'doctor') {
      if (patientId) {
        // Fetch patient pub first, then record
        fetch(`/api/user/${patientId}/public_key/`)
          .then(async (r) => {
            if (!r.ok) throw new Error(await r.text())
            const data = await r.json()
            const { public_key } = data
            if (!public_key || typeof public_key !== 'string') {
              throw new Error('Invalid or missing public key: ' + JSON.stringify(data))
            }
            const pubBytes = hexToBytes(public_key)
            setPatientPub(pubBytes)
            await fetchRecord(`/api/record/patient/${patientId}/`, false, pubBytes)
          })
          .catch((err) => {
            console.error('Patient pub fetch failed:', err)
            setError(err.message)
          })
      } else {
        fetchAppointedPatients()
      }
    }
  }, [user, patientId])

  const fetchRecord = async (url: string, isSelf: boolean, patientPubBytes?: Uint8Array) => {
    try {
      const r = await fetch(url)
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
        await processRawRecord(isSelf, encrypted_data, signature, encDek, patientPubBytes)
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

  const processRawRecord = async (isSelf: boolean, encrypted_data: string, signature: string, encDek: string, patientPubBytes?: Uint8Array) => {
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
        dek = await decryptDEK(encDek, shared)
      }

      // Verify signature
      const edPub = deriveEd25519FromX25519(isSelf ? window.__MY_PRIV__ : patientPubBytes!).publicKey
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

  const decryptDEK = async (encDekStr: string, key: Uint8Array): Promise<Uint8Array> => {
    const dekBytes = base64ToBytes(encDekStr)
    const iv = dekBytes.slice(0, 12)
    const tag = dekBytes.slice(-16)
    const ciphertext = dekBytes.slice(12, -16)
    return await decryptAES(ciphertext, key, iv, tag)
  }

  const handlePrivInput = async () => {
    try {
      const newPriv = base64ToBytes(inputPriv)
      window.__MY_PRIV__ = newPriv
      sessionStorage.setItem('x25519_priv_b64', inputPriv);

      // If has KEK (PRF), encrypt and update on server
      if (window.__KEK__) {
        const encryptedPriv = await encryptAES(newPriv, window.__KEK__)
        const encryptedPrivStr = bytesToBase64(new Uint8Array([...encryptedPriv.iv, ...encryptedPriv.ciphertext, ...encryptedPriv.tag]))
        const r = await fetch('/api/user/keys/update/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
          credentials: 'include',
          body: JSON.stringify({
            encrypted_priv: encryptedPrivStr
          })
        })
        if (!r.ok) console.error('Failed to update encrypted priv')
      }

      // Retry processing record
      if (rawRecordData && user) {
        const isSelf = user.type === 'patient'
        await processRawRecord(isSelf, rawRecordData.encrypted_data, rawRecordData.signature, isSelf ? rawRecordData.encrypted_deks['self'] : rawRecordData.encrypted_dek!, patientPub)
      }

      setInputPrivOpen(false)
      setInputPriv('')
    } catch (err) {
      setError('Invalid private key')
    }
  }

  const fetchAppointedDoctors = async () => {
    try {
      const r = await fetch('/api/appoint/doctors/')
      if (!r.ok) throw new Error(await r.text())
      const { doctors } = await r.json()
      setAppointedDoctors(doctors)
    } catch (err) {
      console.error('Doctors fetch failed:', err)
      setError(err.message)
    }
  }

  const fetchAppointedPatients = async () => {
    try {
      const r = await fetch('/api/appoint/patients/')
      if (!r.ok) throw new Error(await r.text())
      const { patients } = await r.json()
      setAppointedPatients(patients)
    } catch (err) {
      console.error('Patients fetch failed:', err)
      setError(err.message)
    }
  }

  const updateRecord = async (rotate = false) => {
    if (!record) return alert('No record to update.')

    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true)
      return
    }

    try {
      let dek = rotate ? randomBytes(32) : (window.__CURRENT_DEK__ || randomBytes(32))
      let priv = window.__MY_PRIV__
      let pubUpdate: string | undefined

      if (rotate) {
        const newKeypair = generateX25519Keypair()
        priv = newKeypair.privateKey
        pubUpdate = bytesToHex(newKeypair.publicKey)
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
        const docPubRes = await fetch(`/api/user/${doc.id}/public_key/`)
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

      const r = await fetch('/api/record/update/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
        credentials: 'include',
        body: JSON.stringify({
          encrypted_data: bytesToBase64(concatenated),
          encrypted_deks: deks,
          signature: bytesToBase64(sig),
          metadata,
        }),
      })
      if (!r.ok) throw new Error('Update error: ' + await r.text())

      if (rotate) {
        let body: any = { public_key: pubUpdate }
        if (window.__KEK__) {
          const encryptedPriv = await encryptAES(priv, window.__KEK__)
          body.encrypted_priv = bytesToBase64(new Uint8Array([...encryptedPriv.iv, ...encryptedPriv.ciphertext, ...encryptedPriv.tag]))
        }
        const kr = await fetch('/api/user/keys/update/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
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

  const handleRotate = () => {
    if (confirm('Rotate encryption keys? This will generate a new identity key and DEK.')) {
      updateRecord(true)
    }
    setRotateOpen(false)
  }

  const calculateMaxDepth = (node: RecordNode, current = 0): number => {
    if (node.type !== 'folder' || !node.children) return current
    return Math.max(...node.children.map((child) => calculateMaxDepth(child, current + 1)), current)
  }

  const removeDoctor = async (doctorId: string) => {
    try {
      const res = await fetch(`/api/appoint/remove/${doctorId}/`, { 
        method: 'DELETE',
        headers: { 'X-CSRFToken': getCookie('csrftoken') || '' },
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
      const r = await fetch(`/api/doctors/search/?q=${encodeURIComponent(q)}`)
      if (!r.ok) throw new Error(await r.text())
      const { doctors } = await r.json()
      setSearchedDoctors(doctors)
    } catch (err) {
      console.error('Search doctors failed:', err)
      setError(err.message)
    }
  }

  const appointDoctor = async (doctorId: string) => {
    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true)
      return
    }

    try {
      const docPubRes = await fetch(`/api/user/${doctorId}/public_key/`)
      let encryptedDekStr: string | null = null

      if (docPubRes.status === 404) {
        throw new Error('Doctor not found')
      }

      if (docPubRes.ok) {
        const { public_key } = await docPubRes.json()
        if (public_key) {
          const docPubBytes = hexToBytes(public_key)
          const shared = await ecdhSharedSecret(window.__MY_PRIV__, docPubBytes)
          
          let dek = window.__CURRENT_DEK__;
          if (!dek) {
            dek = randomBytes(32);
            await updateRecord();  
          }
          
          const encryptedDek = await encryptAES(dek, shared)
          encryptedDekStr = bytesToBase64(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))
        }
      }

      const res = await fetch(`/api/appoint/${doctorId}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
        credentials: 'include',
        body: JSON.stringify({ encrypted_dek: encryptedDekStr })
      })
      if (!res.ok) throw new Error('Appoint failed: ' + await res.text())
      fetchAppointedDoctors()
      setAddDoctorDialogOpen(false)
    } catch (err) {
      console.error('Appoint doctor failed:', err)
      setError(err.message)
    }
  }

  const findNode = (root: RecordNode, path: string[]): RecordNode | null => {
    let current = root
    for (const p of path) {
      if (!current.children) return null
      const child = current.children.find((c) => c.name === p)
      if (!child) return null
      current = child
    }
    return current
  }

  const cloneRecord = () => JSON.parse(JSON.stringify(record)) as RecordNode

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
    const index = parent.children.findIndex((c) => c.name === path[path.length - 1])
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
    return (
      <div className={`ml-${level * 4}`}>
        <div
          className={`flex items-center cursor-pointer py-1 px-2 rounded ${isSelected ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
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
                  <DropdownMenuItem onClick={() => handleDelete(path)}>
                    <Trash className="mr-2 h-4 w-4" /> Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              ) : (
                <DropdownMenuContent className="w-56">
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
                  {node.type === 'file' && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => { setRequestType(node.mime?.startsWith('text/') ? 'edit_text' : 'edit_binary'); setRequestDialogOpen(true) }}>
                        <Edit className="mr-2 h-4 w-4" /> Request {node.mime?.startsWith('text/') ? 'Edit' : 'Replace'}
                      </DropdownMenuItem>
                    </>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => { setRequestType('delete'); setRequestDialogOpen(true) }}>
                    <Trash className="mr-2 h-4 w-4" /> Request Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              )}
            </DropdownMenu>
          </div>
        </div>
        {isFolder && isOpen && node.children?.map((child, i) => (
          <RenderTree key={i} node={child} path={[...path, child.name]} level={level + 1} />
        ))}
      </div>
    )
  }

  const handleRequest = async () => {
    if (!patientId || !patientPub || !requestType) return

    if (!window.__MY_PRIV__) {
      setInputPrivOpen(true)
      return
    }

    let body: any = { type: requestType, patient: patientId }
    if (requestType.startsWith('add')) {
      body.path = selectedPath.join('/')
      body.name = requestName
    } else {
      body.path = selectedPath.join('/')
    }
    let metadata = { time: new Date().toISOString(), size: 0, privileges: 'doctor', tree_depth: selectedPath.length }

    if (requestType.includes('text') || requestType.includes('binary')) {
      const dek = randomBytes(32)
      let rawContent: string
      if (requestType.includes('binary')) {
        if (!requestFile) return
        rawContent = await readFileAsBase64(requestFile)
      } else {
        rawContent = requestContent
      }
      const raw = new TextEncoder().encode(rawContent)
      const encrypted = await encryptAES(raw, dek)
      const concatenated = new Uint8Array([...encrypted.iv, ...encrypted.ciphertext, ...encrypted.tag])
      const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey
      const sig = signEd25519(concatenated, edPriv)
      const shared = await ecdhSharedSecret(window.__MY_PRIV__, patientPub)
      const encryptedDek = await encryptAES(dek, shared)
      const encryptedDekStr = bytesToBase64(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))

      body.encrypted_data = bytesToBase64(concatenated)
      body.encrypted_dek = encryptedDekStr
      body.signature = bytesToBase64(sig)
      body.mime = requestType.includes('text') ? 'text/plain' : (requestFile?.type || 'application/octet-stream')
      metadata.size = concatenated.length
    }

    body.metadata = metadata

    try {
      const r = await fetch('/api/pending/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') || '' },
        credentials: 'include',
        body: JSON.stringify(body),
      })
      if (!r.ok) console.error('Request error:', await r.text())
      else alert('Request sent')
      setRequestDialogOpen(false)
      setRequestType(null)
      setRequestName('')
      setRequestContent('')
      setRequestFile(null)
    } catch (err) {
      console.error('Request failed:', err)
    }
  }

  if (error) {
    return <div>Error: {error}</div>
  }

  if (!user || !record) return <div>Loading...</div>

  const isPatient = user.type === 'patient'
  const header = isPatient ? 'My Medical Record' : patientId ? `Patient Record: ${patientInfo?.name || ''} (DOB: ${patientInfo?.dob || ''})` : 'My Appointed Patients'
  const selectedNode = findNode(record, selectedPath)

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
                    <Document
                      file={`data:application/pdf;base64,${selectedNode.content}`}
                      onLoadSuccess={({ numPages: np }) => setNumPages(np)}
                    >
                      {Array.from(new Array(numPages || 0), (_, index) => (
                        <Page key={index} pageNumber={index + 1} />
                      ))}
                    </Document>
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
          </Card>
        </div>
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
                    <TableHead>Name</TableHead>
                    <TableHead>Organization</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {appointedDoctors.map((doc) => (
                    <TableRow key={doc.id}>
                      <TableCell>{doc.name}</TableCell>
                      <TableCell>{doc.org}</TableCell>
                      <TableCell>
                        <Button variant="destructive" onClick={() => removeDoctor(doc.id)}>Remove</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
          <CardFooter>
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
                      <span>{doc.name} ({doc.org})</span>
                      <Button onClick={() => appointDoctor(doc.id)}>Appoint</Button>
                    </div>
                  ))}
                </div>
              </DialogContent>
            </Dialog>
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
              {(requestType !== 'add_folder') && <Input placeholder="Name" value={requestName} onChange={(e) => setRequestName(e.target.value)} />}
              {(requestType === 'add_text' || requestType === 'edit_text') && (
                <Textarea placeholder="Content" value={requestContent} onChange={(e) => setRequestContent(e.target.value)} />
              )}
              {(requestType === 'add_binary' || requestType === 'edit_binary') && (
                <Input type="file" onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) {
                    setRequestName(file.name)
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

      <div className="mt-8 p-4 bg-amber-50 rounded-lg flex items-start space-x-4">
        <Shield className="w-6 h-6 text-amber-600" />
        <p className="text-amber-700">Data encrypted end-to-end. Signature verified.</p>
      </div>
    </div>
  )
}
