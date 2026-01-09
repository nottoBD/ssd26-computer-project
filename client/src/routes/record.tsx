import { useState, useEffect } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { encryptAES, decryptAES, signEd25519, verifyEd25519, ecdhSharedSecret, deriveEd25519FromX25519, deriveKEK, randomBytes, bytesToHex, hexToBytes } from '../components/CryptoUtils'

export const Route = createFileRoute('/record')({
  component: RecordPage,
})

function RecordPage() {
  const [data, setData] = useState<{ notes: string }>({ notes: '' })
  const [doctors, setDoctors] = useState<{ id: string; name: string }[]>([])

  useEffect(() => {
    if (!window.__KEK__ || !window.__MY_PRIV__) {
      alert('Encryption keys not available. Please re-login with a PRF-supported device.');
      return;
    }

    // Fetch record
    fetch('/api/record/my/').then(async r => {
      if (!r.ok) {
        console.error('Fetch record error:', await r.text())
        return
      }
      const { encrypted_data, encrypted_deks, signature } = await r.json()
      if (encrypted_data) {
        const rawBytes = hexToBytes(encrypted_data)
        const iv = rawBytes.slice(0, 12)
        const tag = rawBytes.slice(-16)
        const ciphertext = rawBytes.slice(12, -16)

        const dek = await decryptDEK(encrypted_deks['self'], window.__KEK__)
        const decrypted = await decryptAES(ciphertext, dek, iv, tag)
        setData(JSON.parse(new TextDecoder().decode(decrypted)))

        // Verify sig over full encrypted_data bytes
        const edPub = deriveEd25519FromX25519(window.__MY_PRIV__).publicKey
        if (!verifyEd25519(hexToBytes(signature), rawBytes, edPub)) alert('Tampered!')
      }
    }).catch(err => console.error('Record fetch failed:', err))

    // Fetch doctors
    fetch('/api/appoint/doctors/').then(async r => {
      if (!r.ok) {
        console.error('Fetch doctors error:', await r.text())
        return
      }
      const { doctors } = await r.json()
      setDoctors(doctors)
    }).catch(err => console.error('Doctors fetch failed:', err))
  }, [])

  const decryptDEK = async (dekHex: string, kek: Uint8Array): Promise<Uint8Array> => {
    const dekBytes = hexToBytes(dekHex)
    const iv = dekBytes.slice(0, 12)
    const tag = dekBytes.slice(-16)
    const ciphertext = dekBytes.slice(12, -16)
    return decryptAES(ciphertext, kek, iv, tag)
  }

  const updateRecord = async () => {
    if (!window.__KEK__ || !window.__MY_PRIV__) {
      alert('Encryption keys not available. Please re-login.');
      return;
    }

    const dek = randomBytes(32)
    const raw = new TextEncoder().encode(JSON.stringify(data))
    const encrypted = await encryptAES(raw, dek)

    // Concat full encrypted data for sig and storage
    const concatenated = new Uint8Array([...encrypted.iv, ...encrypted.ciphertext, ...encrypted.tag]);
    // Derive Ed25519 signing private key from X25519 priv
    const edPriv = deriveEd25519FromX25519(window.__MY_PRIV__).privateKey;
    const sig = signEd25519(concatenated, edPriv);  // Sync, no await

    const deks: Record<string, string> = {}
    
    // Self DEK: Encrypt with KEK
    const encryptedSelfDek = await encryptAES(dek, window.__KEK__)
    deks['self'] = bytesToHex(new Uint8Array([...encryptedSelfDek.iv, ...encryptedSelfDek.ciphertext, ...encryptedSelfDek.tag]))

    // Doctor DEKs: ECDH shared
    for (const doc of doctors) {
      const docPubRes = await fetch(`/api/user/${doc.id}/public_key/`)
      if (!docPubRes.ok) continue
      const { public_key } = await docPubRes.json()
      const docPubBytes = hexToBytes(public_key) // Assume hex string from server
      const shared = await ecdhSharedSecret(window.__MY_PRIV__, docPubBytes)
      const encryptedDek = await encryptAES(dek, shared)
      deks[doc.id] = bytesToHex(new Uint8Array([...encryptedDek.iv, ...encryptedDek.ciphertext, ...encryptedDek.tag]))
    }

    await fetch('/api/record/update/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encrypted_data: bytesToHex(concatenated),
        encrypted_deks: deks,
        signature: bytesToHex(sig),
      })
    }).then(async r => {
      if (!r.ok) console.error('Update error:', await r.text())
    }).catch(err => console.error('Update failed:', err))
  }

  const removeDoctor = async (doctorId: string) => {
    try {
      const res = await fetch(`/api/appoint/remove/${doctorId}/`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Remove failed');
      // Refresh doctors list
      const r = await fetch('/api/appoint/doctors/');
      const { doctors } = await r.json();
      setDoctors(doctors);
    } catch (err) {
      console.error('Remove doctor failed:', err);
    }
  };

  return (
    <div>
      <p>Current Notes: {data.notes || 'No notes yet'}</p>
      <Input value={data.notes} onChange={e => setData({ notes: e.target.value })} />
      <Button onClick={updateRecord}>Save Encrypted Record</Button>
      <div className="mt-4">
        <h3>Appointed Doctors</h3>
        {doctors.length === 0 ? (
          <p>No doctors appointed yet.</p>
        ) : (
          doctors.map(doc => (
            <div key={doc.id} className="flex justify-between items-center">
              <span>{doc.name}</span>
              <Button variant="destructive" onClick={() => removeDoctor(doc.id)}>Remove</Button>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
