import { useState, useEffect } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { encryptAES, decryptAES, signEd25519, verifyEd25519, ecdhSharedSecret } from '../components/CryptoUtils'

export const Route = createFileRoute('/record')({
  component: RecordPage,
})

function RecordPage() {
  const [data, setData] = useState<{ notes: string }>({ notes: '' })
  const [doctors, setDoctors] = useState<{ id: string; name: string }[]>([])  // from /api/my/doctors/

  useEffect(() => {
    fetch('/api/record/my/').then(async r => {
      const { encrypted_data, encrypted_deks, signature } = await r.json()
      if (encrypted_data) {
        const dek = decryptDEK(encrypted_deks['self'])  // self-encrypted DEK
        const raw = bytes.fromhex(encrypted_data)
        const decrypted = decryptAES(raw.ciphertext, dek, raw.iv, raw.tag)
        setData(JSON.parse(new TextDecoder().decode(decrypted)))
        
        // Verify sig
        const edPub = deriveEd25519FromX25519(window.__MY_PRIV__).publicKey  // or fetch patient pub
        if (!verifyEd25519(bytes.fromhex(signature), raw, edPub)) alert('Tampered!')
      }
    })
  }, [])

  const updateRecord = async () => {
    const dek = randomBytes(32)
    const raw = new TextEncoder().encode(JSON.stringify(data))
    const encrypted = encryptAES(raw, dek)
    
    const sig = signEd25519(new Uint8Array([...encrypted.ciphertext, ...encrypted.tag]), window.__SIGN_PRIV__)
    
    const deks: Record<string, string> = { 'self': encryptAES(dek, window.__MY_PRIV__).ciphertext.hex() }  // self for patient
    for (const doc of doctors) {
      const docPub = await fetch(`/api/user/${doc.id}/public_key/`).then(r => r.json().public_key)
      const shared = ecdhSharedSecret(window.__MY_PRIV__, new Uint8Array(docPub))
      deks[doc.id] = encryptAES(dek, shared).ciphertext.hex()
    }
    
    await fetch('/api/record/update/', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_data: { ...encrypted, ciphertext: encrypted.ciphertext.hex(), iv: encrypted.iv.hex(), tag: encrypted.tag.hex() },
        encrypted_deks: deks,
        signature: sig.hex(),
      })
    })
  }

  return (
    <div>
      <Input value={data.notes} onChange={e => setData({ notes: e.target.value })} />
      <Button onClick={updateRecord}>Save Encrypted Record</Button>
    </div>
  )
}
