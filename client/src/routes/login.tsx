'use client'

import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, Fingerprint, Loader2 } from 'lucide-react'
import { startAuthentication } from '@simplewebauthn/browser'
import { decode } from 'cbor-x'

export const Route = createFileRoute('/login')({
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stage, setStage] = useState<'prompt' | 'authenticating'>('prompt')

  const startWebAuthnLogin = async () => {
    setLoading(true)
    setError(null)
    setStage('authenticating')
  }

  const handleWebAuthnLogin = async () => {
    startWebAuthnLogin()

    try {
      // Step 1: Ask server for authentication options (discoverable credentials = no email needed)
      const resp = await fetch('/api/webauthn/login/start/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}), // empty → allow any registered device
      })

      if (!resp.ok) throw new Error('No registered device found for this browser')

      const options = await resp.json()

      // Step 2: Trigger browser native prompt
      const credential = await startAuthentication(options)

      // Step 3: Send back to server
      const finishResp = await fetch('/api/webauthn/login/finish/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/cbor' },
        body: encode(credential),
      })

      const result = await finishResp.json()

      if (!finishResp.ok) throw new Error(result.error || 'Authentication failed')

      // PRF SUCCESS → KEK IS NOW AVAILABLE IN MEMORY
      if (result.prf_available && result.prf_hex) {
        const prfBytes = Uint8Array.from(
          result.prf_hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
        )
        const kek = await crypto.subtle.importKey('raw', prfBytes, 'PBKDF2', false, ['deriveKey'])
        // Store globally or in context for encryption layer (commit 5)
        window.__KEK__ = kek
        console.log('✅ PRF KEK derived and ready for encryption')
      }

      navigate({ to: '/' })
    } catch (err: any) {
      console.error(err)
      setError(err.message || 'Authentication failed — try another device or register first')
      setStage('prompt')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 bg-gradient-to-br from-gray-50 to-slate-100">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 rounded-full bg-gradient-to-r from-blue-500 to-indigo-600">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl text-center">HealthSecure Login</CardTitle>
          <CardDescription className="text-center">
            Secure authentication using WebAuthn with PRF extension
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-4">
            {stage === 'prompt' ? (
              <>
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 mb-4">
                    <Fingerprint className="w-8 h-8 text-blue-600" />
                  </div>
                  <h3 className="text-lg font-semibold">Biometric / Security Key Login</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Use your registered security key, fingerprint, or face recognition
                  </p>
                </div>
                
                <Button
                  onClick={handleWebAuthnLogin}
                  className="w-full h-12 text-base bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                >
                  <Fingerprint className="mr-2 h-5 w-5" />
                  Login with WebAuthn
                </Button>
              </>
            ) : (
              <div className="py-12 text-center space-y-6">
                <div className="mx-auto w-20 h-20 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 flex items-center justify-center animate-pulse">
                  <Fingerprint className="h-10 w-10 text-white" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold">Confirm your identity</h3>
                  <p className="text-muted-foreground mt-2">Use Face ID, Touch ID, Windows Hello, or security key</p>
                </div>
              </div>
            )}
          </div>

          <Alert className="bg-blue-50 border-blue-200">
            <AlertDescription className="text-sm text-blue-800">
              <strong>How it works:</strong> WebAuthn uses public key cryptography. Your private key 
              never leaves your device. Server authentication is verified before login.
            </AlertDescription>
          </Alert>
        </CardContent>

        <CardFooter className="flex-col space-y-4 border-t pt-6">
          <div className="text-center text-sm">
            <p className="text-muted-foreground">
              Don't have an account?{' '}
              <a href="/register" className="font-medium text-blue-600 hover:text-blue-500">
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
    </div>
  )
}
