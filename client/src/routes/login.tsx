import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, Fingerprint, Key } from 'lucide-react'

export const Route = createFileRoute('/login')({
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [useWebAuthn, setUseWebAuthn] = useState(true)

  const handleWebAuthnLogin = async () => {
    setLoading(true)
    setError(null)
    
    try {
      // TODO: Implement actual WebAuthn authentication
      // This will include server authentication and credential assertion
      console.log('Initiating WebAuthn authentication...')
      
      // Simulate WebAuthn flow
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      alert('WebAuthn authentication will be implemented here')
      navigate({ to: '/' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'WebAuthn authentication failed')
    } finally {
      setLoading(false)
    }
  }

  const handleFallbackLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    const formData = new FormData(e.currentTarget)
    const username = formData.get('username')
    
    try {
      // TODO: Implement fallback authentication (temporary for development)
      console.log('Fallback login for:', username)
      
      await new Promise(resolve => setTimeout(resolve, 1000))
      alert('Note: Production will use WebAuthn only')
      navigate({ to: '/' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
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

          {/* WebAuthn Primary Login */}
          <div className="space-y-4">
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
              disabled={loading}
              className="w-full h-12 text-base bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
            >
              {loading ? (
                <span className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Authenticating...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  <Fingerprint className="mr-2 h-5 w-5" />
                  Login with WebAuthn
                </span>
              )}
            </Button>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  Or continue with
                </span>
              </div>
            </div>

            {/* Fallback Login (Development Only) */}
            <div className="p-4 border rounded-lg bg-amber-50 border-amber-200">
              <div className="flex items-start space-x-3">
                <Key className="w-5 h-5 text-amber-600 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-amber-800">Development Fallback</p>
                  <p className="text-xs text-amber-600 mt-1">
                    This is for development only. Production will use WebAuthn exclusively.
                  </p>
                </div>
              </div>
              
              <form onSubmit={handleFallbackLogin} className="mt-4 space-y-3">
                <div className="space-y-2">
                  <Label htmlFor="username">Username / Email</Label>
                  <Input
                    id="username"
                    name="username"
                    placeholder="user@example.com"
                    className="bg-white"
                  />
                </div>
                <Button
                  type="submit"
                  variant="outline"
                  disabled={loading}
                  className="w-full border-amber-300 text-amber-700 hover:bg-amber-100"
                >
                  Development Login
                </Button>
              </form>
            </div>
          </div>

          {/* Security Information */}
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
