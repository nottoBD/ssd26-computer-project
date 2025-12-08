import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, User, Stethoscope } from 'lucide-react'

export const Route = createFileRoute('/register')({
  component: RegisterPage,
})

function RegisterPage() {
  const navigate = useNavigate()
  const [userType, setUserType] = useState<'patient' | 'doctor'>('patient')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    const formData = new FormData(e.currentTarget)
    const data = {
      email: (formData.get("email") as string).trim().toLowerCase(),
      userType,
      firstName: formData.get('firstName'),
      lastName: formData.get('lastName'),
      dateOfBirth: userType === 'patient' ? formData.get('dateOfBirth') : undefined,
      medicalOrganization: userType === 'doctor' ? formData.get('medicalOrganization') : undefined,
    }

    try {
      // TODO: Replace with WebAuthn registration flow
      // This is a placeholder for the WebAuthn + PRF flow
      console.log('Registration data (will be secured with WebAuthn + PRF):', data)
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      alert('Registration submitted. WebAuthn + PRF flow will be implemented here.')
      navigate({ to: '/login' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  const initiateWebAuthn = async () => {
    // TODO: Implement actual WebAuthn registration
    alert('WebAuthn registration will be implemented here')
  }

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 bg-gradient-to-br from-blue-50 to-indigo-50">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 rounded-full bg-blue-100">
            <Shield className="w-6 h-6 text-blue-600" />
          </div>
          <CardTitle className="text-2xl text-center">Create HealthSecure Account</CardTitle>
          <CardDescription className="text-center">
            Secure medical records access with WebAuthn authentication
          </CardDescription>
        </CardHeader>
        
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-6">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* User Type Selection */}
            <div className="space-y-4">
              <Label>I am registering as a:</Label>
              <RadioGroup
                value={userType}
                onValueChange={(value: 'patient' | 'doctor') => setUserType(value)}
                className="grid grid-cols-2 gap-4"
              >
                <div>
                  <RadioGroupItem value="patient" id="patient" className="peer sr-only" />
                  <Label
                    htmlFor="patient"
                    className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-transparent p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary"
                  >
                    <User className="mb-3 h-6 w-6" />
                    <span className="text-sm font-medium">Patient</span>
                  </Label>
                </div>
                <div>
                  <RadioGroupItem value="doctor" id="doctor" className="peer sr-only" />
                  <Label
                    htmlFor="doctor"
                    className="flex flex-col items-center justify-between rounded-md border-2 border-muted bg-transparent p-4 hover:bg-accent hover:text-accent-foreground peer-data-[state=checked]:border-primary [&:has([data-state=checked])]:border-primary"
                  >
                    <Stethoscope className="mb-3 h-6 w-6" />
                    <span className="text-sm font-medium">Doctor</span>
                  </Label>
                </div>
              </RadioGroup>
            </div>

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="email">Email Address *</Label>
              <Input
                id="email"
                name="email"
                type="email"
                required
                placeholder={
                  userType === "doctor"
                    ? "doctor@hospital.com"
                    : "patient@example.com"
                }
                autoComplete="email"
              />
            </div>

            {/* Common Fields */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="firstName">First Name *</Label>
                <Input
                  id="firstName"
                  name="firstName"
                  required
                  placeholder="John"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="lastName">Last Name *</Label>
                <Input
                  id="lastName"
                  name="lastName"
                  required
                  placeholder="Doe"
                />
              </div>
            </div>

            {/* Patient-specific Fields */}
            {userType === 'patient' && (
              <div className="space-y-2">
                <Label htmlFor="dateOfBirth">Date of Birth *</Label>
                <Input
                  id="dateOfBirth"
                  name="dateOfBirth"
                  type="date"
                  required
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Medical records will be created upon registration
                </p>
              </div>
            )}

            {/* Doctor-specific Fields */}
            {userType === 'doctor' && (
              <div className="space-y-2">
                <Label htmlFor="medicalOrganization">Medical Organization *</Label>
                <Input
                  id="medicalOrganization"
                  name="medicalOrganization"
                  required
                  placeholder="e.g., City General Hospital"
                />
                <div className="p-3 mt-2 text-sm bg-blue-50 rounded-md border border-blue-200">
                  <p className="font-medium text-blue-800">Trusted User Registration</p>
                  <p className="text-blue-600 text-xs mt-1">
                    Doctor accounts require certificate-based authentication (CA-signed certificates required)
                  </p>
                </div>
              </div>
            )}

            {/* WebAuthn Section */}
            <div className="pt-4 border-t">
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <div className="flex-shrink-0 w-2 h-2 rounded-full bg-green-500"></div>
                  <span className="text-sm font-medium">WebAuthn Authentication</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Your credentials will be secured using WebAuthn with PRF extension. 
                  No passwords are stored on the server.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  onClick={initiateWebAuthn}
                  className="w-full"
                >
                  Register Security Key / Biometric
                </Button>
              </div>
            </div>

            {/* Security Notice */}
            <Alert className="bg-amber-50 border-amber-200">
              <AlertDescription className="text-xs text-amber-800">
                <strong>Security Notice:</strong> All sensitive data is encrypted client-side before transmission. 
                The server never receives plaintext medical information or authentication secrets.
              </AlertDescription>
            </Alert>
          </CardContent>

          <CardFooter className="flex-col space-y-4">
            <Button 
              type="submit" 
              className="w-full"
              disabled={loading}
            >
              {loading ? 'Securing Registration...' : 'Complete Secure Registration'}
            </Button>
            
            <div className="text-center text-sm text-muted-foreground">
              Already have an account?{' '}
              <a href="/login" className="text-blue-600 hover:text-blue-500 font-medium">
                Sign in with WebAuthn
              </a>
            </div>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
