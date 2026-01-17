/**
 * FILE: index.tsx
 *
 * ROLE:
 *      Public landing page of the application
 *
 * PURPOSE:
 *      Serves as the entry point for unauthenticated users and presents
 *      the security architecture and core guarantees of the system
 *
 * CONTENT:
 *  - High-level description of WebAuthn-based authentication.
 *  - Overview of end-to-end encryption and zero-trust principles
 *  - Navigation links to registration and login flows
 *
 * SECURITY NOTES:
 *  - No authentication state is required to access this page
 *  - No cryptographic keys or sensitive data are handled 
 */

import { useEffect } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, Lock, Fingerprint, Database, Users, FileLock } from 'lucide-react'
import { Link } from '@tanstack/react-router'


/**
 * ROUTE: /
 *
 * PURPOSE:
 *      Declares the public homepage route and binds it to the IndexPage component.
 *
 * NOTES:
 *  - This route is accessible without authentication.
 *  - Used as the first contact point for new users.
 */

export const Route = createFileRoute('/')({
  component: IndexPage,
})


/**
 * COMPONENT: IndexPage
 *
 * PURPOSE:
 *      Renders the public homepage of the application
 *
 * FLOW:
 *  1) On mount, performs a lightweight backend health check
 *  2) Displays a hero section with security-focused messaging
 *  3) Presents static feature descriptions (WebAuthn, E2EE, RBAC)
 *  4) Provides navigation to registration and login routes
 *
 * SECURITY NOTES:
 *  - This component does not depend on authentication state
 *  - All displayed content is static and non-sensitive
 */

function IndexPage() {
  useEffect(() => {
      /**
     * EFFECT: backendHealthCheck
     *
     * PURPOSE:
     *      Verifies that the backend API is reachable
     *
     * FLOW:
     *  1) Send GET request to /api/health/
     *  2) Log backend status if reachable
     *  3) Log a warning if the backend is unreachable
     *
     * SECURITY NOTES:
     *  - This check is informational only
     *  - It does not authenticate the user or affect UI behavior
     */

    fetch('/api/health/')
      .then(r => r.json())
      .then(data => console.log('Backend status:', data))
      .catch(err => console.warn('Backend check failed:', err))
  }, [])

  return (
    <div className="p-4 sm:p-6 lg:p-8">
      {/* Hero Section */}
      <div className="max-w-6xl mx-auto text-center mb-12">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 mb-6">
          <Shield className="w-8 h-8 text-white" />
        </div>
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight mb-4">
          Secure Medical Records Management
        </h1>
        <p className="text-xl text-muted-foreground max-w-3xl mx-auto mb-8">
          Zero-trust architecture with WebAuthn authentication and end-to-end encryption.
          Designed for maximum security in healthcare data protection.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button asChild size="lg" className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700">
            <Link to="/register">Get Started with WebAuthn</Link>
          </Button>
          <Button asChild variant="outline" size="lg">
            <Link to="/login">Login with Security Key</Link>
          </Button>
        </div>
      </div>

      {/* Features Grid */}
      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
        <Card className="border-blue-200 hover:border-blue-300 transition-colors">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-blue-100 flex items-center justify-center mb-4">
              <Fingerprint className="w-6 h-6 text-blue-600" />
            </div>
            <CardTitle>WebAuthn + PRF Authentication</CardTitle>
            <CardDescription>
              Passwordless authentication using security keys, biometrics, and device credentials
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                No passwords stored on server
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                Phishing-resistant authentication
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                Server authentication required
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card className="border-green-200 hover:border-green-300 transition-colors">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-green-100 flex items-center justify-center mb-4">
              <Lock className="w-6 h-6 text-green-600" />
            </div>
            <CardTitle>End-to-End Encryption</CardTitle>
            <CardDescription>
              Medical records encrypted client-side before transmission
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                Server cannot decrypt sensitive data
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                Zero-knowledge architecture
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                Metadata protection
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card className="border-purple-200 hover:border-purple-300 transition-colors">
          <CardHeader>
            <div className="w-12 h-12 rounded-lg bg-purple-100 flex items-center justify-center mb-4">
              <Users className="w-6 h-6 text-purple-600" />
            </div>
            <CardTitle>Role-Based Access Control</CardTitle>
            <CardDescription>
              Secure separation between Patients and Trusted Doctors
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-purple-500 mr-2"></div>
                Patients control access to records
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-purple-500 mr-2"></div>
                Doctors require CA certificates
              </li>
              <li className="flex items-center">
                <div className="w-2 h-2 rounded-full bg-purple-500 mr-2"></div>
                Appointment-based access control
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* User Types */}
      <div className="max-w-4xl mx-auto mb-12">
        <h2 className="text-3xl font-bold text-center mb-8">Designed for Healthcare Security</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <Card className="border-blue-100">
            <CardHeader>
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center">
                  <Users className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <CardTitle>For Patients</CardTitle>
                  <CardDescription>Secure access to medical records</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mr-3"></div>
                  <span>Full control over medical record access</span>
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mr-3"></div>
                  <span>Appoint trusted doctors as needed</span>
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mr-3"></div>
                  <span>End-to-end encrypted file storage</span>
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card className="border-green-100">
            <CardHeader>
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-full bg-green-100 flex items-center justify-center">
                  <FileLock className="w-5 h-5 text-green-600" />
                </div>
                <div>
                  <CardTitle>For Doctors</CardTitle>
                  <CardDescription>Trusted medical professional access</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-3"></div>
                  <span>CA-signed certificate authentication</span>
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-3"></div>
                  <span>Patient-approved record access</span>
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-3"></div>
                  <span>Secure file upload with patient consent</span>
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Security Notice */}
      <Card className="max-w-3xl mx-auto border-amber-200 bg-amber-50">
        <CardContent className="pt-6">
          <div className="flex items-start space-x-4">
            <div className="flex-shrink-0">
              <div className="w-10 h-10 rounded-full bg-amber-100 flex items-center justify-center">
                <Database className="w-5 h-5 text-amber-600" />
              </div>
            </div>
            <div>
              <h3 className="font-semibold text-lg mb-2 text-amber-800">Zero-Trust Architecture</h3>
              <p className="text-amber-700">
                This system implements a zero-trust security model. The server is not trusted with 
                sensitive data. All medical records are encrypted client-side before transmission. 
                WebAuthn ensures strong authentication without password risks. Server compromise 
                does not expose sensitive medical information.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
