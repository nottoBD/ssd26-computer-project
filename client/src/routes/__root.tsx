import { createRootRoute, Link, Outlet } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Shield, User, Stethoscope } from 'lucide-react'

export const Route = createRootRoute({
  component: () => (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">
      <nav className="border-b bg-white/80 backdrop-blur-sm shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <Link to="/" className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              HealthSecure
            </Link>
            <span className="hidden sm:inline text-xs px-2 py-1 rounded-full bg-blue-100 text-blue-700 font-medium">
              Medical Records System
            </span>
          </div>
          <div className="flex items-center space-x-3">
            <div className="hidden md:flex items-center space-x-4 text-sm">
              <div className="flex items-center text-muted-foreground">
                <User className="w-4 h-4 mr-1" />
                <span>Patient Portal</span>
              </div>
              <div className="h-4 w-px bg-gray-300"></div>
              <div className="flex items-center text-muted-foreground">
                <Stethoscope className="w-4 h-4 mr-1" />
                <span>Doctor Portal</span>
              </div>
            </div>
            <Button asChild variant="ghost" className="text-blue-600 hover:text-blue-700 hover:bg-blue-50">
              <Link to="/login">Login with WebAuthn</Link>
            </Button>
            <Button asChild className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700">
              <Link to="/register">Secure Registration</Link>
            </Button>
          </div>
        </div>
      </nav>
      <Outlet />
      
      {/* Footer */}
      <footer className="mt-12 border-t bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <h3 className="text-lg font-semibold mb-4">Security Features</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                  WebAuthn with PRF extension
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                  End-to-end encryption
                </li>
                <li className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                  Zero-knowledge architecture
                </li>
              </ul>
            </div>
            <div>
              <h3 className="text-lg font-semibold mb-4">User Types</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-center">
                  <User className="w-4 h-4 mr-2" />
                  Patients: Secure medical records access
                </li>
                <li className="flex items-center">
                  <Stethoscope className="w-4 h-4 mr-2" />
                  Doctors: CA-certified trusted access
                </li>
              </ul>
            </div>
            <div>
              <h3 className="text-lg font-semibold mb-4">Compliance</h3>
              <p className="text-sm text-muted-foreground">
                Designed for medical data protection regulations.
                No plaintext sensitive data transmission.
                Server cannot decrypt medical records.
              </p>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t text-center text-sm text-muted-foreground">
            <p>Computer Project - Secure Software Development - Group SSD26</p>
            <p className="mt-1">Server authentication required • No trusted third parties</p>
          </div>
        </div>
      </footer>
    </div>
  ),
})
