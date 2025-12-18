import { createRootRoute, Link, Outlet, useNavigate } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'
import { Shield, User, Stethoscope, Settings as SettingsIcon, LogOut as LogOutIcon } from 'lucide-react'
import { useState, useEffect , createContext, useContext} from 'react'

interface AuthContextType {
  isAuthenticated: boolean
  refreshAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const Route = createRootRoute({
  component: () => {
    const navigate = useNavigate()
    const [isAuthenticated, setIsAuthenticated] = useState(false)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
      checkAuth()
    }, [])

    const getCsrfToken = () => {
      const match = document.cookie.match(new RegExp('(^| )csrftoken=([^;]+)'))
      return match ? match[2] : ''
    }

    const checkAuth = async () => {
      try {
        const response = await fetch('/api/webauthn/auth/status/', {
          method: 'GET',
          credentials: 'include',
        })
        if (!response.ok) {
          setIsAuthenticated(false)
          return
        }
        const data = await response.json()
        setIsAuthenticated(data.authenticated)
      } catch (error) {
        setIsAuthenticated(false)
      } finally {
        setLoading(false)
      }
    }

    const handleLogout = async () => {
      try {
        const csrfToken = getCsrfToken()
        const response = await fetch('/api/webauthn/logout/', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'X-CSRFToken': csrfToken,
          },
        })
        if (!response.ok) {
            throw new Error('Logout failed')
        }
        setIsAuthenticated(false)
        navigate({ to: '/' })
      } catch (error) {
        console.error('Logout failed', error)
      }
    }

    const handleAuthAction = () => {
      if (isAuthenticated) {
        handleLogout()
      } else {
        navigate({ to: '/login' })
      }
    }

    if (loading) {
      return <div>Loading...</div>
    }

    return (
        <AuthContext.Provider value={{ isAuthenticated, refreshAuth: checkAuth }}>
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

              {/* Settings Gear Icon only when authenticated */}
              {isAuthenticated && (
                <Button asChild variant="ghost" className="text-gray-600 hover:text-gray-700 hover:bg-gray-50">
                  <Link to="/settings">
                    <SettingsIcon className="w-4 h-4" />
                  </Link>
                </Button>
              )}

              {/* Dynamic Auth Button */}
              <Button
                variant="ghost"
                className={isAuthenticated ? "text-red-600 hover:text-red-700 hover:bg-red-50" : "text-blue-600 hover:text-blue-700 hover:bg-blue-50"}
                onClick={handleAuthAction}
              >
                {isAuthenticated ? (
                  <>
                    <LogOutIcon className="w-4 h-4 mr-1" /> Logout from WebAuthn
                  </>
                ) : (
                  "Login with WebAuthn"
                )}
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
              <p>ULB Computer Project - Secure Software Design - Group SSD26</p>
              <p className="mt-1">Server authentication required • No trusted third parties</p>
            </div>
          </div>
        </footer>
      </div>

        </AuthContext.Provider>
    )
  },
})
