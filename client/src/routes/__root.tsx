/**
 * FILE: __root.tsx
 *
 * PURPOSE:
 *      Defines the root route and application shell for the client.
 *      The file centralizes session discovery, exposes authentication state via
 *      a React context, and implements global navigation (including logout).
 *
 * RESPONSIBILITIES:
 *  - Provide an AuthContext with:
 *      * isAuthenticated: client view of session state
 *      * refreshAuth(): re-fetch session state from backend
 *  - Query backend session status using HttpOnly cookies (sessionid) and determine
 *    whether a user is currently authenticated.
 *  - Fetch the current user's profile to infer role (patient/doctor) for UI rendering.
 *  - Perform logout request and local cookie cleanup, then reset local auth state.
 *
 *  NOTES:
 *  - Authentication state is derived from backend session cookies (credentials: include).
 *    The client is not a source of truth for authorization; server-side checks remain mandatory.
 *  - Logout uses CSRF protection (csrftoken) for POST requests.
 *  - Cookie deletion performed in JS is best-effort; actual session invalidation must occur
 *    server-side via /api/webauthn/logout/.
 *
 * LIMITATIONS:
 *  - Role-based navigation styling is cosmetic; it must not be relied upon for access control.
 *  - Error handling intentionally fails closed (sets isAuthenticated=false on exceptions).
 */

import { createRootRoute, Link, Outlet, useNavigate } from '@tanstack/react-router'
import { getKey, deleteKey } from '../lib/key-store';
import { deriveEd25519FromX25519 } from '../components/CryptoUtils';
import { Button } from '@/components/ui/button'
import { Shield, User, Stethoscope, Settings as SettingsIcon, LogOut as LogOutIcon } from 'lucide-react'
import { useState, useEffect, createContext, useContext } from 'react'
import { apiFetch } from '../lib/utils';
import { generateMetadata, prepareMetadata } from '../lib/metadata';

interface AuthContextType {
  isAuthenticated: boolean
  refreshAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

/**
 * FUNCTION: useAuth
 *
 * PURPOSE:
 *      Typed helper hook to access AuthContext safely throughout the client.
 *
 * BEHAVIOR:
 *  - Throws a hard error if used outside of AuthContext.Provider to prevent
 *    silent null usage and inconsistent authentication logic.
 */

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
    const [userType, setUserType] = useState<'patient' | 'doctor' | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
      checkAuth()
    }, [])


    /**
 * FUNCTION: getCsrfToken
 *
 * PURPOSE:
 *      Extracts the Django CSRF token from document cookies for state-changing
 *      requests (e.g., logout).
 *
 * SECURITY:
 *      Used to satisfy Django's CSRF middleware when issuing POST requests with
 *      session cookies included.
 */

    const getCsrfToken = () => {
      const match = document.cookie.match(new RegExp('(^| )csrftoken=([^;]+)'))
      return match ? match[2] : ''
    }




/**
 * FUNCTION: checkAuth
 *
 * PURPOSE:
 *      Refreshes client-side session state by querying the backend.
 *
 * FLOW:
 *  1) GET /api/webauthn/auth/status/ with credentials included.
 *  2) If authenticated, GET /api/user/me/ to obtain user role (patient/doctor).
 *  3) Update local state: isAuthenticated, userType.
 *
 * FAILURE MODE:
 *  - On any network or parsing error, fail closed by setting isAuthenticated=false.
 *
 * SIDE EFFECTS:
 *  - Updates local UI gating (settings button visibility, role highlighting).
 */

    const checkAuth = async () => {
      try {
        const response = await apiFetch('/api/webauthn/auth/status/', { method: 'GET', credentials: 'include' }, ["auth", "status"]);
        if (!response.ok) {
          setIsAuthenticated(false)
          return
        }
        const data = await response.json()
        setIsAuthenticated(data.authenticated)
        if (data.authenticated) {
          const userRes = await apiFetch('/api/user/me/', { method: 'GET', credentials: 'include' }, ["user", "get_me"]);
          if (userRes.ok) {
            const userData = await userRes.json()
            setUserType(userData.type)
          }

        if (!(window as any).__MY_PRIV__) {
            try {
              const storedKey = await getKey('master_priv_key');
              if (storedKey) {
                  console.log("Restore key from IndexDB");
                  
                  let privBytes: Uint8Array;
                  if (storedKey instanceof CryptoKey) {
                    const raw = await crypto.subtle.exportKey("raw", storedKey);
                    privBytes = new Uint8Array(raw);
                  } else {
                    privBytes = storedKey as Uint8Array;
                  }
                  
                  (window as any).__MY_PRIV__ = privBytes;
                  (window as any).__SIGN_PRIV__ = deriveEd25519FromX25519(privBytes).privateKey;
              }
            } catch (e) { console.error("Error during key restore", e); }
        }
        }
      } catch (error) {
        setIsAuthenticated(false)
      } finally {
        setLoading(false)
      }
    }


  
/**
 * FUNCTION: handleLogout
 *
 * PURPOSE:
 *      Logs the user out of the backend session and clears client-visible state.
 *
 * FLOW:
 *  1) Read CSRF token from cookies.
 *  2) POST /api/webauthn/logout/ with credentials included.
 *  3) Regardless of backend response:
 *      - Clear session cookies locally (best-effort).
 *      - Reset isAuthenticated/userType.
 *      - Redirect to "/" to return to a safe default route.
 *
 * SECURITY NOTES:
 *  - Actual session invalidation must be performed server-side; JS cookie deletion
 *    is only a local cleanup step.
 */

    const handleLogout = async () => {
      try {
        const csrfToken = getCsrfToken()
        const logoutMetadata = generateMetadata({}, ['user', 'logout'], 'POST');
        const logoutMetadataHeader = await prepareMetadata(logoutMetadata, (window as any).__SIGN_PRIV__);
        const response = await fetch('/api/webauthn/logout/', {
          method: 'POST',
          credentials: 'include',
          headers: { 
            'X-CSRFToken': csrfToken,
            'X-Metadata': logoutMetadataHeader
          },
        })
      } catch (error) {
        console.error('Logout request failed', error)
      } finally {
        await deleteKey('master_priv_key'); // delete from indexDB
        await deleteKey('cert_priv');
        delete (window as any).__MY_PRIV__; // delete from ram
        delete (window as any).__SIGN_PRIV__;
        document.cookie = 'sessionid=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; secure; samesite=lax';
        document.cookie = 'csrftoken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; secure; samesite=lax';
        setIsAuthenticated(false);
        setUserType(null);
        navigate({ to: '/' });
      }
    }

/**
 * FUNCTION: handleAuthAction
 *
 * PURPOSE:
 *      Provides a single UI handler that toggles between login and logout
 *      based on the current authentication state.
 *
 * BEHAVIOR:
 *  - If authenticated: triggers logout sequence.
 *  - If unauthenticated: redirects to /login.
 */
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
                  <Link to="/record" className={`flex items-center ${userType === 'patient' ? 'text-blue-600' : 'text-muted-foreground'}`}>
                    <User className="w-4 h-4 mr-1" />
                    <span>Patient Portal</span>
                  </Link>
                  <div className="h-4 w-px bg-gray-300"></div>
                  <Link to="/doctor" className={`flex items-center ${userType === 'doctor' ? 'text-blue-600' : 'text-muted-foreground'}`}>
                    <Stethoscope className="w-4 h-4 mr-1" />
                    <span>Doctor Portal</span>
                  </Link>
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
                <p className="mt-1">Server authentication required • No trusted third parties</p>
                <p>Master of Cybersecurity • Secure Software Design</p>
                <p>2026</p>
              </div>
            </div>
          </footer>
        </div>
      </AuthContext.Provider>
    )
  },
  errorComponent: ({ error }) => {
    console.error('Root error:', error);
    return (
      <div className="p-4">
        <h1 className="text-2xl font-bold mb-4">An error occurred</h1>
        <p className="text-red-600 mb-2">{error.message}</p>
        <pre className="bg-gray-100 p-4 overflow-auto">{error.stack}</pre>
      </div>
    );
  },
})
