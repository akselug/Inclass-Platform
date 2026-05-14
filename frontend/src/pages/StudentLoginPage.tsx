import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authApi } from '../api/authApi';
import { BookOpen, Mail, Lock } from 'lucide-react';

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: {
            client_id: string;
            callback: (response: { credential?: string }) => void;
            auto_select?: boolean;
          }) => void;
          renderButton: (
            element: HTMLElement,
            options: {
              theme?: 'outline' | 'filled_blue' | 'filled_black';
              size?: 'large' | 'medium' | 'small';
              type?: 'standard' | 'icon';
              text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
              shape?: 'rectangular' | 'pill' | 'circle' | 'square';
              logo_alignment?: 'left' | 'center';
              width?: number;
            }
          ) => void;
        };
      };
    };
  }
}

const GOOGLE_SCRIPT_ID = 'google-identity-services';

export const StudentLoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [error, setError] = useState('');
  const [googleButtonReady, setGoogleButtonReady] = useState(false);
  const googleButtonRef = useRef<HTMLDivElement>(null);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const persistStudentSession = async (token: string) => {
    localStorage.setItem('demo_token', token);
    localStorage.setItem('demo_role', 'student');

    const me = await authApi.getMe();
    localStorage.setItem('demo_user', JSON.stringify(me));
  };

  useEffect(() => {
    let isMounted = true;

    const loadGoogleScript = () =>
      new Promise<void>((resolve, reject) => {
        if (window.google?.accounts?.id) {
          resolve();
          return;
        }

        const existingScript = document.getElementById(GOOGLE_SCRIPT_ID) as HTMLScriptElement | null;
        if (existingScript) {
          existingScript.addEventListener('load', () => resolve(), { once: true });
          existingScript.addEventListener('error', () => reject(new Error('Google sign-in script could not be loaded.')), { once: true });
          return;
        }

        const script = document.createElement('script');
        script.id = GOOGLE_SCRIPT_ID;
        script.src = 'https://accounts.google.com/gsi/client';
        script.async = true;
        script.defer = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('Google sign-in script could not be loaded.'));
        document.head.appendChild(script);
      });

    const initializeGoogleButton = async () => {
      try {
        const [config] = await Promise.all([authApi.getGoogleConfig(), loadGoogleScript()]);
        if (!isMounted || !googleButtonRef.current) return;

        if (!config.clientId) {
          throw new Error('Google client ID is not configured.');
        }

        window.google?.accounts.id.initialize({
          client_id: config.clientId,
          auto_select: false,
          callback: async (response) => {
            setError('');

            if (!response.credential) {
              setError('Google sign-in did not return a credential.');
              return;
            }

            try {
              setIsGoogleLoading(true);
              const { token } = await authApi.googleStudentLogin(response.credential);
              await persistStudentSession(token);
              navigate('/student/dashboard');
            } catch (err: any) {
              const message = err.response?.data?.detail || err.message || 'Google sign-in failed';
              setError(message);
            } finally {
              setIsGoogleLoading(false);
            }
          },
        });

        googleButtonRef.current.innerHTML = '';
        window.google?.accounts.id.renderButton(googleButtonRef.current, {
          type: 'standard',
          theme: 'outline',
          size: 'large',
          text: 'signin_with',
          shape: 'pill',
          logo_alignment: 'left',
          width: 360,
        });
        setGoogleButtonReady(true);
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Google sign-in could not be initialized.');
        }
      }
    };

    initializeGoogleButton();

    return () => {
      isMounted = false;
    };
  }, [navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Please fill in all fields');
      return;
    }

    try {
      setIsLoading(true);
      const { token } = await authApi.login('STUDENT', email, password);

      await persistStudentSession(token);

      navigate('/student/dashboard');
    } catch (err: any) {
      const message = err.response?.data?.detail || err.message || 'Login failed';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="bg-indigo-600 p-3 rounded-2xl shadow-xl">
            <BookOpen className="w-10 h-10 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Student Login
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Access your student portal
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-white py-8 px-6 shadow-2xl sm:rounded-3xl border border-gray-100">
          <form className="space-y-5" onSubmit={handleLogin}>
            {error && (
              <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
                <p className="text-sm text-red-700 font-semibold">{error}</p>
              </div>
            )}

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-1">School Email</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500"
                  placeholder="name@university.edu"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-700 mb-1">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-3 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-500"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl shadow-lg text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none disabled:opacity-50 transition-all"
            >
              {isLoading ? 'Processing...' : 'Sign In'}
            </button>
          </form>

          <div className="my-6 flex items-center gap-3">
            <div className="h-px flex-1 bg-gray-200" />
            <span className="text-xs font-bold uppercase tracking-wide text-gray-400">or</span>
            <div className="h-px flex-1 bg-gray-200" />
          </div>

          <div className="flex flex-col items-center">
            <div
              ref={googleButtonRef}
              className={googleButtonReady ? '' : 'h-11 w-full rounded-full border border-gray-300 bg-gray-50'}
            />
            {isGoogleLoading && (
              <p className="mt-3 text-sm font-semibold text-gray-500">Signing in with Google...</p>
            )}
          </div>

          <div className="mt-6 text-center space-y-2">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Link to="/student/register" className="font-bold text-indigo-600 hover:text-indigo-500">
                Register here
              </Link>
            </p>
            <p className="text-sm text-gray-500">
              Are you an instructor?{' '}
              <Link to="/instructor/login" className="font-semibold text-indigo-400 hover:text-indigo-500">
                Sign in here
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
