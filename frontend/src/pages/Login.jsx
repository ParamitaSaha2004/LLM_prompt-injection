import React, { useState } from 'react';
import { Shield, ShieldAlert, Lock, Mail, User } from 'lucide-react';

export default function Login({ onLoginSuccess }) {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user'); // admin or user
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const endpoint = isRegister ? '/api/auth/register' : '/api/auth/login';
    const payload = isRegister 
      ? { username, email, password, role }
      : { username, password };

    try {
      const response = await fetch(`http://localhost:5000${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Something went wrong.');
      }

      if (isRegister) {
        // Success callback for registration: toggle back to login
        setIsRegister(false);
        setError('Registered successfully! Please login.');
        setUsername('');
        setEmail('');
        setPassword('');
      } else {
        // Handle login success
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLoginSuccess(data.user, data.token);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-screen w-screen flex items-center justify-center bg-[#020617] relative overflow-hidden h-screen text-slate-100">
      {/* Dynamic Background Grid & Lights */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-40"></div>
      
      {/* Glowing colored circles */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl -translate-y-1/2 -translate-x-1/2"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl translate-y-1/2 translate-x-1/2"></div>

      <div className="relative w-full max-w-md p-8 glass rounded-2xl glow-primary">
        
        {/* Header Icon */}
        <div className="flex flex-col items-center mb-8">
          <div className="p-3 bg-indigo-600/20 text-indigo-400 rounded-2xl mb-3 border border-indigo-500/20 animate-pulse-slow">
            <Shield size={36} />
          </div>
          <h2 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
            {isRegister ? 'Create Security Account' : 'PromptShield Portal'}
          </h2>
          <p className="text-xs text-slate-400 mt-1.5 text-center">
            {isRegister 
              ? 'Register credentials for prompt injection scanning access' 
              : 'Sign in to access secure RAG LLM environment'
            }
          </p>
        </div>

        {/* Errors / Info message banner */}
        {error && (
          <div className={`p-3.5 mb-5 rounded-xl flex items-start gap-3 border text-xs ${
            error.includes('successfully')
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-red-500/10 border-red-500/20 text-red-400'
          }`}>
            <ShieldAlert size={16} className="mt-0.5 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          
          {/* Username Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Username</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                <User size={16} />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/25 transition-all duration-200"
                required
              />
            </div>
          </div>

          {/* Email Field (Only on Register) */}
          {isRegister && (
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Email Address</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                  <Mail size={16} />
                </span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@example.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/25 transition-all duration-200"
                  required
                />
              </div>
            </div>
          )}

          {/* Password Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                <Lock size={16} />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/25 transition-all duration-200"
                required
              />
            </div>
          </div>

          {/* Role selector (Only on Register for demonstration flexibilities) */}
          {isRegister && (
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wider">Default Role</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setRole('user')}
                  className={`py-2 px-4 rounded-xl border text-sm font-medium transition-all ${
                    role === 'user'
                      ? 'bg-indigo-600/10 border-indigo-500 text-indigo-400'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  Regular User
                </button>
                <button
                  type="button"
                  onClick={() => setRole('admin')}
                  className={`py-2 px-4 rounded-xl border text-sm font-medium transition-all ${
                    role === 'admin'
                      ? 'bg-purple-600/10 border-purple-500 text-purple-400'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  Administrator
                </button>
              </div>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-medium py-2.5 rounded-xl shadow-lg shadow-indigo-600/20 active:scale-[0.98] transition-all disabled:opacity-50 text-sm"
          >
            {loading ? 'Processing...' : isRegister ? 'Register Account' : 'Authenticate Portal'}
          </button>

        </form>

        {/* Toggle Mode */}
        <div className="mt-6 text-center text-xs">
          <span className="text-slate-500">
            {isRegister ? 'Already have an account?' : 'Need a demonstration account?'}
          </span>
          <button
            onClick={() => {
              setIsRegister(!isRegister);
              setError('');
            }}
            className="ml-1.5 text-indigo-400 hover:text-indigo-300 font-semibold underline decoration-indigo-500/30"
          >
            {isRegister ? 'Sign In' : 'Register Here'}
          </button>
        </div>

      </div>
    </div>
  );
}
