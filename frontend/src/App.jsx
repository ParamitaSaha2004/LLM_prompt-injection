import React, { useState, useEffect } from 'react';
import Login from './pages/Login';
import Sidebar from './components/Sidebar';
import ChatInterface from './pages/ChatInterface';
import Playground from './pages/Playground';
import Dashboard from './pages/Dashboard';
import FileScanner from './pages/FileScanner';

export default function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [activeTab, setActiveTab] = useState('chat'); // chat, playground, dashboard
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check local storage for active authentication session
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');

    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
      
      // Auto-validate session against backend /me endpoint
      validateSession(storedToken);
    } else {
      setLoading(false);
    }
  }, []);

  const validateSession = async (sessionToken) => {
    try {
      const res = await fetch('http://localhost:5000/api/auth/me', {
        headers: { 'Authorization': `Bearer ${sessionToken}` }
      });
      const data = await res.json();
      
      if (!res.ok) {
        // Session expired or invalid
        handleLogout();
      } else {
        setUser(data);
      }
    } catch (err) {
      console.error("Session verification deferred (offline fallback).");
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSuccess = (userData, userToken) => {
    setUser(userData);
    setToken(userToken);
    setActiveTab('chat');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setToken(null);
    setActiveTab('chat');
  };

  if (loading) {
    return (
      <div className="w-screen h-screen flex flex-col items-center justify-center bg-[#020617] text-slate-400">
        <div className="relative w-12 h-12 mb-4">
          <div className="absolute inset-0 border-4 border-indigo-500/20 rounded-full"></div>
          <div className="absolute inset-0 border-4 border-t-indigo-500 rounded-full animate-spin"></div>
        </div>
        <p className="text-xs font-semibold tracking-wider uppercase text-slate-500">
          Loading Security Vault...
        </p>
      </div>
    );
  }

  // Guard for Login page
  if (!token || !user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="w-screen h-screen flex bg-[#030712] overflow-hidden text-slate-200">
      {/* Navigation sidebar */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        user={user} 
        onLogout={handleLogout} 
      />

      {/* Primary tab-based view routing */}
      <main className="flex-1 flex flex-col overflow-hidden h-full">
        {activeTab === 'chat' && <ChatInterface token={token} user={user} />}
        {activeTab === 'filescanner' && <FileScanner />}
        {activeTab === 'playground' && <Playground token={token} />}
        {activeTab === 'dashboard' && user.role === 'admin' && <Dashboard token={token} />}
      </main>
    </div>
  );
}
