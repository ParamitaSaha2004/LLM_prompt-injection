import React from 'react';
import { 
  Shield, 
  MessageSquare, 
  Play, 
  BarChart3, 
  FileText, 
  LogOut, 
  User 
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, user, onLogout }) {
  const isAdmin = user?.role === 'admin';

  const menuItems = [
    { id: 'chat', label: 'RAG Chat', icon: MessageSquare },
    { id: 'filescanner', label: 'Static File Scanner', icon: Shield },
    { id: 'playground', label: 'Attack Playground', icon: Play },
  ];

  // Admin-only panels
  if (isAdmin) {
    menuItems.push(
      { id: 'dashboard', label: 'Security Dashboard', icon: BarChart3 }
    );
  }

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen select-none">
      {/* Brand Logo */}
      <div className="p-6 border-b border-slate-800 flex items-center gap-3">
        <div className="p-2 bg-indigo-600 rounded-lg text-white glow-primary">
          <Shield size={22} className="animate-pulse" />
        </div>
        <div>
          <h1 className="font-bold text-lg tracking-tight bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            PromptShield
          </h1>
          <span className="text-[10px] text-slate-500 font-semibold tracking-wider uppercase">
            RAG Guard System
          </span>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3.5 px-4 py-3 rounded-xl transition-all duration-200 ${
                isActive
                  ? 'bg-indigo-600/10 text-indigo-400 border-l-4 border-indigo-500 font-medium'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Icon size={18} />
              <span className="text-sm">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* User Footer Profile */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40">
        <div className="flex items-center gap-3 mb-3 px-2">
          <div className="p-2 bg-slate-800 rounded-lg text-slate-300">
            <User size={16} />
          </div>
          <div className="overflow-hidden">
            <p className="text-xs font-semibold text-slate-200 truncate">{user?.username || 'User'}</p>
            <p className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">
              {user?.role || 'Guest'}
            </p>
          </div>
        </div>
        
        <button
          onClick={onLogout}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-slate-800 text-slate-400 hover:text-red-400 hover:bg-red-500/5 hover:border-red-500/20 transition-all duration-150 text-xs font-medium"
        >
          <LogOut size={14} />
          Logout
        </button>
      </div>
    </aside>
  );
}
