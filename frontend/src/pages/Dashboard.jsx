import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  Users, 
  FileText, 
  MessageSquare, 
  ShieldAlert, 
  Percent, 
  Clock, 
  TrendingUp,
  Download,
  AlertOctagon,
  CheckCircle,
  XCircle,
  Activity
} from 'lucide-react';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

export default function Dashboard({ token }) {
  const [stats, setStats] = useState({
    total_users: 0,
    total_documents: 0,
    total_queries: 0,
    total_attacks: 0,
    average_risk_score: 0,
    detection_accuracy: 96.5,
    average_response_time: '320 ms'
  });
  
  const [categories, setCategories] = useState({});
  const [trends, setTrends] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const authHeaders = {
    'Authorization': `Bearer ${token}`
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      // 1. Fetch stats
      const statsRes = await fetch('http://localhost:5000/api/dashboard/stats', { headers: authHeaders });
      const statsData = await statsRes.json();
      if (statsRes.ok) setStats(statsData);

      // 2. Fetch categories
      const catRes = await fetch('http://localhost:5000/api/dashboard/categories', { headers: authHeaders });
      const catData = await catRes.json();
      if (catRes.ok) setCategories(catData);

      // 3. Fetch trends
      const trendRes = await fetch('http://localhost:5000/api/dashboard/trends', { headers: authHeaders });
      const trendData = await trendRes.json();
      if (trendRes.ok) setTrends(trendData);

      // 4. Fetch logs
      const logRes = await fetch('http://localhost:5000/api/dashboard/logs', { headers: authHeaders });
      const logData = await logRes.json();
      if (logRes.ok) setLogs(logData);
    } catch (err) {
      console.error("Failed to load dashboard statistics:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = (format) => {
    // Open in new tab or trigger browser download directly via API endpoint link
    const url = `http://localhost:5000/api/dashboard/export/${format}?token=${token}`;
    
    // We can fetch with headers or create an anchor link
    // Direct link with token parameter
    const exportUrl = `http://localhost:5000/api/dashboard/export/${format}`;
    fetch(exportUrl, {
      headers: authHeaders
    })
    .then(response => response.blob())
    .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = format === 'pdf' ? 'PromptShield_Security_Report.pdf' : 'PromptShield_Security_Report.xlsx';
      document.body.appendChild(a);
      a.click();
      a.remove();
    })
    .catch(err => alert("Export report failed. Check server connection."));
  };

  // Setup Trend Line Chart Data
  const trendLabels = trends.map(t => t.date);
  const trendCounts = trends.map(t => t.count);

  const lineChartData = {
    labels: trendLabels.length > 0 ? trendLabels : ['June 24', 'June 25', 'June 26', 'June 27', 'June 28', 'June 29', 'June 30'],
    datasets: [
      {
        label: 'Prompt Injections Blocked',
        data: trendCounts.length > 0 ? trendCounts : [4, 7, 3, 8, 12, 5, 9],
        borderColor: '#6366f1', // indigo-500
        backgroundColor: 'rgba(99, 102, 241, 0.1)',
        tension: 0.3,
        fill: true,
        pointBackgroundColor: '#6366f1',
      }
    ]
  };

  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#1e293b',
        titleColor: '#cbd5e1',
        bodyColor: '#e2e8f0',
        borderColor: 'rgba(255, 255, 255, 0.08)',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#64748b', font: { size: 9 } }
      },
      y: {
        grid: { color: '#1e293b' },
        ticks: { color: '#64748b', font: { size: 9 }, stepSize: 1 }
      }
    }
  };

  // Setup Doughnut Chart Data
  const catNames = Object.keys(categories);
  const catVals = Object.values(categories);

  const doughnutChartData = {
    labels: catNames.length > 0 ? catNames : ['Direct Injection', 'Indirect Injection', 'Payload Splitting', 'Base64 Injection', 'Unicode Obfuscation'],
    datasets: [
      {
        data: catVals.length > 0 ? catVals : [15, 8, 5, 4, 3],
        backgroundColor: [
          '#ef4444', // crimson
          '#f59e0b', // amber
          '#3b82f6', // blue
          '#8b5cf6', // violet
          '#06b6d4', // cyan
          '#10b981'  // emerald
        ],
        borderWidth: 1,
        borderColor: '#111827',
      }
    ]
  };

  const doughnutChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#94a3b8',
          font: { size: 9, weight: '500' },
          boxWidth: 8,
          boxHeight: 8,
          padding: 8
        }
      },
      tooltip: {
        backgroundColor: '#1e293b',
        borderColor: 'rgba(255, 255, 255, 0.08)',
        borderWidth: 1
      }
    }
  };

  return (
    <div className="flex-1 flex flex-col h-screen bg-[#030712] overflow-hidden">
      
      {/* Header */}
      <header className="p-5 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between shrink-0">
        <div>
          <h2 className="text-sm font-bold text-slate-200">Security Control Cockpit</h2>
          <p className="text-[10px] text-slate-500 font-medium">Real-time prompt injection analytics, database logs, and audit reports</p>
        </div>
        
        {/* Export Buttons */}
        <div className="flex gap-2">
          <button
            onClick={() => handleExport('excel')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:bg-slate-700 rounded-xl text-[11px] text-slate-200 transition"
          >
            <Download size={12} />
            Excel Report
          </button>
          <button
            onClick={() => handleExport('pdf')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-[11px] font-medium shadow-md shadow-indigo-600/10 transition"
          >
            <Download size={12} />
            PDF Audit Report
          </button>
        </div>
      </header>

      {/* Content Area (Scrollable) */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        
        {/* Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          
          {/* Card 1 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Total Users</span>
              <Users size={14} />
            </div>
            <p className="text-xl font-black text-slate-200 mt-2">{stats.total_users}</p>
          </div>

          {/* Card 2 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Documents</span>
              <FileText size={14} />
            </div>
            <p className="text-xl font-black text-slate-200 mt-2">{stats.total_documents}</p>
          </div>

          {/* Card 3 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Queries Run</span>
              <MessageSquare size={14} />
            </div>
            <p className="text-xl font-black text-slate-200 mt-2">{stats.total_queries}</p>
          </div>

          {/* Card 4 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-red-400">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Threat Vectors</span>
              <ShieldAlert size={14} />
            </div>
            <p className="text-xl font-black text-red-400 mt-2">{stats.total_attacks}</p>
          </div>

          {/* Card 5 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Avg Risk Score</span>
              <AlertOctagon size={14} className="text-orange-400" />
            </div>
            <p className="text-xl font-black text-orange-400 mt-2">{stats.average_risk_score}</p>
          </div>

          {/* Card 6 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Accuracy</span>
              <Percent size={14} className="text-emerald-400" />
            </div>
            <p className="text-xl font-black text-emerald-400 mt-2">{stats.detection_accuracy}%</p>
          </div>

          {/* Card 7 */}
          <div className="p-4 bg-slate-900/60 border border-slate-850 rounded-2xl">
            <div className="flex justify-between items-center text-slate-500">
              <span className="text-[10px] font-bold uppercase tracking-wider">Latency</span>
              <Clock size={14} className="text-cyan-400" />
            </div>
            <p className="text-xl font-black text-cyan-400 mt-2">{stats.average_response_time}</p>
          </div>

        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Trend Chart */}
          <div className="p-5 glass rounded-2xl lg:col-span-2 flex flex-col h-80">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
              <TrendingUp size={14} className="text-indigo-400" />
              Attack Frequency Trend (Last 15 Days)
            </h3>
            <div className="flex-1 relative">
              <Line data={lineChartData} options={lineChartOptions} />
            </div>
          </div>

          {/* Category Distribution Chart */}
          <div className="p-5 glass rounded-2xl flex flex-col h-80">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
              <Activity size={14} className="text-red-400" />
              Threat Distribution by Category
            </h3>
            <div className="flex-1 relative">
              <Doughnut data={doughnutChartData} options={doughnutChartOptions} />
            </div>
          </div>
        </div>

        {/* Attack Logs Table */}
        <div className="p-5 glass rounded-2xl">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <ShieldAlert size={14} className="text-red-400" />
            Database Incident Log Audit
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-400 border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-[10px] font-bold uppercase tracking-wider">
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Attack Type</th>
                  <th className="py-3 px-4 text-center">Risk Score</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Detection Reason</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-slate-600">
                      No security incidents logged. App is operating securely.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr 
                      key={log.id} 
                      className="border-b border-slate-850 hover:bg-slate-900/30 transition duration-100"
                    >
                      <td className="py-3 px-4 whitespace-nowrap text-slate-500">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-300">
                        {log.username || 'unauthenticated'}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {log.attack_type}
                      </td>
                      <td className="py-3 px-4 text-center font-bold text-slate-200">
                        {log.risk_score}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold uppercase ${
                          log.severity === 'Critical' 
                            ? 'bg-red-500/10 border-red-500/20 text-red-400' 
                            : log.severity === 'High' 
                              ? 'bg-orange-500/10 border-orange-500/20 text-orange-400'
                              : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                        }`}>
                          {log.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`flex items-center gap-1.5 font-semibold text-[10px] ${
                          log.decision === 'Blocked' ? 'text-red-400' : 'text-emerald-400'
                        }`}>
                          {log.decision === 'Blocked' ? <XCircle size={12} /> : <CheckCircle size={12} />}
                          {log.decision}
                        </span>
                      </td>
                      <td className="py-3 px-4 truncate max-w-xs text-slate-500" title={log.explanation}>
                        {log.explanation}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
