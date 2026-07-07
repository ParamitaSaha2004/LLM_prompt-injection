import React, { useState, useEffect } from 'react';
import { 
  Play, 
  HelpCircle, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle,
  ArrowRight,
  Flame,
  Binary
} from 'lucide-react';

export default function Playground({ token }) {
  const [presets, setPresets] = useState([]);
  const [selectedAttackType, setSelectedAttackType] = useState('Direct Prompt Injection');
  const [payload, setPayload] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const attackTypes = [
    'Direct Prompt Injection',
    'Indirect Prompt Injection',
    'RAG Poisoning',
    'Payload Splitting',
    'Base64 Injection',
    'Multilingual Injection',
    'Unicode/Obfuscated prompts',
    'Adversarial Suffix',
    'Hidden Document Instructions'
  ];

  useEffect(() => {
    fetchPresets();
  }, []);

  const fetchPresets = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/playground/presets');
      const data = await res.json();
      if (res.ok) {
        setPresets(data);
        if (data.length > 0) {
          loadPreset(data[0]);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadPreset = (preset) => {
    setPayload(preset.payload);
    setSelectedAttackType(preset.type);
    setResult(null);
    setError('');
  };

  const handleSimulate = async (e) => {
    e.preventDefault();
    if (!payload.trim()) return;

    setLoading(true);
    setResult(null);
    setError('');

    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const res = await fetch('http://localhost:5000/api/playground/simulate', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          attack_type: selectedAttackType,
          payload: payload
        })
      });
      const data = await res.json();

      if (res.ok) {
        setResult(data);
      } else {
        setError(data.message || 'Simulation execution failed.');
      }
    } catch (err) {
      setError('Connection to security engine timed out.');
    } finally {
      setLoading(false);
    }
  };

  // Helper colors based on risk severity
  const getSeverityStyles = (severity) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'High': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'Medium': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default: return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    }
  };

  return (
    <div className="flex-1 flex flex-col h-screen bg-[#030712] overflow-hidden">
      
      {/* Header */}
      <header className="p-5 border-b border-slate-800 bg-slate-900/40 shrink-0">
        <h2 className="text-sm font-bold text-slate-200">Attack Playground</h2>
        <p className="text-[10px] text-slate-500 font-medium">Safe environment to test prompt injection payloads and evaluate detectors</p>
      </header>

      {/* Main Workspace Scrollable */}
      <div className="flex-1 overflow-y-auto p-6 flex flex-col lg:flex-row gap-6">
        
        {/* LEFT WORKSPACE: Presets and Sandbox Input */}
        <section className="flex-1 space-y-6 max-w-xl">
          
          {/* Preset templates */}
          <div className="p-5 glass rounded-2xl">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Binary size={14} className="text-indigo-400" />
              Presets Attack Payloads
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {presets.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => loadPreset(preset)}
                  className="px-3 py-2 bg-slate-950 border border-slate-850 hover:bg-slate-800 hover:border-slate-700 rounded-xl text-[11px] font-medium text-slate-400 hover:text-slate-200 text-left truncate transition-all"
                  title={preset.payload}
                >
                  {preset.name}
                </button>
              ))}
            </div>
          </div>

          {/* Sandbox form */}
          <div className="p-5 glass rounded-2xl">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
              <Flame size={14} className="text-orange-400" />
              Security Sandbox Simulation
            </h3>
            
            <form onSubmit={handleSimulate} className="space-y-4">
              {/* Type Select */}
              <div>
                <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Attack Category</label>
                <select
                  value={selectedAttackType}
                  onChange={(e) => setSelectedAttackType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/25"
                >
                  {attackTypes.map((type, idx) => (
                    <option key={idx} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              {/* Payload input */}
              <div>
                <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wider">Payload Input</label>
                <textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  placeholder="Enter custom prompt injection string..."
                  rows={6}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-300 placeholder-slate-750 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 resize-none leading-relaxed"
                  required
                />
              </div>

              {/* Run button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500 text-white py-2.5 rounded-xl font-medium shadow-md shadow-red-500/10 active:scale-[0.98] transition flex items-center justify-center gap-2 text-xs"
              >
                <Play size={14} />
                {loading ? 'Analyzing Threat Vector...' : 'Execute Simulation Scan'}
              </button>
            </form>
          </div>
        </section>

        {/* RIGHT WORKSPACE: Threat Report Analyzer */}
        <section className="flex-1 max-w-xl">
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-2xl text-xs flex gap-2">
              <ShieldAlert size={16} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {!result && !error && (
            <div className="h-full min-h-[300px] border border-dashed border-slate-800 rounded-2xl flex flex-col items-center justify-center text-center p-8 bg-slate-900/10">
              <HelpCircle size={32} className="text-slate-600 mb-3" />
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">No Report Generated</h4>
              <p className="text-[11px] text-slate-600 mt-2 max-w-xs leading-normal">
                Load a preset payload or draft a custom attack, select the target classifier, and run the simulator to view safety analysis.
              </p>
            </div>
          )}

          {result && (
            <div className="p-5 glass rounded-2xl glow-primary space-y-5 animate-fade-in">
              {/* Header result */}
              <div className="flex items-center justify-between border-b border-slate-850 pb-4">
                <div>
                  <h3 className="font-bold text-sm text-slate-200">Threat Assessment Scan</h3>
                  <span className="text-[9px] font-mono text-slate-500">{result.attack_type}</span>
                </div>
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-bold ${
                  result.blocked
                    ? 'bg-red-500/10 border-red-500/25 text-red-400'
                    : 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400'
                }`}>
                  {result.blocked ? <ShieldAlert size={14} /> : <ShieldCheck size={14} />}
                  {result.blocked ? 'BLOCKED' : 'ALLOWED'}
                </div>
              </div>

              {/* Score index */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-xl">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Risk Score Index</span>
                  <p className={`text-2xl font-black mt-1 ${result.blocked ? 'text-red-400' : 'text-emerald-400'}`}>
                    {result.risk_score} <span className="text-xs text-slate-600 font-medium">/ 100</span>
                  </p>
                </div>
                <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-xl">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Threat Level</span>
                  <div className={`mt-2.5 px-2 py-0.5 rounded-full border text-[10px] font-bold text-center w-fit uppercase ${getSeverityStyles(result.detector_result.severity)}`}>
                    {result.detector_result.severity}
                  </div>
                </div>
              </div>

              {/* Progress gauge bar */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-[10px] text-slate-500 font-semibold uppercase">
                  <span>Detection Severity Meter</span>
                  <span>{result.risk_score >= 80 ? 'Critical Severity' : result.risk_score >= 50 ? 'High' : result.risk_score >= 25 ? 'Medium' : 'Negligible'}</span>
                </div>
                <div className="h-2.5 bg-slate-950 border border-slate-900 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${
                      result.risk_score >= 80 
                        ? 'bg-red-500 glow-danger' 
                        : result.risk_score >= 50 
                          ? 'bg-orange-500' 
                          : result.risk_score >= 25 
                            ? 'bg-amber-500' 
                            : 'bg-emerald-500'
                    }`} 
                    style={{ width: `${result.risk_score}%` }}
                  ></div>
                </div>
              </div>

              {/* Explanations findings list */}
              <div className="bg-slate-950/50 p-4 border border-slate-900 rounded-xl space-y-2">
                <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Matched Security Audits</h4>
                {result.detector_result.explanations.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No injection signatures matched. This prompt complies with general safety rules.</p>
                ) : (
                  <div className="space-y-1.5">
                    {result.detector_result.explanations.map((exp, idx) => (
                      <div key={idx} className="flex gap-2 items-start text-xs text-slate-300">
                        <ArrowRight size={12} className="text-red-400 shrink-0 mt-0.5" />
                        <span>{exp}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Payload Breakdown */}
              <div>
                <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Payload Echo Preview</h4>
                <div className="p-3 bg-slate-950 border border-slate-900 rounded-xl text-[11px] font-mono text-slate-400 max-h-[120px] overflow-y-auto whitespace-pre-wrap leading-normal break-all">
                  {result.input}
                </div>
              </div>

            </div>
          )}
        </section>

      </div>
    </div>
  );
}
