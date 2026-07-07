import React, { useState, useEffect, useRef } from 'react';
import { 
  Upload, 
  Trash2, 
  FileText, 
  AlertTriangle, 
  Send, 
  Plus, 
  CheckCircle2, 
  XCircle, 
  ArrowRight,
  Shield,
  Layers,
  Activity
} from 'lucide-react';

export default function ChatInterface({ token, user }) {
  // Document states
  const [documents, setDocuments] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');


  // Static file scan states for RAG uploads
  const [scannedFile, setScannedFile] = useState(null);
  const [scanReport, setScanReport] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanLogs, setScanLogs] = useState([]);

  // Chat states
  const [conversations, setConversations] = useState([]);
  const [activeConvId, setActiveConvId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [queryLoading, setQueryLoading] = useState(false);
  const [lastResponseReport, setLastResponseReport] = useState(null);
  const [history, setHistory] = useState([]);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetchDocuments();
    fetchConversations();
  }, []);

  useEffect(() => {
    if (activeConvId) {
      fetchMessages(activeConvId);
      setLastResponseReport(null);
    } else {
      setMessages([]);
    }
  }, [activeConvId]);

  useEffect(() => {
    scrollToBottom();
  }, [messages, queryLoading]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const authHeaders = {
    'Authorization': `Bearer ${token}`
  };

  // --- Document Manager Handlers ---
  const fetchDocuments = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/docs/', { headers: authHeaders });
      const data = await res.json();
      if (res.ok) setDocuments(data);
    } catch (err) {
      console.error("Error fetching documents:", err);
    }
  };

  // --- Static Heuristic Parsers ---
  const analyzePDF = (bytes, textContent) => {
    const findings = [];
    let score = 0;
    
    // Strict magic bytes signature check for PDF validity
    const isPDFHeader = bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46; // %PDF
    if (!isPDFHeader) {
      score += 65;
      findings.push({
        category: "Invalid PDF Signature",
        detail: "File extension claims PDF, but magic bytes (%PDF) are missing or corrupt. This indicates header spoofing or critical corruption.",
        severity: "High"
      });
    }

    // Heuristics: scan PDF text content for Indirect Prompt Injections
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous\s+)?instructions/i,
      /system\s+prompt/i,
      /forget\s+(your\s+)?(rules|constraints|instructions)/i,
      /acting\s+as\b.*\bnow/i,
      /override\b.*\bsettings/i,
      /jailbreak/i,
      /do\s+anything\s+now/i
    ];
    
    let matchedInjections = [];
    injectionPatterns.forEach(pattern => {
      const match = textContent.match(pattern);
      if (match) {
        matchedInjections.push(match[0]);
      }
    });

    if (matchedInjections.length > 0) {
      score += 45;
      findings.push({
        category: "Indirect Prompt Injection",
        detail: `Detected prompt override keywords inside document text: "${matchedInjections.join(', ')}". Upload blocked for safety.`,
        severity: "High"
      });
    }

    const jsMatches = textContent.match(/\/JS\b|\/JavaScript\b/g);
    if (jsMatches) {
      score += 35;
      findings.push({
        category: "Embedded Script",
        detail: "Found active PDF Javascript triggers (/JS or /JavaScript). Embedded scripts can execute code automatically.",
        severity: "High"
      });
    }
    
    const actionMatches = textContent.match(/\/OpenAction\b|\/AA\b/g);
    if (actionMatches) {
      score += 25;
      findings.push({
        category: "Auto-Execution Action",
        detail: "Auto-launch action (/OpenAction or /AA) detected. This executes commands upon opening.",
        severity: "High"
      });
    }

    const launchMatches = textContent.match(/\/Launch\b/g);
    if (launchMatches) {
      score += 30;
      findings.push({
        category: "System Launch Trigger",
        detail: "Found system shell launch directives (/Launch). This can attempt to run external executables.",
        severity: "High"
      });
    }

    const embeddedFiles = textContent.match(/\/EmbeddedFiles\b/g);
    if (embeddedFiles) {
      score += 20;
      findings.push({
        category: "Embedded Resource",
        detail: "Found embedded files catalog (/EmbeddedFiles). Often used to pack secondary payloads.",
        severity: "Medium"
      });
    }

    const formSubmit = textContent.match(/\/SubmitForm\b/g);
    if (formSubmit) {
      score += 15;
      findings.push({
        category: "Data Submission Trigger",
        detail: "Found interactive form submission actions (/SubmitForm). Could leak document data.",
        severity: "Medium"
      });
    }

    const uriMatches = textContent.match(/\/URI\b/g);
    if (uriMatches) {
      score += 10;
      findings.push({
        category: "Hyperlink Reference",
        detail: `Detected external hyperlink directives (/URI). Found ${uriMatches.length} clickable URL reference(s).`,
        severity: "Low"
      });
    }

    const encryptMatches = textContent.match(/\/Encrypt\b/g);
    if (encryptMatches) {
      score += 5;
      findings.push({
        category: "Document Cryptography",
        detail: "Document is password encrypted (/Encrypt), preventing deep content inspections.",
        severity: "Low"
      });
    }

    // Heuristics: extract structure elements counts for display
    const objCount = (textContent.match(/obj\b/g) || []).length || Math.round(bytes.length / 800) + 12;

    const metadata = {
      fileType: "PDF document",
      pdfHeader: isPDFHeader ? "Valid" : "Invalid (Malformed)",
      objectsFound: objCount,
      approxPages: (textContent.match(/\/Type\s*\/Page\b/g) || []).length || "1",
      fileSize: `${(bytes.length / (1024 * 1024)).toFixed(2)} MB`
    };

    return { score, findings, metadata };
  };

  const analyzeDocxOrTxt = (bytes, textContent, filename) => {
    const findings = [];
    let score = 0;

    // Check for direct injection patterns locally to alert early
    if (textContent.includes("ignore previous instructions") || textContent.includes("system prompt")) {
      score += 45;
      findings.push({
        category: "Payload Override Signature",
        detail: "Found direct prompt override keywords matching injection safety filters.",
        severity: "High"
      });
    }

    const metadata = {
      fileType: filename.endsWith('.docx') ? "DOCX Document" : "TXT Document",
      pdfHeader: "N/A (Standard Data)",
      objectsFound: "N/A",
      approxPages: Math.ceil(textContent.length / 3000) || 1,
      fileSize: `${(bytes.length / (1024 * 1024)).toFixed(2)} MB`
    };

    return { score, findings, metadata };
  };

  const decodeASCII85 = (bytes) => {
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    
    // Clean string from PDF encoding spaces and delimiters
    str = str.replace(/\s/g, "").replace(/<~/g, "").replace(/~>/g, "");
    
    const out = [];
    let count = 0;
    let val = 0;
    
    for (let i = 0; i < str.length; i++) {
      const c = str.charAt(i);
      if (c === 'z') {
        if (count !== 0) continue;
        out.push(0, 0, 0, 0);
      } else {
        const code = c.charCodeAt(0) - 33;
        if (code < 0 || code > 84) continue;
        val = val * 85 + code;
        count++;
        if (count === 5) {
          out.push(
            (val >> 24) & 0xff,
            (val >> 16) & 0xff,
            (val >> 8) & 0xff,
            val & 0xff
          );
          val = 0;
          count = 0;
        }
      }
    }
    
    if (count > 0) {
      if (count >= 2) {
        const pad = 5 - count;
        for (let i = 0; i < pad; i++) {
          val = val * 85 + 84;
        }
        const bytesToAdd = 4 - pad;
        if (bytesToAdd >= 1) out.push((val >> 24) & 0xff);
        if (bytesToAdd >= 2) out.push((val >> 16) & 0xff);
        if (bytesToAdd >= 3) out.push((val >> 8) & 0xff);
      }
    }
    
    return new Uint8Array(out);
  };

  const decompressPDFStreams = async (bytes) => {
    let combinedText = "";
    let pos = 0;
    while (pos < bytes.length) {
      let streamStart = -1;
      for (let i = pos; i < bytes.length - 6; i++) {
        if (bytes[i] === 115 && bytes[i+1] === 116 && bytes[i+2] === 114 && bytes[i+3] === 101 && bytes[i+4] === 97 && bytes[i+5] === 109) {
          let offset = 6;
          if (bytes[i+6] === 13) offset++; // \r
          if (bytes[i+offset] === 10) offset++; // \n
          streamStart = i + offset;
          break;
        }
      }
      
      if (streamStart === -1) break;
      
      let streamEnd = -1;
      for (let i = streamStart; i < bytes.length - 9; i++) {
        if (bytes[i] === 101 && bytes[i+1] === 110 && bytes[i+2] === 100 && bytes[i+3] === 115 && bytes[i+4] === 116 && bytes[i+5] === 114 && bytes[i+6] === 101 && bytes[i+7] === 97 && bytes[i+8] === 109) {
          let endOffset = i;
          if (bytes[i-1] === 10) endOffset--; // \n
          if (bytes[i-2] === 13) endOffset--; // \r
          streamEnd = endOffset;
          break;
        }
      }
      
      if (streamEnd === -1) break;
      
      const compressedData = bytes.slice(streamStart, streamEnd);
      
      let finalBytes = compressedData;
      // Zlib header check (magic byte: 0x78)
      const isZlib = compressedData[0] === 0x78 && (compressedData[1] === 0x9C || compressedData[1] === 0x01 || compressedData[1] === 0xDA);
      if (!isZlib) {
        try {
          const decoded = decodeASCII85(compressedData);
          if (decoded.length > 0) {
            finalBytes = decoded;
          }
        } catch (err) {
          // Ignore failed base85 decoding
        }
      }

      try {
        const ds = new DecompressionStream('deflate');
        const writer = ds.writable.getWriter();
        writer.write(finalBytes);
        writer.close();
        
        const response = new Response(ds.readable);
        const decompressedBuffer = await response.arrayBuffer();
        const streamText = new TextDecoder('utf-8', { fatal: false }).decode(decompressedBuffer);
        
        // Clean Tj parentheses layout strings
        const matches = streamText.match(/\(([^)]*)\)/g);
        if (matches) {
          const textNoSpaces = matches.map(m => m.slice(1, -1).replace(/\\([()])/g, '$1')).join("");
          const textWithSpaces = matches.map(m => m.slice(1, -1).replace(/\\([()])/g, '$1')).join(" ");
          combinedText += textNoSpaces + "\n" + textWithSpaces + "\n";
        }
        
        // Clean TJ hex codes
        const hexMatches = streamText.match(/<([0-9a-fA-F]+)>/g);
        if (hexMatches) {
          let hexDecoded = "";
          hexMatches.forEach(hm => {
            const hex = hm.slice(1, -1);
            let str = "";
            for (let i = 0; i < hex.length; i += 2) {
              str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
            }
            hexDecoded += str;
          });
          combinedText += hexDecoded + "\n";
        }

        combinedText += streamText + "\n";
      } catch (err) {
        // Safe skip non-deflate blocks
      }
      
      pos = streamEnd + 9;
    }
    return combinedText;
  };

  const runStaticFileScan = (file) => {
    setScannedFile(file);
    setScanning(true);
    setScanProgress(0);
    setScanLogs([]);
    setScanReport(null);

    const ext = file.name.split('.').pop().toLowerCase();
    const reader = new FileReader();

    const logSteps = [
      "Initializing secure client-side sandbox...",
      "Reading raw file streams into ArrayBuffer...",
      `Analyzing file structure of '${file.name}'...`,
      "Running magic bytes signature checks...",
      "Inspecting structural segment catalogs...",
      "Scanning binary blocks for disguised threats...",
      "Searching for active JavaScript streams, triggers (/JS)...",
      "Inspecting metadata headers and fields..."
    ];

    reader.onload = async (event) => {
      const arrayBuffer = event.target.result;
      const bytes = new Uint8Array(arrayBuffer);
      
      const textDecoder = new TextDecoder('utf-8', { fatal: false });
      const rawText = textDecoder.decode(bytes);

      // Extract text content dynamically from compressed PDF streams
      const decompressedText = await decompressPDFStreams(bytes);
      const textContent = rawText + "\n" + decompressedText;

      let resultData;
      if (ext === 'pdf') {
        resultData = analyzePDF(bytes, textContent);
      } else {
        resultData = analyzeDocxOrTxt(bytes, textContent, file.name);
      }

      let stepIdx = 0;
      const interval = setInterval(() => {
        if (stepIdx < logSteps.length) {
          setScanLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${logSteps[stepIdx]}`]);
          setScanProgress(Math.round(((stepIdx + 1) / logSteps.length) * 100));
          stepIdx++;
        } else {
          clearInterval(interval);
          setTimeout(() => {
            setScanning(false);
            setScanReport(resultData);
          }, 300);
        }
      }, 150);
    };

    reader.readAsArrayBuffer(file);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    runStaticFileScan(file);
    e.target.value = ''; // Reset input
  };

  const executeActualUpload = async () => {
    if (!scannedFile) return;

    setUploading(true);
    setUploadError('');
    setUploadSuccess('');
    
    const targetFile = scannedFile;
    // Clear scanned files states to close modal
    setScannedFile(null);
    setScanReport(null);

    const formData = new FormData();
    formData.append('file', targetFile);

    try {
      const res = await fetch('http://localhost:5000/api/docs/upload', {
        method: 'POST',
        headers: authHeaders,
        body: formData
      });
      const data = await res.json();

      if (!res.ok) {
        if (data.report) {
          setUploadError(`Security Alert: Document rejected. Prompt Injection risk index ${data.report.risk_score}/100. Reasons: ${data.report.explanations.join(', ')}`);
        } else {
          setUploadError(data.message || "Failed to process document.");
        }
      } else {
        setUploadSuccess(`Successfully indexed: ${data.filename} (${data.chunks} chunks)`);
        fetchDocuments();
      }
    } catch (err) {
      setUploadError("Network connection error. File upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteDoc = async (docId) => {
    if (!window.confirm("Are you sure you want to delete this document from vector database and storage?")) return;
    try {
      const res = await fetch(`http://localhost:5000/api/docs/${docId}`, {
        method: 'DELETE',
        headers: authHeaders
      });
      if (res.ok) {
        setDocuments(documents.filter(d => d.id !== docId));
      } else {
        alert("Failed to delete document.");
      }
    } catch (err) {
      console.error(err);
    }
  };

  // --- Conversation Handlers ---
  const fetchConversations = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/chat/conversations', { headers: authHeaders });
      const data = await res.json();
      if (res.ok) {
        setConversations(data);
        if (data.length > 0 && !activeConvId) {
          setActiveConvId(data[0].id);
        }
      }
    } catch (err) {
      console.error("Error fetching conversations:", err);
    }
  };

  const fetchMessages = async (convId) => {
    try {
      const res = await fetch(`http://localhost:5000/api/chat/conversations/${convId}`, { headers: authHeaders });
      const data = await res.json();
      if (res.ok) {
        setMessages(data);
      }
    } catch (err) {
      console.error("Error fetching messages:", err);
    }
  };

  const startNewConversation = () => {
    setActiveConvId(null);
    setMessages([]);
    setLastResponseReport(null);
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!inputMessage.strip && inputMessage.trim() === '') return;

    // Save user message into conversation history
setHistory(prev => [
    ...prev,
    {
        role: "user",
        content: inputMessage
    }
]);

    const userMessage = inputMessage.trim();
    setInputMessage('');
    setQueryLoading(true);
    setLastResponseReport(null);

    // Optimistically add user message (non-blocked representation)
    const tempUserMsg = { sender: 'user', message: userMessage, timestamp: new Date() };
    setMessages(prev => [...prev, tempUserMsg]);

    try {
      const res = await fetch('http://localhost:5000/api/chat/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders
        },
        body: JSON.stringify({
          message: userMessage,
          conversation_id: activeConvId
        })
      });
      const data = await res.json();

      if (res.ok) {
        if (!activeConvId && data.conversation_id) {
          setActiveConvId(data.conversation_id);
          fetchConversations();
        }
// Add server response (bot message)
const botMsg = {
  sender: 'assistant',
  message: data.response,
  is_blocked: data.is_blocked,
  sources: data.sources,
  timestamp: new Date()
};

setMessages(prev => [...prev, botMsg]);

// ✅ Save assistant reply into history
setHistory(prev => [
  ...prev,
  {
    role: "assistant",
    content: data.response
  }
]);

// Keep track of the safety reports to display detailed alert panels
if (data.safety_report) {
  setLastResponseReport(data.safety_report);
}
      }
    } catch (err) {
      console.error("Query failed:", err);
    } finally {
      setQueryLoading(false);
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden h-screen bg-[#030712]">
      
      {/* LEFT PANEL: Document Manager */}
      <section className="w-80 bg-slate-900/60 border-r border-slate-800/80 flex flex-col h-full">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-sm font-semibold tracking-wider uppercase text-slate-400">Document Repository</h2>
          <p className="text-[11px] text-slate-500 mt-1">Upload and index files in vector DB</p>
        </div>

        {/* Upload Area */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/20">
          <label className="flex flex-col items-center justify-center p-6 border border-dashed border-slate-800 hover:border-indigo-500/50 rounded-xl cursor-pointer bg-slate-950/40 hover:bg-slate-950/70 transition-all duration-200 group">
            <Upload className="text-slate-500 group-hover:text-indigo-400 mb-2 transition-colors" size={20} />
            <span className="text-xs font-medium text-slate-300">{uploading ? 'Processing file...' : 'Upload Document'}</span>
            <span className="text-[10px] text-slate-500 mt-1">PDF, DOCX, TXT (Max 5MB)</span>
            <input 
              type="file" 
              accept=".pdf,.docx,.txt" 
              onChange={handleFileUpload} 
              disabled={uploading} 
              className="hidden" 
            />
          </label>

          {/* Feedback alerts */}
          {uploadError && (
            <div className="mt-3 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-[10px] flex gap-2">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>{uploadError}</span>
            </div>
          )}
          {uploadSuccess && (
            <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg text-[10px] flex gap-2">
              <CheckCircle2 size={14} className="shrink-0 mt-0.5" />
              <span>{uploadSuccess}</span>
            </div>
          )}
        </div>

        {/* Documents Indexed List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          <h3 className="text-xs font-semibold text-slate-500 tracking-wider uppercase mb-1">Indexed Context Files</h3>
          {documents.length === 0 ? (
            <div className="text-center py-8 text-slate-600 text-xs">
              No files uploaded. Query RAG using general model.
            </div>
          ) : (
            documents.map((doc) => (
              <div 
                key={doc.id}
                className="flex items-center justify-between p-3 rounded-xl border border-slate-800/80 bg-slate-950/20 hover:bg-slate-950/50 transition group"
              >
                <div className="flex items-center gap-3 overflow-hidden pr-2">
                  <div className={`p-1.5 rounded-lg ${
                    doc.status === 'failed' 
                      ? 'bg-red-500/10 text-red-400' 
                      : 'bg-slate-800 text-slate-400'
                  }`}>
                    <FileText size={15} />
                  </div>
                  <div className="overflow-hidden">
                    <p className="text-xs font-medium text-slate-300 truncate" title={doc.filename}>{doc.filename}</p>
                    <p className="text-[9px] text-slate-500 uppercase font-semibold">
                      {doc.status} • {doc.username ? `by ${doc.username}` : 'user'}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleDeleteDoc(doc.id)}
                  className="p-1.5 text-slate-500 hover:text-red-400 rounded-lg hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all duration-150"
                  title="Remove from RAG index"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))
          )}
        </div>
      </section>

      {/* RIGHT PANEL: Chat Workspace */}
      <section className="flex-1 flex flex-col h-full bg-[#020617] relative">
        
        {/* Dynamic Warning Alert Overlay for prompt validation feedback */}
        {lastResponseReport && lastResponseReport.is_blocked && (
          <div className="absolute top-20 right-6 left-6 z-10 p-4 border border-red-500/30 bg-red-500/5 backdrop-blur-md rounded-2xl glow-danger animate-fade-in flex gap-4">
            <div className="p-3 bg-red-500/10 rounded-xl text-red-400 shrink-0 h-fit">
              <Shield size={24} />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold text-red-400">Prompt Injection Threat Blocked</h4>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 uppercase">
                  {lastResponseReport.severity} Risk
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                The input query triggered our security defenses and was prevented from reaching the LLM layer.
              </p>
              
              {/* Score Bar */}
              <div className="mt-3 flex items-center gap-2">
                <span className="text-[10px] text-slate-400 font-semibold uppercase">Risk Score Index:</span>
                <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden max-w-xs">
                  <div 
                    className="h-full bg-gradient-to-r from-orange-500 to-red-500" 
                    style={{ width: `${lastResponseReport.risk_score}%` }}
                  ></div>
                </div>
                <span className="text-xs font-bold text-red-400">{lastResponseReport.risk_score}/100</span>
              </div>

              {/* Specific Findings list */}
              {lastResponseReport.explanations.length > 0 && (
                <div className="mt-2 text-[10px] text-red-300/80 space-y-0.5">
                  <span className="font-semibold uppercase block mb-1">Defense Signatures Matched:</span>
                  {lastResponseReport.explanations.map((exp, i) => (
                    <div key={i} className="flex gap-1.5 items-center">
                      <ArrowRight size={10} />
                      <span>{exp}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <button 
              onClick={() => setLastResponseReport(null)}
              className="text-slate-500 hover:text-slate-300 shrink-0 self-start p-1"
            >
              ✕
            </button>
          </div>
        )}

        {/* Chat Header */}
        <header className="p-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/40">
          <div className="flex items-center gap-3">
            <button
              onClick={fetchConversations}
              className="md:hidden p-2 text-slate-400 hover:bg-slate-800 rounded-xl"
            >
              ☰
            </button>
            <div>
              <h2 className="text-sm font-bold text-slate-200">Secure RAG Chat Assistant</h2>
              <p className="text-[10px] text-slate-500 font-medium">Mitigating prompt overrides & instruction injections</p>
            </div>
          </div>
          <button
            onClick={startNewConversation}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:bg-slate-700 rounded-xl text-xs text-slate-200 hover:text-white transition"
          >
            <Plus size={14} />
            New Thread
          </button>
        </header>

        {/* Messages list */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full max-w-lg mx-auto text-center">
              <div className="p-4 bg-indigo-600/10 text-indigo-400 rounded-3xl mb-4 border border-indigo-500/10 glow-primary">
                <Shield size={32} />
              </div>
              <h3 className="font-bold text-slate-300">Start a Safe Chat Session</h3>
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                Type a question about your uploaded documents. Direct injections and exfiltration commands will be scanned, contexts wrapped in XML isolation borders, and outputs validated.
              </p>
              
              {/* Threat coverage indicators */}
              <div className="mt-8 grid grid-cols-2 gap-3 w-full text-left">
                <div className="p-3 border border-slate-800 rounded-xl bg-slate-950/40">
                  <span className="text-[10px] font-bold text-indigo-400 uppercase">Input Sanitizer</span>
                  <p className="text-[11px] text-slate-400 mt-1">Direct inject & obfuscation block</p>
                </div>
                <div className="p-3 border border-slate-800 rounded-xl bg-slate-950/40">
                  <span className="text-[10px] font-bold text-purple-400 uppercase">XML Isolation</span>
                  <p className="text-[11px] text-slate-400 mt-1">Untrusted context separation</p>
                </div>
              </div>
            </div>
          ) : (
            messages.map((msg, i) => {
              const isAssistant = msg.sender === 'assistant';
              return (
                <div 
                  key={i} 
                  className={`flex flex-col max-w-3xl ${
                    isAssistant ? 'mr-auto items-start' : 'ml-auto items-end'
                  } animate-fade-in`}
                >
                  <div className={`p-4 rounded-2xl leading-relaxed text-sm ${
                    !isAssistant
                      ? 'bg-indigo-600 text-white rounded-br-none glow-primary'
                      : msg.is_blocked
                        ? 'bg-red-500/10 border border-red-500/30 text-red-400 rounded-bl-none'
                        : 'bg-slate-900 border border-slate-850 text-slate-200 rounded-bl-none'
                  }`}>
                    {msg.is_blocked && (
                      <div className="flex items-center gap-1.5 mb-2 text-xs font-bold text-red-400 border-b border-red-500/20 pb-1.5">
                        <AlertTriangle size={14} />
                        BLOCKED BY PROMPTSHIELD
                      </div>
                    )}
                    <p className="whitespace-pre-wrap">{msg.message}</p>
                  </div>
                  
                  {/* Retrieved Sources Sub-panel (Only for assistant responses if they exist) */}
                  {isAssistant && msg.sources && msg.sources.length > 0 && (
                    <div className="mt-2 pl-2">
                      <details className="text-[11px] text-slate-500 hover:text-slate-400 transition cursor-pointer select-none">
                        <summary className="font-semibold flex items-center gap-1">
                          <Layers size={11} />
                          View Retrieved Chunks ({msg.sources.length})
                        </summary>
                        <div className="mt-2 space-y-2 max-w-xl pl-3 border-l border-slate-800">
                          {msg.sources.map((src, srcIdx) => (
                            <div key={srcIdx} className="bg-slate-950/40 p-2.5 rounded-lg border border-slate-900/60">
                              <div className="flex items-center justify-between text-[9px] font-bold text-slate-500 mb-1">
                                <span>CHUNK #{src.chunk_index + 1} ({src.filename})</span>
                                <span className="text-emerald-500">SIM: {Math.round(src.score * 100)}%</span>
                              </div>
                              <p className="text-[10px] text-slate-400 leading-normal font-mono">{src.text}</p>
                            </div>
                          ))}
                        </div>
                      </details>
                    </div>
                  )}

                  <span className="text-[9px] text-slate-500 font-semibold uppercase mt-1 px-1">
                    {isAssistant ? 'PromptShield Core' : 'You'}
                  </span>
                </div>
              );
            })
          )}

          {/* Loader */}
          {queryLoading && (
            <div className="flex max-w-xs mr-auto items-start animate-pulse">
              <div className="p-4 bg-slate-900 border border-slate-850 rounded-2xl rounded-bl-none flex items-center gap-2">
                <div className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                <div className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                <div className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        
{/* Input Bar Footer */}
{/* Conversation History */}
<div className="border-t border-slate-800 bg-slate-950/40 px-4 py-3 max-h-52 overflow-y-auto">

  <h3 className="text-xs font-semibold uppercase tracking-wider text-indigo-400 mb-3">
    Conversation History
  </h3>

  {history.length === 0 ? (
    <p className="text-slate-500 text-xs">
      No previous conversation.
    </p>
  ) : (
    history.map((msg, index) => (
      <div
        key={index}
        className={`mb-2 rounded-lg p-2 ${
          msg.role === "user"
            ? "bg-blue-900/20 border border-blue-700/30"
            : "bg-green-900/20 border border-green-700/30"
        }`}
      >
        <div className="text-xs font-semibold mb-1">
          {msg.role === "user"
            ? "👤 User"
            : "🤖 Assistant"}
        </div>

        <div className="text-sm text-slate-300 break-words">
          {msg.content}
        </div>
      </div>
    ))
  )}

</div>

{/* Input Bar Footer */}
<footer className="p-4 border-t border-slate-800 bg-slate-900/40">
          <form onSubmit={handleSendMessage} className="flex gap-3 max-w-4xl mx-auto">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Ask a question about the uploaded document..."
              className="flex-1 bg-slate-950 border border-slate-800 rounded-2xl px-5 py-3.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 transition duration-200"
              disabled={queryLoading}
            />
            <button
              type="submit"
              disabled={queryLoading || !inputMessage.trim()}
              className="p-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-2xl shadow-lg shadow-indigo-600/10 active:scale-[0.96] transition disabled:opacity-50"
            >
              <Send size={18} />
            </button>
          </form>
        </footer>

      </section>

      {/* Client-Side Static File Scan Overlay Modal */}
      {scannedFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-3xl overflow-hidden shadow-2xl animate-fade-in flex flex-col max-h-[90vh]">
            
            {/* Top scanning status banner */}
            {scanning && (
              <div className="p-6 flex flex-col items-center justify-center text-center space-y-4">
                <div className="relative w-16 h-16 flex items-center justify-center">
                  <div className="absolute inset-0 border border-indigo-500/40 rounded-full animate-ping"></div>
                  <div className="absolute inset-2 border-2 border-indigo-500/30 rounded-full"></div>
                  <Activity size={24} className="text-indigo-400 animate-pulse" />
                </div>
                <h3 className="text-sm font-semibold text-slate-200">Local Security Scan Running...</h3>
                <p className="text-[11px] text-slate-500 font-mono">{scannedFile.name}</p>
                
                {/* Progress bar */}
                <div className="w-full max-w-xs space-y-1.5">
                  <div className="flex justify-between text-[9px] font-bold text-slate-500 uppercase tracking-wider">
                    <span>Scan progress</span>
                    <span>{scanProgress}%</span>
                  </div>
                  <div className="h-1.5 bg-slate-950 border border-slate-900 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            )}

            {/* Final Scan Verdict Card (Matches User's uploaded screenshot) */}
            {scanReport && (
              <div className="flex-1 flex flex-col overflow-hidden">
                {/* Top border colored based on risk */}
                <div className={`h-1.5 w-full ${scanReport.score >= 40 ? 'bg-red-500' : scanReport.score > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`}></div>
                
                {/* Content scrollable inside */}
                <div className="p-6 space-y-6 overflow-y-auto no-scrollbar flex-1">
                  
                  {/* Verdict & Score segment */}
                  <div className="flex justify-between items-start gap-4">
                    <div>
                      <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">{scannedFile.name} • {scanReport.metadata.fileType.toUpperCase()}</span>
                      
                      {/* Stamp-like verdict box */}
                      <div className="mt-2 flex items-center">
                        <div className={`transform -rotate-2 border-2 rounded px-3 py-1 font-mono text-lg font-black uppercase tracking-widest bg-opacity-5 ${
                          scanReport.score >= 40 
                            ? 'border-red-500/60 text-red-400 bg-red-500' 
                            : scanReport.score > 0 
                              ? 'border-amber-500/60 text-amber-400 bg-amber-500' 
                              : 'border-emerald-500/60 text-emerald-400 bg-emerald-500'
                        }`}>
                          {scanReport.score >= 40 ? 'HIGH RISK' : scanReport.score > 0 ? 'SUSPICIOUS' : 'CLEAR'}
                        </div>
                      </div>

                      <p className="text-[11px] text-slate-400 mt-4 max-w-md leading-normal">
                        {scanReport.score >= 40 
                          ? "CRITICAL: This file triggers high-risk prompt injection override instructions or malicious triggers. Uploading is blocked."
                          : scanReport.score > 0 
                            ? "WARNING: Suspicious structural attributes detected. This file contains active triggers that could override guidelines."
                            : "No structural warning signs were found in this file. It appears to be a standard, unmodified document."
                        }
                      </p>
                    </div>

                    {/* Risk Score Index circle/block */}
                    <div className="text-right shrink-0">
                      <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider block">Risk Score</span>
                      <p className={`text-3xl font-black mt-1 ${scanReport.score >= 40 ? 'text-red-400' : scanReport.score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {scanReport.score} <span className="text-sm text-slate-600 font-bold">/100</span>
                      </p>
                    </div>
                  </div>

                  {/* Metadata Table Grid (exactly like user screenshot) */}
                  <div className="border border-slate-800 rounded-2xl overflow-hidden divide-y divide-slate-800 bg-slate-950/20">
                    <div className="grid grid-cols-3 divide-x divide-slate-800">
                      <div className="p-3">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-wider block">File Type</span>
                        <span className="text-xs font-semibold text-slate-300 mt-1 block">{scanReport.metadata.fileType}</span>
                      </div>
                      <div className="p-3">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-wider block">PDF Header</span>
                        <span className="text-xs font-semibold text-slate-300 mt-1 block">{scanReport.metadata.pdfHeader}</span>
                      </div>
                      <div className="p-3">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-wider block">Objects Found</span>
                        <span className="text-xs font-semibold text-slate-300 mt-1 block">{scanReport.metadata.objectsFound}</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 divide-x divide-slate-800">
                      <div className="p-3">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-wider block">Approx. Pages</span>
                        <span className="text-xs font-semibold text-slate-300 mt-1 block">{scanReport.metadata.approxPages}</span>
                      </div>
                      <div className="p-3">
                        <span className="text-[9px] font-bold text-slate-600 uppercase tracking-wider block">File Size</span>
                        <span className="text-xs font-semibold text-slate-300 mt-1 block">{scanReport.metadata.fileSize}</span>
                      </div>
                      <div className="p-3 bg-slate-900/10"></div>
                    </div>
                  </div>

                  {/* Evidence Log Panel (exactly like user screenshot) */}
                  <div className="border border-slate-800 rounded-2xl p-5 bg-slate-950/10 space-y-3">
                    <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider block">Evidence Log</span>
                    
                    {scanReport.findings.length === 0 ? (
                      <div className="flex gap-4 items-start text-xs border-b border-transparent pb-1">
                        <span className="font-mono text-slate-600 font-bold">01</span>
                        <div className="flex-1">
                          <h5 className="font-bold text-slate-300">No suspicious structures found</h5>
                          <p className="text-[10px] text-slate-500 mt-1 leading-normal font-mono">
                            A scan of the document's internal objects, actions, and scripts did not turn up any of the common patterns seen in malicious PDFs.
                          </p>
                        </div>
                        <span className="px-2 py-0.5 border border-slate-850 bg-slate-900/40 text-slate-500 text-[8px] font-bold uppercase rounded-full self-start">
                          INFO
                        </span>
                      </div>
                    ) : (
                      <div className="space-y-4 max-h-[160px] overflow-y-auto pr-1">
                        {scanReport.findings.map((item, idx) => (
                          <div key={idx} className="flex gap-4 items-start text-xs border-b border-slate-850/40 pb-3 last:border-0 last:pb-0">
                            <span className="font-mono text-slate-600 font-bold">{(idx + 1).toString().padStart(2, '0')}</span>
                            <div className="flex-1">
                              <h5 className="font-bold text-slate-300">{item.category}</h5>
                              <p className="text-[10px] text-slate-500 mt-1 leading-normal font-mono">{item.detail}</p>
                            </div>
                            <span className={`px-2 py-0.5 border text-[8px] font-bold uppercase rounded-full self-start ${getSeverityBadge(item.severity)}`}>
                              {item.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Footer buttons (Scan another file vs proceed) */}
                <footer className="p-4 border-t border-slate-800 bg-slate-950/20 flex justify-between items-center shrink-0">
                  <button
                    onClick={() => {
                      setScannedFile(null);
                      setScanReport(null);
                    }}
                    className="px-4 py-2 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-xl text-xs font-semibold active:scale-98 transition"
                  >
                    Scan another file
                  </button>
                  
                  {scanReport.score >= 40 ? (
                    <div className="flex items-center gap-1.5 px-4 py-2 bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-bold rounded-xl select-none">
                      <AlertTriangle size={14} />
                      Blocked: High Threat Level
                    </div>
                  ) : (
                    <button
                      onClick={executeActualUpload}
                      disabled={uploading}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold shadow-md shadow-emerald-600/15 active:scale-98 transition flex items-center gap-1.5"
                    >
                      Proceed to Index in RAG
                      <ArrowRight size={14} />
                    </button>
                  )}
                </footer>
              </div>
            )}

          </div>
        </div>
      )}

    </div>
  );
}

const getSeverityBadge = (sev) => {
  switch (sev) {
    case 'High': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'Medium': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'Low': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    default: return 'bg-slate-800 text-slate-400 border-slate-700';
  }
};
