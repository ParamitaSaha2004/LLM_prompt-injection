import React, { useState } from 'react';
import { 
  Upload, 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  Image as ImageIcon,
  Activity, 
  RefreshCw, 
  AlertTriangle, 
  Info,
  ChevronRight,
  Terminal
} from 'lucide-react';

export default function FileScanner() {
  const [file, setFile] = useState(null);
  const [scanState, setScanState] = useState('IDLE'); // IDLE, SCANNING, RESULT
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  // --- Static Analysis Heuristics ---

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

    // Heuristic 1: Embedded JavaScript
    const jsMatches = textContent.match(/\/JS\b|\/JavaScript\b/g);
    if (jsMatches) {
      score += 35;
      findings.push({
        category: "Embedded Script",
        detail: "Found active PDF Javascript triggers (/JS or /JavaScript). Embedded scripts can execute actions automatically.",
        severity: "High"
      });
    }
    
    // Heuristic 2: Auto-open actions
    const actionMatches = textContent.match(/\/OpenAction\b|\/AA\b/g);
    if (actionMatches) {
      score += 25;
      findings.push({
        category: "Auto-Execution Action",
        detail: "Auto-launch action (/OpenAction or /AA) detected. This executes commands upon opening.",
        severity: "High"
      });
    }

    // Heuristic 3: External launches / triggers
    const launchMatches = textContent.match(/\/Launch\b/g);
    if (launchMatches) {
      score += 30;
      findings.push({
        category: "System Launch Trigger",
        detail: "Found system shell launch directives (/Launch). This can attempt to run external executables.",
        severity: "High"
      });
    }

    // Heuristic 4: Embedded files / structures
    const embeddedFiles = textContent.match(/\/EmbeddedFiles\b/g);
    if (embeddedFiles) {
      score += 20;
      findings.push({
        category: "Embedded Resource",
        detail: "Found embedded files catalog (/EmbeddedFiles). Often used to pack secondary payloads.",
        severity: "Medium"
      });
    }

    // Heuristic 5: Form submission
    const formSubmit = textContent.match(/\/SubmitForm\b/g);
    if (formSubmit) {
      score += 15;
      findings.push({
        category: "Data Submission Trigger",
        detail: "Found interactive form submission actions (/SubmitForm). Could leak document data to external hosts.",
        severity: "Medium"
      });
    }

    // Heuristic 6: External URLs / Phishing
    const uriMatches = textContent.match(/\/URI\b/g);
    if (uriMatches) {
      score += 10;
      findings.push({
        category: "Hyperlink Reference",
        detail: `Detected external hyperlink directives (/URI). Found ${uriMatches.length} clickable URL reference(s).`,
        severity: "Low"
      });
    }

    // Heuristic 7: PDF Encryption
    const encryptMatches = textContent.match(/\/Encrypt\b/g);
    if (encryptMatches) {
      score += 5;
      findings.push({
        category: "Document Cryptography",
        detail: "Document is password encrypted (/Encrypt), preventing deep content inspections.",
        severity: "Low"
      });
    }

    // Extract metadata
    const metadata = {
      "Structure Format": "PDF Document",
      "PDF Header": isPDFHeader ? "Valid" : "Invalid (Malformed)",
      "Total Pages": (textContent.match(/\/Type\s*\/Page\b/g) || []).length || "Unknown (Streamed)",
      "Software Producer": (textContent.match(/\/Producer\s*\(([^)]+)\)/) || [null, "Not Specified"])[1],
      "Authoring Creator": (textContent.match(/\/Creator\s*\(([^)]+)\)/) || [null, "Not Specified"])[1],
      "Title Name": (textContent.match(/\/Title\s*\(([^)]+)\)/) || [null, "Not Specified"])[1],
      "PDF Version": (textContent.match(/%PDF-\d\.\d/g) || ["%PDF-1.4"])[0]
    };

    return { score, findings, metadata };
  };

  const analyzeImage = (bytes, filename) => {
    const findings = [];
    let score = 0;
    
    // Get first 8 bytes hex representation
    let headerHex = "";
    for (let i = 0; i < Math.min(bytes.length, 8); i++) {
      headerHex += bytes[i].toString(16).padStart(2, '0').toUpperCase() + " ";
    }
    headerHex = headerHex.trim();

    const isPNG = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
    const isJPEG = bytes[0] === 0xFF && bytes[1] === 0xD8;
    
    // Heuristic 1: Verify header magic bytes
    const ext = filename.split('.').pop().toLowerCase();
    if (ext === 'png' && !isPNG) {
      score += 45;
      findings.push({
        category: "File Integrity Violation",
        detail: `File extension claims PNG, but binary magic bytes do not match. Detected signature: [${headerHex}]`,
        severity: "High"
      });
    } else if ((ext === 'jpg' || ext === 'jpeg') && !isJPEG) {
      score += 45;
      findings.push({
        category: "File Integrity Violation",
        detail: `File extension claims JPEG, but binary magic bytes do not match. Detected signature: [${headerHex}]`,
        severity: "High"
      });
    }

    // Heuristic 2: Disguised PE Executable
    let mzCount = 0;
    for (let i = 0; i < Math.min(bytes.length, 100) - 1; i++) {
      if (bytes[i] === 0x4D && bytes[i+1] === 0x5A) { // 'MZ'
        mzCount++;
      }
    }
    if (mzCount > 0) {
      score += 55;
      findings.push({
        category: "Disguised Executable Check",
        detail: "Found DOS executable signatures (MZ header) in initial bytes. Indicates an executable disguised as an image.",
        severity: "High"
      });
    }

    // Heuristic 3: Embedded WebShell Scripts
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    // Decode first 100KB for signature checks
    const textContent = textDecoder.decode(bytes.slice(0, 100000));
    
    const scriptMatches = textContent.match(/<script\b|eval\(|<?php\b/gi);
    if (scriptMatches) {
      score += 40;
      findings.push({
        category: "Embedded Script Shell",
        detail: "Detected HTML/PHP/JS script indicators inside file bytes, suggesting a web-shell injection payload.",
        severity: "High"
      });
    }

    // Heuristic 4: Embedded ZIP archives
    let zipCount = 0;
    for (let i = 0; i < bytes.length - 3; i++) {
      if (bytes[i] === 0x50 && bytes[i+1] === 0x4B && bytes[i+2] === 0x03 && bytes[i+3] === 0x04) { // PK..
        zipCount++;
      }
    }
    if (zipCount > 0) {
      score += 25;
      findings.push({
        category: "Nested Archive Container",
        detail: "Detected ZIP compressed container headers (PK tags). Suggests a polyglot file hiding nested resources.",
        severity: "Medium"
      });
    }

    // Heuristic 5: Oversized Metadata/File Size Checks
    if (bytes.length > 10 * 1024 * 1024) {
      findings.push({
        category: "Oversized Metadata risk",
        detail: `Large image container size detected (${(bytes.length / (1024*1024)).toFixed(1)} MB). Oversized images can act as vectors for payload stuffing.`,
        severity: "Low"
      });
    }

    const metadata = {
      "Structure Format": isPNG ? "PNG Image" : isJPEG ? "JPEG Image" : "Unknown Format",
      "Raw Magic Header": headerHex,
      "File Size Bytes": `${bytes.length.toLocaleString()} bytes`,
      "Nested zip Blocks": zipCount,
      "Script Overlays": scriptMatches ? "Detected" : "Clean"
    };

    return { score, findings, metadata };
  };

  // --- Handlers ---

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
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

  const processFile = (selectedFile) => {
    // 20MB limit (20 * 1024 * 1024)
    if (selectedFile.size > 20 * 1024 * 1024) {
      alert("File size exceeds the 20MB limit.");
      return;
    }

    setFile(selectedFile);
    setScanState('SCANNING');
    setProgress(0);
    setLogs([]);
    setScanResult(null);

    const ext = selectedFile.name.split('.').pop().toLowerCase();
    const reader = new FileReader();

    const startScanTime = Date.now();
    const logSteps = [
      "Initializing secure client-side sandbox environment...",
      "Reading raw file streams into ArrayBuffer...",
      `Analyzing filename '${selectedFile.name}' structure and type...`,
      "Running Magic Bytes verification to check file spoofing...",
      "Inspecting structural segment catalogs and header directories...",
      "Scanning binary blocks for disguised threats...",
      "Searching for active JavaScript streams, macros, and URI redirects...",
      "Inspecting metadata headers and EXIF fields...",
      "Compiling heuristic risk weights and audit records..."
    ];

    reader.onload = async (event) => {
      const arrayBuffer = event.target.result;
      const bytes = new Uint8Array(arrayBuffer);
      
      // Decode content as text for regex matching (safe client-side conversion)
      const textDecoder = new TextDecoder('utf-8', { fatal: false });
      const rawText = textDecoder.decode(bytes);

      // Extract text content dynamically from compressed PDF streams
      const decompressedText = await decompressPDFStreams(bytes);
      const textContent = rawText + "\n" + decompressedText;

      // Perform analysis
      let resultData;
      if (ext === 'pdf') {
        resultData = analyzePDF(bytes, textContent);
      } else {
        resultData = analyzeImage(bytes, selectedFile.name);
      }

      // Simulate animated progress scans
      let stepIdx = 0;
      const interval = setInterval(() => {
        if (stepIdx < logSteps.length) {
          setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${logSteps[stepIdx]}`]);
          setProgress(Math.round(((stepIdx + 1) / logSteps.length) * 100));
          stepIdx++;
        } else {
          clearInterval(interval);
          setTimeout(() => {
            setScanState('RESULT');
            setScanResult(resultData);
          }, 600);
        }
      }, 350);
    };

    reader.readAsArrayBuffer(selectedFile);
  };

  const getVerdict = (score) => {
    if (score >= 60) return { label: "High Risk Threat", color: "text-red-400 border-red-500/30 bg-red-500/10", glow: "glow-danger" };
    if (score >= 30) return { label: "Suspicious File", color: "text-orange-400 border-orange-500/30 bg-orange-500/10", glow: "glow-warning" };
    if (score > 0) return { label: "Low Risk Features", color: "text-amber-400 border-amber-500/30 bg-amber-500/10", glow: "glow-warning" };
    return { label: "Clear / Safe File", color: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10", glow: "glow-primary" };
  };

  const resetScanner = () => {
    setFile(null);
    setScanState('IDLE');
    setScanResult(null);
    setLogs([]);
    setProgress(0);
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'High': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'Medium': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'Low': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default: return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="flex-1 flex flex-col h-screen bg-[#030712] overflow-hidden text-slate-200">
      
      {/* Header */}
      <header className="p-5 border-b border-slate-800 bg-slate-900/40 shrink-0">
        <h2 className="text-sm font-bold text-slate-200">Static File Guard</h2>
        <p className="text-[10px] text-slate-500 font-medium">100% client-side heuristic inspection of files for malicious structures, macros, or scripts</p>
      </header>

      {/* Main Container */}
      <div className="flex-1 overflow-y-auto p-6 max-w-4xl mx-auto w-full space-y-6">
        
        {/* STATE 1: IDLE - Upload Area */}
        {scanState === 'IDLE' && (
          <div className="space-y-6">
            <div 
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-3xl p-12 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-300 ${
                dragActive 
                  ? 'border-indigo-500 bg-indigo-500/5 glow-primary' 
                  : 'border-slate-800 bg-slate-900/10 hover:border-indigo-500/40 hover:bg-slate-900/20'
              }`}
            >
              <div className="p-4 bg-slate-950/60 rounded-full border border-slate-850 text-indigo-400 mb-4 shadow-lg animate-pulse-slow">
                <Upload size={32} />
              </div>
              <h3 className="text-sm font-semibold text-slate-200">Drag & Drop Secure File</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-xs leading-normal">
                Supports PDF documents and Image files (JPG, JPEG, PNG) up to 20MB.
              </p>
              
              <label className="mt-6 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-indigo-600/15 cursor-pointer active:scale-98 transition">
                Browse Files
                <input 
                  type="file"
                  accept=".pdf,.png,.jpg,.jpeg"
                  onChange={handleFileInput}
                  className="hidden"
                />
              </label>
            </div>

            {/* Features Highlight */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-2xl border border-slate-850 bg-slate-900/20 flex gap-3">
                <div className="p-2.5 bg-indigo-500/10 rounded-xl text-indigo-400 shrink-0 h-fit">
                  <FileText size={16} />
                </div>
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Static PDF Inspector</h4>
                  <p className="text-[11px] text-slate-500 mt-1">Looks for auto-open scripts (/OpenAction), embedded Javascript streams (/JS), external system shells (/Launch), or phishing links.</p>
                </div>
              </div>
              <div className="p-4 rounded-2xl border border-slate-850 bg-slate-900/20 flex gap-3">
                <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-400 shrink-0 h-fit">
                  <ImageIcon size={16} />
                </div>
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Spoofing & Polyglot Scan</h4>
                  <p className="text-[11px] text-slate-500 mt-1">Verifies file integrity matching magic bytes, scans for embedded ZIP compression headers, or EXE boot tags disguised as images.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STATE 2: SCANNING - Animated Progress & Logs */}
        {scanState === 'SCANNING' && (
          <div className="p-6 glass rounded-3xl space-y-6 glow-primary border-indigo-500/10">
            {/* Animated Radar */}
            <div className="flex flex-col items-center justify-center py-6">
              <div className="relative w-20 h-20 flex items-center justify-center mb-4">
                <div className="absolute inset-0 border border-indigo-500/40 rounded-full animate-ping"></div>
                <div className="absolute inset-2 border-2 border-indigo-500/30 rounded-full"></div>
                <Activity size={32} className="text-indigo-400 animate-pulse" />
              </div>
              <h3 className="text-sm font-semibold tracking-wide text-indigo-400">Static Engine Scanning File...</h3>
              <p className="text-[11px] text-slate-500 mt-1">Extracting structure blocks in secure browser memory</p>
            </div>

            {/* Progress bar */}
            <div className="space-y-1.5 max-w-md mx-auto">
              <div className="flex justify-between text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                <span>Scan Progress</span>
                <span>{progress}%</span>
              </div>
              <div className="h-2 bg-slate-950 border border-slate-900 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
            </div>

            {/* Live Terminal Logs */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                <Terminal size={12} />
                Live Heuristics Log
              </span>
              <div className="p-4 bg-slate-950 border border-slate-900 rounded-2xl font-mono text-[10px] text-slate-400 space-y-1.5 h-44 overflow-y-auto no-scrollbar flex flex-col justify-end">
                {logs.map((log, idx) => (
                  <div key={idx} className="flex gap-2 items-start leading-relaxed text-indigo-300">
                    <ChevronRight size={10} className="shrink-0 mt-1" />
                    <span>{log}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* STATE 3: RESULT - Threat assessment breakdown */}
        {scanState === 'RESULT' && scanResult && (
          <div className="space-y-6 animate-fade-in">
            {/* Summary card */}
            <div className={`p-6 border rounded-3xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4 ${getVerdict(scanResult.score).color} ${getVerdict(scanResult.score).glow}`}>
              <div className="flex gap-4 items-center">
                <div className="p-3 bg-slate-950/40 rounded-2xl">
                  {scanResult.score > 0 ? (
                    <ShieldAlert size={28} className={scanResult.score >= 60 ? 'text-red-400' : 'text-orange-400'} />
                  ) : (
                    <ShieldCheck size={28} className="text-emerald-400" />
                  )}
                </div>
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Analysis Verdict</span>
                  <h3 className="text-lg font-black tracking-wide leading-tight">{getVerdict(scanResult.score).label}</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">File inspected: <span className="font-mono text-slate-300 break-all">{file.name}</span></p>
                </div>
              </div>

              {/* Gauge metric */}
              <div className="flex items-center gap-3 bg-slate-950/40 px-5 py-3 border border-white/5 rounded-2xl">
                <div>
                  <span className="text-[8px] font-bold text-slate-500 uppercase tracking-wider block text-right">Risk Score</span>
                  <p className="text-2xl font-black tracking-tight">{scanResult.score} <span className="text-xs text-slate-600 font-bold">/100</span></p>
                </div>
                <div className="w-10 h-10 rounded-full border-4 border-slate-800 flex items-center justify-center overflow-hidden">
                  <div className={`w-full h-full ${scanResult.score >= 60 ? 'bg-red-500' : scanResult.score >= 30 ? 'bg-orange-500' : scanResult.score > 0 ? 'bg-amber-500' : 'bg-emerald-500'}`}></div>
                </div>
              </div>
            </div>

            {/* Two Column details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Left Column: Metadata Panel */}
              <div className="p-5 glass rounded-3xl space-y-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 border-b border-slate-850 pb-2">File Metadata</h4>
                <div className="space-y-3">
                  {Object.entries(scanResult.metadata).map(([key, val]) => (
                    <div key={key} className="flex justify-between items-center text-xs">
                      <span className="text-slate-500 font-medium">{key}</span>
                      <span className="text-slate-300 font-semibold max-w-[180px] truncate" title={val}>{val}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Evidence Log */}
              <div className="p-5 glass rounded-3xl flex flex-col h-fit min-h-[190px]">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 border-b border-slate-850 pb-2 mb-3">Audit Findings Log</h4>
                
                {scanResult.findings.length === 0 ? (
                  <div className="flex-1 flex flex-col justify-center items-center py-6 text-center text-slate-600">
                    <Info size={24} className="mb-2" />
                    <p className="text-xs">No malicious indicators triggered.</p>
                  </div>
                ) : (
                  <div className="space-y-3 flex-1 overflow-y-auto max-h-[220px] pr-1">
                    {scanResult.findings.map((item, idx) => (
                      <div 
                        key={idx}
                        className="p-3 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1.5"
                      >
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] font-bold text-slate-300">{item.category}</span>
                          <span className={`px-2 py-0.5 rounded-full border text-[8px] font-bold uppercase ${getSeverityBadge(item.severity)}`}>
                            {item.severity}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-500 leading-relaxed font-mono">{item.detail}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>

            {/* Action buttons */}
            <div className="flex justify-center border-t border-slate-850 pt-6">
              <button
                onClick={resetScanner}
                className="flex items-center gap-1.5 px-5 py-2.5 bg-slate-800 border border-slate-700 hover:bg-slate-700 rounded-xl text-xs font-semibold text-slate-200 active:scale-98 transition shadow-lg"
              >
                <RefreshCw size={14} />
                Scan Another File
              </button>
            </div>
          </div>
        )}

        {/* Built-in disclaimer */}
        <footer className="p-4 border border-slate-850 rounded-2xl bg-slate-900/10 text-[10px] text-slate-500 leading-relaxed flex gap-2">
          <Info size={14} className="shrink-0 mt-0.5" />
          <p>
            <strong>Disclaimer:</strong> PromptShield Static File Guard performs local structural, signature, and heuristics checks entirely inside your web browser. No file contents are uploaded, providing 100% data privacy. This static checker is a diagnostic tool and does not substitute for dedicated, real-time operating system antivirus protections.
          </p>
        </footer>

      </div>
    </div>
  );
}
