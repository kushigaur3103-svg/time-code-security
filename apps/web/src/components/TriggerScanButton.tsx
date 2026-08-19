'use client';

import { Activity } from 'lucide-react';
import toast from 'react-hot-toast';

export function TriggerScanButton() {
  const handleScan = () => {
    toast.success('Manual scan initiated. Listening for IDE payloads...');
    // Future backend integration logic here
  };

  return (
    <button 
      onClick={handleScan}
      className="relative group overflow-hidden bg-[#0A0D18] border border-white/10 hover:border-indigo-400/60 text-white font-semibold py-3 px-6 rounded-2xl shadow-[0_0_30px_rgba(0,0,0,0.5)] transition-all duration-300 ease-in-out hover:shadow-[0_0_40px_rgba(99,102,241,0.4)] hover:-translate-y-1 transform-gpu will-change-transform"
    >
      <span className="relative z-10 flex items-center space-x-2">
        <Activity className="w-5 h-5 text-indigo-400 group-hover:text-white transition-colors" />
        <span>Trigger Manual Scan</span>
      </span>
      {/* The Shimmer Effect */}
      <div className="absolute inset-0 -top-[50%] -bottom-[50%] w-[50%] bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:animate-shimmer"></div>
      {/* Hover Glow */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 bg-indigo-500/10 transition-opacity duration-500"></div>
    </button>
  );
}
