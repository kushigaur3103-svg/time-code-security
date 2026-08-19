import { ShieldAlert, CheckCircle, Code, ShieldOff, Sparkles, Activity, Zap } from 'lucide-react';
import { prisma } from '@/lib/db';
import { UpgradeButton } from '@/components/UpgradeButton';
import { TriggerScanButton } from '@/components/TriggerScanButton';

export const dynamic = 'force-dynamic';

export default async function Dashboard() {
  const totalScans = await prisma.scan.count();
  const vulnerabilitiesFound = totalScans; 
  const autoHealedScans = await prisma.scan.count({
    where: { status: 'Auto-Healed' }
  });

  const resolutionRate = totalScans > 0 
    ? ((autoHealedScans / totalScans) * 100).toFixed(1) 
    : '0.0';

  const recentScans = await prisma.scan.findMany({
    orderBy: { createdAt: 'desc' },
    take: 5
  });

  return (
    <div className="space-y-12 relative z-0 pb-12">
      
      {/* GOD-TIER AMBIENT BACKGROUND ORBS WITH BLOB ANIMATION */}
      <div className="fixed top-[-15%] left-[-10%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle,rgba(79,70,229,0.15)_0%,transparent_70%)] pointer-events-none -z-10 animate-blob transform-gpu will-change-transform"></div>
      <div className="fixed top-[20%] right-[-10%] w-[500px] h-[500px] rounded-full bg-[radial-gradient(circle,rgba(147,51,234,0.15)_0%,transparent_70%)] pointer-events-none -z-10 animate-blob transform-gpu will-change-transform" style={{ animationDelay: '5s' }}></div>
      <div className="fixed bottom-[-20%] left-[20%] w-[700px] h-[700px] rounded-full bg-[radial-gradient(circle,rgba(37,99,235,0.1)_0%,transparent_70%)] pointer-events-none -z-10 animate-blob transform-gpu will-change-transform" style={{ animationDelay: '10s' }}></div>

      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-end md:justify-between pt-8">
        <div className="animate-float">
          <div className="flex items-center space-x-4 mb-3">
            <div className="flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-white/10 shadow-[0_0_30px_rgba(99,102,241,0.3)] backdrop-blur-xl">
              <Zap className="w-6 h-6 text-indigo-400 drop-shadow-[0_0_10px_rgba(129,140,248,0.8)]" />
            </div>
            <span className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-[#051125] border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)]">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,1)]"></span>
              </span>
              <span className="text-[10px] font-bold tracking-[0.2em] text-emerald-400 uppercase">Neural Engine Active</span>
            </span>
          </div>
          <h1 className="text-5xl md:text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-indigo-300 to-purple-400 bg-[length:200%_auto] animate-gradient-x tracking-tighter drop-shadow-lg pb-1">
            Security Command Center
          </h1>
          <p className="mt-4 text-slate-400/80 text-lg max-w-2xl font-light leading-relaxed">
            Autonomous threat detection and real-time auto-healing engine powered by Next-Gen AI.
          </p>
        </div>
        
        <div className="mt-8 md:mt-0 flex items-center space-x-4 animate-float-delayed">
          <TriggerScanButton />
          
          <UpgradeButton />
        </div>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-4">
        {/* Card 1 */}
        <div className="animate-float group bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.5)] hover:-translate-y-2 hover:shadow-[inset_0_1px_1px_rgba(255,255,255,0.1),0_25px_50px_0_rgba(79,70,229,0.2)] hover:border-indigo-500/40 transition-all duration-700 relative overflow-hidden transform-gpu">
          <div className="absolute -top-24 -right-24 w-64 h-64 bg-[radial-gradient(circle,rgba(99,102,241,0.25)_0%,transparent_70%)] rounded-full group-hover:bg-[radial-gradient(circle,rgba(99,102,241,0.4)_0%,transparent_70%)] group-hover:scale-150 transition-all duration-1000 transform-gpu will-change-transform"></div>
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-gradient-to-r from-transparent via-indigo-400 to-transparent group-hover:w-3/4 transition-all duration-1000"></div>
          
          <div className="flex items-center justify-between relative z-10">
            <p className="text-[11px] font-bold text-slate-400/80 uppercase tracking-[0.25em]">Total Scans</p>
            <div className="bg-white/5 p-3 rounded-2xl border border-white/10 group-hover:border-indigo-400/40 group-hover:bg-indigo-500/20 transition-all duration-500 shadow-inner">
              <Code className="h-6 w-6 text-slate-300 group-hover:text-indigo-300 transition-colors duration-500" />
            </div>
          </div>
          <p className="mt-8 text-6xl font-black text-transparent bg-clip-text bg-gradient-to-b from-white via-white to-slate-500 tracking-tighter drop-shadow-2xl relative z-10">{totalScans}</p>
          <div className="mt-4 flex items-center text-sm relative z-10">
            <span className="text-slate-500/80 font-medium flex items-center">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 mr-2 shadow-[0_0_8px_rgba(99,102,241,0.8)]"></span>
              Live Database Sync
            </span>
          </div>
        </div>

        {/* Card 2 */}
        <div className="animate-float-delayed group bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.5)] hover:-translate-y-2 hover:shadow-[inset_0_1px_1px_rgba(255,255,255,0.1),0_25px_50px_0_rgba(245,158,11,0.2)] hover:border-amber-500/40 transition-all duration-700 relative overflow-hidden transform-gpu">
          <div className="absolute -top-24 -right-24 w-64 h-64 bg-[radial-gradient(circle,rgba(245,158,11,0.25)_0%,transparent_70%)] rounded-full group-hover:bg-[radial-gradient(circle,rgba(245,158,11,0.4)_0%,transparent_70%)] group-hover:scale-150 transition-all duration-1000 transform-gpu will-change-transform"></div>
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-gradient-to-r from-transparent via-amber-400 to-transparent group-hover:w-3/4 transition-all duration-1000"></div>
          
          <div className="flex items-center justify-between relative z-10">
            <p className="text-[11px] font-bold text-slate-400/80 uppercase tracking-[0.25em]">Hotspots</p>
            <div className="bg-white/5 p-3 rounded-2xl border border-white/10 group-hover:border-amber-400/40 group-hover:bg-amber-500/20 transition-all duration-500 shadow-inner">
              <ShieldAlert className="h-6 w-6 text-slate-300 group-hover:text-amber-300 transition-colors duration-500" />
            </div>
          </div>
          <p className="mt-8 text-6xl font-black text-transparent bg-clip-text bg-gradient-to-b from-white via-white to-slate-500 tracking-tighter drop-shadow-2xl relative z-10">{vulnerabilitiesFound}</p>
          <div className="mt-4 flex items-center text-sm relative z-10">
            <span className="text-slate-500/80 font-medium flex items-center">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 mr-2 shadow-[0_0_8px_rgba(245,158,11,0.8)]"></span>
              Unique Vulnerabilities
            </span>
          </div>
        </div>

        {/* Card 3 */}
        <div className="animate-float group bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.5)] hover:-translate-y-2 hover:shadow-[inset_0_1px_1px_rgba(255,255,255,0.1),0_25px_50px_0_rgba(16,185,129,0.2)] hover:border-emerald-500/40 transition-all duration-700 relative overflow-hidden transform-gpu">
          <div className="absolute -top-24 -right-24 w-64 h-64 bg-[radial-gradient(circle,rgba(16,185,129,0.25)_0%,transparent_70%)] rounded-full group-hover:bg-[radial-gradient(circle,rgba(16,185,129,0.4)_0%,transparent_70%)] group-hover:scale-150 transition-all duration-1000 transform-gpu will-change-transform"></div>
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-gradient-to-r from-transparent via-emerald-400 to-transparent group-hover:w-3/4 transition-all duration-1000"></div>
          
          <div className="flex items-center justify-between relative z-10">
            <p className="text-[11px] font-bold text-slate-400/80 uppercase tracking-[0.25em]">Auto-Healed</p>
            <div className="bg-white/5 p-3 rounded-2xl border border-white/10 group-hover:border-emerald-400/40 group-hover:bg-emerald-500/20 transition-all duration-500 shadow-inner">
              <CheckCircle className="h-6 w-6 text-slate-300 group-hover:text-emerald-300 transition-colors duration-500" />
            </div>
          </div>
          <p className="mt-8 text-6xl font-black text-transparent bg-clip-text bg-gradient-to-b from-white via-white to-slate-500 tracking-tighter drop-shadow-2xl relative z-10">{autoHealedScans}</p>
          <div className="mt-4 flex items-center text-sm relative z-10">
            <span className="text-slate-500/80 font-medium flex items-center">
              <span className="text-emerald-400 font-bold mr-1.5 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]">{resolutionRate}%</span> 
              resolution rate
            </span>
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="bg-[#0A0D18] border border-white/10 rounded-[2.5rem] shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_20px_60px_rgba(0,0,0,0.6)] overflow-hidden relative ring-1 ring-white/5 mt-8 transform-gpu">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>
        
        <div className="px-10 py-8 border-b border-white/5 flex items-center justify-between bg-white/[0.01]">
          <div className="flex items-center space-x-4">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(99,102,241,0.2)]">
              <Activity className="w-5 h-5 text-indigo-400" />
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">Recent Interventions</h2>
          </div>
          <span className="px-4 py-1.5 rounded-full bg-white/5 border border-white/10 text-[10px] font-bold text-slate-400/80 uppercase tracking-[0.3em]">Live Feed</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-slate-500/70 bg-black/40 border-b border-white/5">
              <tr>
                <th className="px-10 py-5 font-bold uppercase tracking-[0.2em] text-[10px]">Target File</th>
                <th className="px-10 py-5 font-bold uppercase tracking-[0.2em] text-[10px]">Detected Signature</th>
                <th className="px-10 py-5 font-bold uppercase tracking-[0.2em] text-[10px]">Threat Level</th>
                <th className="px-10 py-5 font-bold uppercase tracking-[0.2em] text-[10px]">Engine Status</th>
                <th className="px-10 py-5 font-bold uppercase tracking-[0.2em] text-[10px] text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-10 py-32 relative overflow-hidden">
                    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-[0.03]"></div>
                    <div className="flex flex-col items-center justify-center text-center relative z-10 animate-float">
                      <div className="relative w-24 h-24 mb-8 flex items-center justify-center">
                        <div className="absolute inset-0 rounded-full border border-dashed border-indigo-500/40 animate-[spin_10s_linear_infinite]"></div>
                        <div className="absolute inset-2 rounded-full border border-dashed border-purple-500/30 animate-[spin_15s_linear_infinite_reverse]"></div>
                        <div className="w-16 h-16 rounded-2xl bg-[#0F1424] flex items-center justify-center shadow-[0_0_30px_rgba(255,255,255,0.05)] border border-white/10">
                          <ShieldOff className="w-7 h-7 text-indigo-300/80" />
                        </div>
                      </div>
                      <h3 className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white to-slate-500 mb-3 tracking-tight">Awaiting Telemetry</h3>
                      <p className="text-slate-400/80 text-base max-w-md font-light leading-relaxed">The AI Engine is standing by. Save a file in your VS Code environment to trigger the first autonomous security sweep.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                recentScans.map((scan) => (
                  <tr key={scan.id} className="group hover:bg-white/[0.04] transition-all duration-300 text-slate-300 cursor-pointer relative">
                    {/* Left Accent line on hover */}
                    <td className="absolute left-0 top-0 bottom-0 w-[3px] bg-indigo-500 scale-y-0 group-hover:scale-y-100 transition-transform duration-300 origin-center shadow-[0_0_10px_rgba(99,102,241,1)]"></td>
                    
                    <td className="px-10 py-6 font-medium text-white flex items-center space-x-4">
                      <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:bg-indigo-500/20 group-hover:border-indigo-500/40 transition-colors duration-300 group-hover:shadow-[0_0_15px_rgba(99,102,241,0.3)]">
                        <Code className="w-5 h-5 text-slate-400 group-hover:text-indigo-300 transition-colors" />
                      </div>
                      <span className="text-base tracking-wide">{scan.fileName}</span>
                    </td>
                    <td className="px-10 py-6">
                      <span className="font-mono text-xs text-slate-300/80 bg-black/60 px-3 py-2 rounded-lg border border-white/5 group-hover:border-indigo-500/30 transition-colors">{scan.vulnerabilityType}</span>
                    </td>
                    <td className="px-10 py-6">
                      <span className={`inline-flex items-center px-4 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-[0.2em] ${
                        scan.riskLevel === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30 shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                      }`}>
                        {scan.riskLevel}
                      </span>
                    </td>
                    <td className="px-10 py-6">
                      {scan.status === 'Auto-Healed' ? (
                        <span className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold uppercase tracking-[0.2em] shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                          <CheckCircle className="h-4 w-4 drop-shadow-[0_0_5px_rgba(16,185,129,0.8)]" />
                          <span>Resolved</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-3 px-4 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold uppercase tracking-[0.2em] shadow-[0_0_15px_rgba(245,158,11,0.2)]">
                          <span className="relative flex h-2.5 w-2.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,1)]"></span>
                          </span>
                          <span>Mitigating</span>
                        </span>
                      )}
                    </td>
                    <td className="px-10 py-6 text-right font-mono text-[11px] tracking-wider text-slate-500 group-hover:text-slate-300 transition-colors">
                      {new Date(scan.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      
    </div>
  );
}
