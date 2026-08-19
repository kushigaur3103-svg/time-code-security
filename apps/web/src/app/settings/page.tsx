import { ShieldCheck, User, Key, CreditCard, ChevronRight } from 'lucide-react';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export default async function SettingsPage() {
  const session = await getServerSession(authOptions);

  return (
    <div className="space-y-12 relative z-0 pb-12 max-w-4xl mx-auto">
      
      {/* GOD-TIER AMBIENT BACKGROUND ORBS */}
      <div className="fixed top-[-10%] left-[-10%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle,rgba(79,70,229,0.15)_0%,transparent_70%)] pointer-events-none -z-10 animate-blob transform-gpu will-change-transform"></div>
      <div className="fixed top-[40%] right-[-10%] w-[400px] h-[400px] rounded-full bg-[radial-gradient(circle,rgba(147,51,234,0.15)_0%,transparent_70%)] pointer-events-none -z-10 animate-blob transform-gpu will-change-transform" style={{ animationDelay: '3s' }}></div>

      {/* Header Section */}
      <div className="pt-8">
        <h1 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-indigo-300 to-purple-400 tracking-tighter drop-shadow-lg pb-1">
          Settings & Preferences
        </h1>
        <p className="mt-4 text-slate-400/80 text-lg font-light leading-relaxed">
          Manage your account details, AI engine API keys, and billing plan.
        </p>
      </div>

      <div className="space-y-8">
        
        {/* Account Details */}
        <section className="bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.3)] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-[radial-gradient(circle,rgba(99,102,241,0.15)_0%,transparent_70%)] rounded-full pointer-events-none transform-gpu will-change-transform"></div>
          
          <div className="flex items-center space-x-4 mb-8">
            <div className="w-12 h-12 rounded-2xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(99,102,241,0.2)]">
              <User className="w-6 h-6 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white tracking-tight">Account Details</h2>
              <p className="text-sm text-slate-400/80">Your personal profile information</p>
            </div>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-xs font-bold text-slate-400/80 uppercase tracking-widest mb-2">Display Name</label>
              <div className="bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white font-medium flex items-center justify-between">
                <span>{session?.user?.name || 'Administrator'}</span>
                <button className="text-indigo-400 hover:text-indigo-300 text-sm font-semibold transition-colors">Edit</button>
              </div>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400/80 uppercase tracking-widest mb-2">Email Address</label>
              <div className="bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-slate-300 font-medium">
                {session?.user?.email || 'admin@example.com'}
              </div>
            </div>
          </div>
        </section>

        {/* API Keys */}
        <section className="bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.3)] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-[radial-gradient(circle,rgba(245,158,11,0.15)_0%,transparent_70%)] rounded-full pointer-events-none transform-gpu will-change-transform"></div>
          
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 rounded-2xl bg-amber-500/20 border border-amber-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(245,158,11,0.2)]">
                <Key className="w-6 h-6 text-amber-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white tracking-tight">Enterprise API & Integration</h2>
                <p className="text-sm text-slate-400/80">Connect your proprietary pipelines to our Headless Security Engine</p>
              </div>
            </div>
            <button className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400 px-4 py-2 rounded-xl text-sm font-bold transition-all shadow-[0_0_10px_rgba(245,158,11,0.2)]">
              Rotate Key
            </button>
          </div>

          <div className="bg-black/40 border border-white/10 rounded-xl p-4 flex items-center justify-between group">
            <div className="flex items-center space-x-3">
              <span className="text-slate-300 font-mono tracking-widest">sk_ent_•••••••••••••••••••••a8b2</span>
            </div>
            <button className="text-slate-400 hover:text-white transition-colors">
              Copy
            </button>
          </div>
        </section>

        {/* Security & Compliance (SOC2) */}
        <section className="bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.3)] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-[radial-gradient(circle,rgba(59,130,246,0.15)_0%,transparent_70%)] rounded-full pointer-events-none transform-gpu will-change-transform"></div>
          
          <div className="flex items-center space-x-4 mb-8">
            <div className="w-12 h-12 rounded-2xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.2)]">
              <ShieldCheck className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white tracking-tight">Security & Compliance (SOC2)</h2>
              <p className="text-sm text-slate-400/80">Manage enterprise data retention policies</p>
            </div>
          </div>

          <div className="bg-black/40 border border-white/10 rounded-xl p-6 flex items-start justify-between">
            <div className="max-w-xl">
              <h3 className="text-lg font-bold text-white mb-2 flex items-center">
                Zero Data Retention Mode
                <span className="ml-3 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">ENTERPRISE</span>
              </h3>
              <p className="text-sm text-slate-400/80 leading-relaxed">
                When enabled, payloads are processed entirely in memory and immediately destroyed. Guaranteed SOC2 compliance for proprietary codebases. No logs, no traces, no database records.
              </p>
            </div>
            <div className="relative mt-2">
              <label className="flex items-center cursor-pointer">
                <div className="relative">
                  <input type="checkbox" className="sr-only" defaultChecked />
                  <div className="block bg-indigo-500 w-14 h-8 rounded-full shadow-[inset_0_2px_4px_rgba(0,0,0,0.4)]"></div>
                  <div className="dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition transform translate-x-6 shadow-[0_2px_5px_rgba(0,0,0,0.3)]"></div>
                </div>
              </label>
            </div>
          </div>
        </section>

        {/* Billing */}
        <section className="bg-[#0A0D18] border border-white/10 rounded-[2rem] p-8 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05),0_10px_40px_0_rgba(0,0,0,0.3)] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-[radial-gradient(circle,rgba(16,185,129,0.15)_0%,transparent_70%)] rounded-full pointer-events-none transform-gpu will-change-transform"></div>
          
          <div className="flex items-center space-x-4 mb-8">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.2)]">
              <CreditCard className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white tracking-tight">Billing & Plans</h2>
              <p className="text-sm text-slate-400/80">You are currently on the Free Tier</p>
            </div>
          </div>

          <div className="bg-gradient-to-r from-indigo-500/10 to-purple-500/10 border border-indigo-500/20 rounded-xl p-6 flex flex-col sm:flex-row items-center justify-between relative overflow-hidden">
            <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-[0.05]"></div>
            <div className="relative z-10 mb-4 sm:mb-0">
              <h3 className="text-xl font-bold text-white">Upgrade to Pro</h3>
              <p className="text-slate-400 text-sm mt-1">Unlock unlimited autonomous healing and priority support.</p>
            </div>
            <button className="relative z-10 bg-indigo-500 hover:bg-indigo-600 text-white font-bold py-2.5 px-6 rounded-xl shadow-[0_0_15px_rgba(99,102,241,0.5)] transition-all hover:scale-105 hover:shadow-[0_0_25px_rgba(99,102,241,0.7)] flex items-center space-x-2">
              <span>Upgrade Now</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </section>

      </div>
    </div>
  );
}
