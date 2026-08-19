import type { Metadata } from 'next';
import { ShieldCheck, Activity, Settings } from 'lucide-react';
import Link from 'next/link';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { SignOutButton } from '@/components/SignOutButton';
import { ClientProvider } from '@/components/ClientProvider';
import { Toaster } from 'react-hot-toast';
import './globals.css';

export const metadata: Metadata = {
  title: 'AI Security Dashboard',
  description: 'Real-Time Code Security & Self-Healing Agent',
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession(authOptions);

  return (
    <html lang="en">
      <body className="font-sans antialiased bg-[#030712] text-slate-300 min-h-screen flex flex-col selection:bg-purple-500/30">
        <ClientProvider>
          {/* Top Navigation Bar */}
          <nav className="bg-[#050814] border-b border-white/10 sticky top-0 z-50 transform-gpu">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex justify-between h-16 items-center">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="h-8 w-8 text-blue-600" />
                  <span className="text-xl text-white font-bold tracking-tight">
                    AI Security Agent
                  </span>
                </div>
                <div className="hidden md:flex space-x-8 items-center">
                  <Link href="/" className="flex items-center space-x-1 text-slate-400 hover:text-white transition-colors">
                    <Activity className="h-4 w-4" />
                    <span className="font-medium">Scans</span>
                  </Link>
                  <Link href="/settings" className="flex items-center space-x-1 text-slate-400 hover:text-white transition-colors">
                    <Settings className="h-4 w-4" />
                    <span className="font-medium">Settings</span>
                  </Link>
                  
                  {/* User Context & Auth */}
                  {session?.user && (
                    <div className="flex items-center space-x-4 border-l border-white/10 pl-6 ml-2">
                      <div className="flex items-center space-x-2">
                        {session.user.image ? (
                          <img src={session.user.image} alt="Avatar" className="w-8 h-8 rounded-full border border-white/10" />
                        ) : (
                          <div className="w-8 h-8 rounded-full bg-white/10" />
                        )}
                        <span className="text-sm font-medium text-slate-300">{session.user.name}</span>
                      </div>
                      <SignOutButton />
                    </div>
                  )}
                </div>
              </div>
            </div>
          </nav>

          {/* Main Content Area */}
          <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
          <Toaster position="bottom-right" toastOptions={{
            style: {
              background: '#1e293b',
              color: '#fff',
              border: '1px solid rgba(255,255,255,0.1)'
            }
          }} />
        </ClientProvider>
      </body>
    </html>
  );
}
