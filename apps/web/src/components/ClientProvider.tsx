"use client";

import { SessionProvider } from "next-auth/react";

export function ClientProvider({ children }: { children: React.ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>;
}
