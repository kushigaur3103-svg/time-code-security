"use client";

import { useState } from "react";

export function UpgradeButton() {
  const [isLoading, setIsLoading] = useState(false);

  const onClick = async () => {
    try {
      setIsLoading(true);
      const response = await fetch("/api/stripe/checkout", {
        method: "POST",
      });

      const data = await response.json();
      
      if (data.url) {
        window.location.href = data.url;
      }
    } catch (error) {
      console.error("Failed to checkout", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="relative group transform-gpu will-change-transform">
      <div className="absolute -inset-0.5 bg-gradient-to-r from-purple-600 to-blue-600 rounded-lg blur opacity-75 group-hover:opacity-100 transition duration-300 ease-in-out"></div>
      <button 
        onClick={onClick}
        disabled={isLoading}
        className="relative bg-white text-slate-900 hover:bg-slate-50 font-bold py-2 px-6 rounded-lg transition-all duration-300 ease-in-out focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 flex items-center space-x-2 disabled:opacity-50"
      >
        <span>{isLoading ? "Redirecting..." : "Upgrade to Pro"}</span>
        {!isLoading && <span className="text-purple-600">✨</span>}
      </button>
    </div>
  );
}
