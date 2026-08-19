import Stripe from 'stripe';

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_123', {
  apiVersion: '2026-07-29.dahlia',
  appInfo: {
    name: 'AI Security Agent',
    version: '1.0.0'
  }
});
