import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { stripe } from "@/lib/stripe";

export async function POST(req: Request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session || !session.user) {
      return new NextResponse("Unauthorized", { status: 401 });
    }

    // Create a Stripe Checkout Session
    const stripeSession = await stripe.checkout.sessions.create({
      success_url: "http://localhost:3000/?success=true",
      cancel_url: "http://localhost:3000/?canceled=true",
      payment_method_types: ["card"],
      mode: "subscription",
      billing_address_collection: "auto",
      customer_email: session.user.email || undefined,
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID || "price_dummy_123",
          quantity: 1,
        },
      ],
    });

    return NextResponse.json({ url: stripeSession.url });
  } catch (error) {
    console.error("[STRIPE_ERROR]", error);
    return new NextResponse("Internal Error", { status: 500 });
  }
}
