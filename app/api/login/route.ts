export const dynamic = "force-dynamic";
import { Scrypt } from "lucia";
import { eq } from "drizzle-orm";
import { db } from "@/db/drizzle";
import { users } from "@/db/schema";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { lucia } from "@/actions/auth/lucia";
import { loginFormSchema } from "@/lib/types";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const dataValidation = loginFormSchema.safeParse(body);

    if (!dataValidation.success) {
      return NextResponse.json(dataValidation.error.format(), {
        status: 400,
      });
    }

    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.emailAddress, body.email));

    if (!existingUser) {
      return NextResponse.json(
        { error: "Incorrect username or password" },
        { status: 401 }
      );
    }

    const validPassword = await new Scrypt().verify(
      existingUser.hashedPassword,
      body.password
    );

    if (!validPassword) {
      return NextResponse.json(
        { error: "Incorrect username or password" },
        { status: 401 }
      );
    }

    const session = await lucia.createSession(existingUser.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);

    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes
    );

    return redirect("/enquiries");
  } catch (error) {
    console.error("Login error:", error);

    if (error instanceof Error && error.message.includes("URL")) {
      return NextResponse.json(
        { error: "Server misconfiguration (URL issue)" },
        { status: 500 }
      );
    }

    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
