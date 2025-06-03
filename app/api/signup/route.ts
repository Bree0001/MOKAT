import { db } from "@/db/drizzle"
import { users } from "@/db/schema"
import { cookies } from "next/headers"
import { generateId, Scrypt } from "lucia"
import { redirect } from "next/navigation"
import { lucia } from "@/actions/auth/lucia"
import { signUpFormSchema } from "@/lib/types"
import { NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  const body = await request.json()
  const dataValidation = signUpFormSchema.safeParse(body)

  if (!dataValidation.success) {
    return NextResponse.json(dataValidation.error.format(), {
      status: 400,
    })
  }

  const hashedPassword = await new Scrypt().hash(body.password)
  const userId = generateId(15)

  await db.insert(users).values({
    id: userId,
    username: body.username,
    hashedPassword: hashedPassword,
    emailAddress: body.email.toLowerCase(),
  })

  const session = await lucia.createSession(userId, {})
  const sessionCookie = lucia.createSessionCookie(session.id)
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  )
  
  return redirect("/enquiries")

}
