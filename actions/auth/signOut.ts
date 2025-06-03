"use server"

import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { lucia, validateAuthRequest } from "./lucia"

export default async function signOut() {
  const { session } = await validateAuthRequest()
  if (!session) {
    return {
      error: "Unauthorized",
    }
  }

  await lucia.invalidateSession(session.id)

  const sessionCookie = lucia.createBlankSessionCookie()
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  )
  return redirect("/login")
}
