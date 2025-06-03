"use server"

import { db } from "@/db/drizzle"
import { generateId } from "lucia"
import { enquiries } from "@/db/schema"
import { revalidatePath } from "next/cache"

export default async function HandleContact(formData: FormData) {
  try {
    let successful = false

    const enquiryId = generateId(15)

    const name = String(formData.get("name"))
    const email = String(formData.get("email"))
    const phone = String(formData.get("phone"))
    const message = String(formData.get("message"))

    await db
      .insert(enquiries)
      .values({
        id: enquiryId,
        name: name,
        emailAddress: email,
        phoneNumber: phone,
        message: message,
      })

      revalidatePath('/enquiries')

    successful = true

    return successful
  } catch (error) {
    console.log(error)
    throw error
  }
}
