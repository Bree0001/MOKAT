"use server"

import { db } from "@/db/drizzle"
import {  desc } from "drizzle-orm"
import { enquiries } from "@/db/schema"

export default async function getEnquiries() {
  try {
    const fetchedEnquiries = await db
      .select()
      .from(enquiries)
      .orderBy(desc(enquiries.sentAt))

    return fetchedEnquiries
  } catch (error) {
    console.log(error)
    throw error
  }
}
