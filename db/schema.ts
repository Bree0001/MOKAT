import { db } from "./drizzle"
import { sql } from "drizzle-orm"
import { DrizzleSQLiteAdapter } from "@lucia-auth/adapter-drizzle"
import { text, integer, sqliteTable } from "drizzle-orm/sqlite-core"

export const users = sqliteTable("users", {
  id: text("id").notNull().primaryKey(),
  username: text("username").notNull().unique(),
  hashedPassword: text("hashed_password").notNull(),
  emailAddress: text("email_address").notNull().unique(),
  isVerified: integer('is_verified', { mode: 'boolean' }).notNull().default(false)
})

export const sessions = sqliteTable("sessions", {
  id: text("id").notNull().primaryKey(),
  expiresAt: integer("expires_at").notNull(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id),
})

export const enquiries = sqliteTable("enquiries", {
  id: text("id").notNull().primaryKey(),
  name: text("username").notNull(),
  message: text("message").notNull(),
  phoneNumber: text("phone_number").notNull(),
  emailAddress: text("email_address").notNull(),
  sentAt: integer('sent_at', { mode: 'timestamp_ms' }).notNull().default(sql`(CURRENT_TIMESTAMP)`),
})

export const adapter = new DrizzleSQLiteAdapter(db, sessions, users)
