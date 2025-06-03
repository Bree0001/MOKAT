import { z } from "zod";

export const ContactSchema = z.object({
    name: z.string().min(3, {message: "Name is required"}),
    email: z.string().email({ message: "Email address is required" }),
    phone: z.number().min(10, {message: "Phone number must be at least 10 characters"}).max(12, {message: "Phone number can be 10-12 characters"}),
    message: z.string().min(10, {message: "A valid message is required"}),
})