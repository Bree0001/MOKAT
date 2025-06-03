import "./globals.css"
import Providers from "./providers"
import type { Metadata } from "next"
import NavBar from "@/components/NavBar"
import { Inter } from "next/font/google"
import Footer from "@/components/Footer"
import { Toaster } from "sonner"

const inter = Inter({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
})

export const metadata: Metadata = {
  title: "Mokat Builders Limited",
  description:
    "Mokat Builders & General Agencies is a leading development contractor duly registered and certified to undertake residential, commercial, institutional, and industrial construction projects.",
}

export const dynamic = "force-dynamic"

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang='en'>
      <body className={`${inter.className} min-h-screen relative`}>
        <Toaster richColors position="top-right" />
        <NavBar />
        <Providers>{children}</Providers>
        <Footer />
      </body>
    </html>
  )
}
