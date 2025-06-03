import { toast } from "sonner"
import { LogOutIcon } from "lucide-react"
import { redirect } from "next/navigation"
import getEnquiries from "@/actions/enquiries"
import signOut from "@/actions/auth/signOut"
import { DataTable } from "./_components/Datatable"
import { validateAuthRequest } from "@/actions/auth/lucia"

export default async function Enquiries() {
  const { user } = await validateAuthRequest()
  if (!user) {
    return redirect("/login")
  }
  // else if (user.isVerified === false) {
  //   // toast.warning("Please verify your account")
  //   return redirect("/")
  // }

  const enquiries = await getEnquiries()

  console.log(enquiries)

  return (
    <div className='p-4 md:p-8 max-w-7xl mx-auto min-h-screen'>
      <div className='mt-10 sm:mt-16 flex items-center justify-between'>
        <h1 className='text-2xl font-bold text-gray-800'>Enquiries</h1>
        <form action={signOut}>
          <button className='px-4 py-2 flex items-center gap-2 bg-transparent hover:bg-slate-100/80 text-slate-500 rounded-lg'>
            <span className='text-sm'>Sign out</span>
            <LogOutIcon size={16} aria-hidden />
          </button>
        </form>
      </div>

      <DataTable enquiries={enquiries} />
    </div>
  )
}
