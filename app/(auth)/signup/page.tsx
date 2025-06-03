import Link from "next/link"
import Image from "next/image"
import SignUpForm from "./_components/sign-up-form"

export default function SignUp() {
  return (
    <main className='min-h-screen mx-auto max-w-7xl space-y-8 p-4 md:p-16 lg:p-32'>
      <div className='max-w-xs mx-auto space-y-8'>
        <h2 className='text-center text-2xl font-bold leading-9 tracking-tight text-gray-900'>
          Create your account
        </h2>

        <SignUpForm />
      </div>
    </main>
  )
}
