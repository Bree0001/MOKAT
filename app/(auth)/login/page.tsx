import Link from "next/link"
import Image from "next/image"
import LoginForm from "./_components/login-form"

export default function Login() {
  return (
    <main className='min-h-screen mx-auto max-w-7xl space-y-8 p-4 md:p-16 lg:p-32'>
      <div className='max-w-xs mx-auto space-y-8'>
        <h2 className='text-center text-2xl font-bold leading-9 tracking-tight text-gray-900'>
          Sign in 
        </h2>

        <LoginForm />
      </div>
    </main>
  )
}
