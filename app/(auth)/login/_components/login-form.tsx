"use client"

import axios from "axios"
import { toast } from "sonner"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { useRouter } from "next/navigation"
import { zodResolver } from "@hookform/resolvers/zod"

import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import TogglePassword from "@/components/TogglePassword"
import { LoginSchema, loginFormSchema } from "@/lib/types"

export default function LoginForm() {
  const [error, setError] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [passwordInputType, setPasswordInputType] = useState("password")

  const router = useRouter()

  const form = useForm<LoginSchema>({
    resolver: zodResolver(loginFormSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  })

  function togglePassword() {
    setShowPassword(!showPassword)
    return showPassword
      ? setPasswordInputType("password")
      : setPasswordInputType("text")
  }

  async function onSubmit(values: LoginSchema) {
    toast.info("Authenticating your account...")
    try {
      const data = {
        email: values.email,
        password: values.password,
      }

      const result = await axios.post("/api/login", data)

      if (result.data.error) {
        setError(result.data.error)
        toast.error(result.data.error)
      } else {
        router.push("/enquiries")
      }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        setError(true)
      }
    }
  }

  return (
    <>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className='space-y-4 mb-4'>
          {error && (
            <p className='p-3 text-sm text-center text-red-500 font-medium bg-red-50 rounded-lg'>
              {error}
            </p>
          )}

          <FormField
            control={form.control}
            name='email'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email Address</FormLabel>
                <FormControl>
                  <Input
                    placeholder='kipchoge@marathonrunner.com'
                    {...field}
                    type='email'
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='password'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    type={passwordInputType}
                    placeholder='8+ characters'
                    suffix={
                      <TogglePassword
                        showPassword={showPassword}
                        onClick={togglePassword}
                      />
                    }
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button type='submit' className='w-full'>
            Sign in with your account
          </Button>
          <Button
            type='button'
            variant='secondary'
            onClick={() => router.push("/signup")}
            className='w-full'
          >
            No account? Create one
          </Button>
        </form>
      </Form>
    </>
  )
}
