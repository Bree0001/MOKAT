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
import { SignUpSchema, signUpFormSchema } from "@/lib/types"

export default function SignUpForm() {
  const [error, setError] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [passwordInputType, setPasswordInputType] = useState("password")

  const router = useRouter()

  const form = useForm<SignUpSchema>({
    resolver: zodResolver(signUpFormSchema),
    defaultValues: {
      username: "",
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

  async function onSubmit(values: SignUpSchema) {
    toast.info("Creating your account...")
    try {
      const data = {
        email: values.email,
        username: values.username,
        password: values.password,
      }

      await axios.post("/api/signup", data)
      router.push("/enquiries")
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
          <FormField
            control={form.control}
            name='username'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Username</FormLabel>
                <FormControl>
                  <Input placeholder='Kipchoge' {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

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
            Join the club now
          </Button>
          <Button
            type='button'
            variant='secondary'
            onClick={() => router.push("/login")}
            className='w-full'
          >
            Have an account? Login
          </Button>
        </form>
      </Form>
    </>
  )
}
