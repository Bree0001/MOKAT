'use client'

import { Toaster, toast } from 'sonner'
import { useFormStatus } from "react-dom"

export default function ContactFormButton() {

    const { pending } = useFormStatus()

    if (pending) {
        toast('Sending your message...')
    }

    return (

        <div>
            <Toaster position="top-right" />

            <button
                type='submit' aria-disabled={pending}
                className="h-fit w-full relative inline-flex justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-orange-500 shadow-sm hover:bg-orange-600 disabled:bg-orange-700">
                <span>{pending ? 'Sending...' : 'Send Message'}</span>
            </button>

        </div>
    )
}