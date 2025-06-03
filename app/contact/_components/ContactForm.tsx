'use client'

import { toast } from "sonner"
import { useState } from "react"
import MessageSent from "./MessageSent"
import handleContact from "@/actions/handleContact"

export default function ContactForm() {

    const [pending, setPending] = useState(false)
    const [submitted, setSubmitted] = useState(false)

    async function submitContact(formData: FormData) {
        setPending(true)
        const result = await handleContact(formData)

        if (result) {
            setSubmitted(true)
        }
    }

    if (pending) {
        toast('Sending your message...')
    }

    return (
        <div>
            {submitted && <MessageSent />}

            <p className={submitted ? 'hidden' : 'text-base font-normal text-gray-600'}>Our friendly team is always here to chat.</p>

            <form action={submitContact} className={submitted ? 'hidden' : "mt-4 md:mt-8  w-full max-w-lg space-y-6"}>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                    <div>
                        <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                            Name
                        </label>
                        <div className="mt-1">
                            <input
                                type="text"
                                name="name"
                                id="name"
                                required
                                className="py-1.5 px-3 shadow-sm border border-gray-300 focus:ring-orange-500 focus:border-orange-500 block w-full sm:text-sm rounded-md"
                                placeholder="Eliud Kipchoge"
                            />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                            Email Address
                        </label>
                        <div className="mt-1">
                            <input
                                type="email"
                                name="email"
                                id="email"
                                required
                                className="py-1.5 px-3 shadow-sm border border-gray-300 focus:ring-orange-500 focus:border-orange-500 block w-full sm:text-sm rounded-md"
                                placeholder="kipchoge@marathonrunner.com"
                            />
                        </div>
                    </div>
                </div>

                <div>
                    <label htmlFor="phone" className="block text-sm font-medium text-gray-700">
                        Phone Number
                    </label>
                    <div className="mt-1">
                        <input
                            type="text"
                            name="phone"
                            id="phone"
                            required
                            className="py-1.5 px-3 shadow-sm border border-gray-300 focus:ring-orange-500 focus:border-orange-500 block w-full sm:text-sm rounded-md"
                            placeholder="0712345678"
                        />
                    </div>
                </div>

                <div className="col-span-full">
                    <label htmlFor="message" className="block text-sm font-medium leading-6 text-gray-900">
                        Message
                    </label>
                    <div className="mt-2">
                        <textarea
                            id="message"
                            name="message"
                            rows={5}
                            required
                            placeholder="Type your message here..."
                            className="py-1.5 px-3 block w-full rounded-md border border-gray-300 active:border-orange-500 focus:border-orange-500 text-gray-900 shadow-sm placeholder:text-gray-400 sm:text-sm sm:leading-6"
                        />
                    </div>
                </div>

                <div className='flex items-center'>
                    <button
                        type='submit' disabled={pending}
                        className="h-fit w-full relative inline-flex justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-orange-500 shadow-sm hover:bg-orange-600 disabled:bg-orange-700 disabled:cursor-not-allowed">
                        <span>{pending ? 'Sending...' : 'Send Message'}</span>
                    </button>
                </div>

            </form>
        </div>
    )
}
