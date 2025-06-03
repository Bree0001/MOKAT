"use client"

import Link from 'next/link'
import { faqs } from '@/lib/faqs'
import Balancer from 'react-wrap-balancer'
import { Disclosure } from '@headlessui/react'
import { ChevronDownIcon } from 'lucide-react'

function classNames(...classes: string[]) {
    return classes.filter(Boolean).join(' ')
}

export default function FAQs() {
    return (
        <section className='max-w-7xl mx-auto p-4 md:p-8'>

            <div className='grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-8'>

                <div>
                    <span className='text-xs text-orange-500 font-medium'>FAQs</span>
                    <h2 className='text-xl sm:text-3xl text-gray-800 font-medium'>Frequently Asked Questions</h2>
                    <p className='mt-4 text-base text-gray-500 font-normal'>
                        <Balancer>Can&#39;t find the answer you&#39;re looking for?
                            Reach out to our <Link href='/' className='text-orange-500 hover:underline hover:decoration-orange-500'>customer support</Link> team.
                        </Balancer>
                    </p>
                </div>

                <div className="max-w-3xl lg:col-span-2 divide-y-2 divide-gray-200">
                    <dl className="mt-2 space-y-6 divide-y divide-gray-200">
                        {faqs.map((faq) => (
                            <Disclosure as="div" key={faq.id} className="pt-6">
                                {({ open }) => (
                                    <>
                                        <dt className="text-lg">
                                            <Disclosure.Button className="text-left w-full flex justify-between items-start text-gray-400">
                                                <span className="text-base sm:text-lg font-medium text-gray-900">{faq.question}</span>
                                                <span className="ml-6 h-7 flex items-center">
                                                    <ChevronDownIcon
                                                        className={classNames(open ? '-rotate-180' : 'rotate-0', 'h-6 w-6 transform')}
                                                        aria-hidden="true"
                                                    />
                                                </span>
                                            </Disclosure.Button>
                                        </dt>
                                        <Disclosure.Panel as="dd" className="mt-2 pr-12">
                                            <p className="text-base text-gray-500">{faq.answer}</p>
                                        </Disclosure.Panel>
                                    </>
                                )}
                            </Disclosure>
                        ))}
                    </dl>
                </div>


            </div>

        </section>
    )
}
