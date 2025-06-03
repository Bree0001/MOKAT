import moment from 'moment'
import Balancer from 'react-wrap-balancer'
import { Fragment, useState } from 'react'
import { EyeIcon, XIcon } from 'lucide-react'
import { Dialog, Transition } from '@headlessui/react'

export function DetailsModal(enquiry: any) {
    let [isOpen, setIsOpen] = useState(false)

    const message = enquiry.enquiry

    function closeModal() {
        setIsOpen(false)
    }

    function openModal() {
        setIsOpen(true)
    }

    return (
        <>
            <div className="flex items-center justify-center">

                <button type="button" onClick={openModal}>
                    <EyeIcon className="h-4 w-4 text-gray-800 mr-4" aria-hidden="true" />
                </button>

            </div>

            <Transition appear show={isOpen} as={Fragment}>
                <Dialog as="div" className="relative z-10" onClose={closeModal}>
                    <Transition.Child
                        as={Fragment}
                        enter="ease-out duration-300"
                        enterFrom="opacity-0"
                        enterTo="opacity-100"
                        leave="ease-in duration-200"
                        leaveFrom="opacity-100"
                        leaveTo="opacity-0"
                    >
                        <div className="fixed inset-0 backdrop-blur-sm bg-black/30" />
                    </Transition.Child>

                    <div className="fixed inset-0 overflow-y-auto overflow-x-hidden">
                        <div className="flex min-h-full items-center justify-center p-4 text-center">
                            <Transition.Child
                                as={Fragment}
                                enter="ease-out duration-300"
                                enterFrom="opacity-0 scale-95"
                                enterTo="opacity-100 scale-100"
                                leave="ease-in duration-200"
                                leaveFrom="opacity-100 scale-100"
                                leaveTo="opacity-0 scale-95"
                            >
                                <Dialog.Panel className="w-full max-w-3xl transform overflow-hidden  rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">
                                    <div className="flex items-center justify-between">

                                        <div className='pr-4 w-full flex items-center justify-between text-xs text-gray-600'>

                                            <div className='flex items-center justify-center gap-2'>

                                                <Dialog.Title as="h1" className="font-semibold text-primary">
                                                    {message.emailAddress} 
                                                </Dialog.Title>

                                                <h2>{`<${message.phoneNumber}>`} </h2>

                                            </div>

                                            <p>{moment(message.sentAt).format('llll')}</p>

                                        </div>

                                        <button type="button" onClick={closeModal}>
                                            <XIcon className="h-4 w-4 text-gray-800" aria-hidden="true" />
                                        </button>
                                    </div>

                                    <div className="mt-2 space-y-4">

                                        <h4 className='text-lg font-semibold leading-6 text-gray-800 hover:text-gray-950'>
                                            <Balancer>
                                                {message.name}
                                            </Balancer>
                                        </h4>

                                        <div className="w-full border-t border-gray-300" />

                                        <p className=' text-sm leading-8 text-gray-600'>
                                            <Balancer>
                                                {message.message}
                                            </Balancer>
                                        </p>

                                    </div>

                                    {/* <div className="mt-4">
                                        <button
                                            type="button"
                                            className="inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                            onClick={closeModal}
                                        >
                                            Got it, thanks!
                                        </button>
                                    </div> */}
                                </Dialog.Panel>
                            </Transition.Child>
                        </div>
                    </div>
                </Dialog>
            </Transition>
        </>
    )
}