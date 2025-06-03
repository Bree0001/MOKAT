'use client'

import { Project } from '@/lib/projects'
import { Fragment, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { ChevronLeftIcon, ChevronRightIcon, XIcon } from 'lucide-react'

export default function ImageCarousel({ project }: { project: Project }) {

    const [isOpen, setIsOpen] = useState(false)
    const [currentIndex, setCurrentIndex] = useState(0)

    function closeModal() {
        setIsOpen(false)
    }

    function openModal() {
        setIsOpen(true)
    }

    function handlePreviousImage() {
        if (currentIndex === 0) {
            setCurrentIndex(project.projectImageSrc.length - 1)
            return
        }

        setCurrentIndex(prev => prev - 1)
    }

    function handleNextImage() {
        if ((project.projectImageSrc.length - 1) === currentIndex) {
            setCurrentIndex(0)
            return
        }

        setCurrentIndex(next => next + 1)
    }

    return (
        <>
            <div className="flex items-center">
                <button
                    type="button"
                    onClick={openModal}
                    className="rounded-lg bg-orange-100 hover:bg-orange-200/70 border border-orange-500 px-4 py-2 text-sm font-medium text-orange-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500 focus-visible:ring-opacity-75"
                >
                    View Project Site
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
                        <div className="fixed inset-0 bg-black bg-opacity-25 grayscale-0 backdrop-blur" />
                    </Transition.Child>

                    <div className="fixed inset-0 overflow-y-auto">
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
                                <Dialog.Panel className="w-full max-w-7xl transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">

                                    <div className='flex justify-between items-center'>
                                        <Dialog.Title
                                            as="h3"
                                            className="text-lg font-medium leading-6 text-gray-900"
                                        >
                                            {project.projectName}
                                        </Dialog.Title>
                                        <button type='button' onClick={closeModal}>
                                            <XIcon className='w-6 h-6 text-gray-500 hover:text-gray-800' aria-hidden="true" />
                                        </button>
                                    </div>

                                    <section className='mt-4 relative'>

                                        <button type='button' onClick={handlePreviousImage} className='p-1 w-6 sm:w-8 h-6 sm:h-8 absolute inset-y-1/2 left-2 bg-gray-100 hover:bg-orange-100 text-gray-500 hover:text-orange-500 rounded-full flex items-center justify-center'>
                                            <ChevronLeftIcon className='w-6 h-6' aria-hidden='true' />
                                        </button>

                                        <button type='button' onClick={handleNextImage} className='p-1 w-6 sm:w-8 h-6 sm:h-8 absolute inset-y-1/2 right-2 bg-gray-100 hover:bg-orange-100 text-gray-500 hover:text-orange-500 rounded-full flex items-center justify-center'>
                                            <ChevronRightIcon className='w-6 h-6 text-gray-500 group-hover:text-orange-500' aria-hidden='true' />
                                        </button>

                                        <img className="mt-4 h-full w-full aspect-video object-cover object-center rounded-md transition ease-in-out group-hover:scale-125 duration-500 delay-150"
                                            src={project.projectImageSrc[currentIndex]} alt={project.projectImageAlt} />


                                    </section>

                                    <div className="mt-2 flex items-center justify-between">
                                        <p className="text-sm text-gray-500"> {project.location} </p>
                                        <p className='text-xs text-orange-500 font-medium'>#{project.type}</p>
                                    </div>


                                </Dialog.Panel>
                            </Transition.Child>
                        </div>
                    </div>
                </Dialog>
            </Transition>
        </>
    )
}
