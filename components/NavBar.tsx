"use client"

import Link from "next/link"
import { navigation } from "@/lib/routes"
import { MenuIcon, X } from "lucide-react"
import { usePathname } from "next/navigation"
import { Disclosure } from "@headlessui/react"

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(" ")
}

export default function NavBar() {
  const pathname = usePathname()

  return (
    <Disclosure as='nav' className='absolute w-full backdrop-blur-lg'>
      {({ open }: any) => (
        <>
          <div className='mx-auto max-w-7xl px-2 sm:px-6 lg:px-8'>
            <div className='relative flex h-16 items-center justify-between'>
              <div className='absolute inset-y-0 left-0 flex items-center sm:hidden'>
                {/* Mobile menu button*/}
                <Disclosure.Button className='relative inline-flex items-center justify-center rounded-md p-2 text-gray-400 hover:text-orange-500 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white'>
                  <span className='absolute -inset-0.5' />
                  <span className='sr-only'>Open main menu</span>
                  {open ? (
                    <X className='block h-6 w-6' aria-hidden='true' />
                  ) : (
                    <MenuIcon className='block h-6 w-6' aria-hidden='true' />
                  )}
                </Disclosure.Button>
              </div>
              <div className='flex'>
                <Link href='/' className='flex flex-shrink-0 items-center'>
                  <img
                    className='ml-12 sm:ml-0 rounded-md'
                    src='/assets/logo.png'
                    alt='Your Company'
                    width='160'
                    height='40'
                  />
                </Link>
                <div className='hidden sm:ml-6 sm:block'>
                  <div className='flex space-x-4'>
                    {navigation?.map((link) => {
                      const isActive = pathname === link.href

                      return (
                        <Link
                          href={link.href}
                          key={link.id}
                          className={
                            isActive
                              ? "inline-flex items-center px-1 py-2 text-orange-500 text-sm font-medium"
                              : "text-gray-400 hover:text-orange-400 inline-flex items-center px-1 py-2 text-sm font-medium"
                          }
                        >
                          {link.name}
                        </Link>
                      )
                    })}
                  </div>
                </div>
              </div>
              <div className='absolute inset-y-0 right-0 flex items-center pr-2 sm:static sm:inset-auto sm:ml-6 sm:pr-0'>
                {/*CTA Button */}

                <Link
                  href='/contact'
                  className='h-fit w-full relative inline-flex justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-orange-500 shadow-sm hover:bg-orange-600'
                >
                  <span>Get in touch</span>
                </Link>
              </div>
            </div>
          </div>

          <Disclosure.Panel className='sm:hidden'>
            <div className='space-y-1 px-2 pb-3 pt-2'>
              {navigation?.map((link) => {
                const isActive = pathname === link.href

                return (
                  <Disclosure.Button
                    key={link.name}
                    as='a'
                    href={link.href}
                    className={classNames(
                      isActive
                        ? "bg-orange-500 text-white"
                        : "text-gray-500 hover:bg-orange-100 hover:text-orange-500",
                      "block rounded-md px-3 py-2 text-base font-medium"
                    )}
                  >
                    {link.name}
                  </Disclosure.Button>
                )
              })}
            </div>
          </Disclosure.Panel>
        </>
      )}
    </Disclosure>
  )
}
