import { ArrowRightIcon } from "lucide-react"
import Link from "next/link"
import Balancer from "react-wrap-balancer"

export default function Hero() {
  return (
    <section>
      <div className='max-w-7xl relative mx-auto'>
        <div className='pt-16 absolute max-w-xl lg:max-w-2xl inset-x-4 sm:left-8 top-20 md:top-10 lg:top-20'>
          <Link
            href='/projects'
            className='py-1 px-3 text-orange-500 bg-orange-50 hover:bg-orange-100 rounded-full w-fit flex items-center justify-center gap-1'
          >
            <span className='text-xs font-medium'>Latest Projects </span>
            <ArrowRightIcon className='w-4 h-4' />
          </Link>
          <h1 className='mt-2 text-2xl md:text-3xl lg:text-4xl xl:text-6xl text-gray-800 font-semibold'>
            Building Dreams
          </h1>
          <p className='mt-2 sm:mt-4 text-sm lg:text-lg text-gray-500 font-normal leading-6 lg:leading-7'>
            <Balancer>
              When it comes to high-end commercial, residential, and industrial
              construction, Mokat Builders and General Agencies Ltd. is the
              contractor you can trust. We are dedicated to delivering unmatched
              quality, exceptional craftsmanship, and exemplary service to all
              our clients.
            </Balancer>
          </p>

          <div className='mt-4 lg:mt-12 flex gap-4'>
            <Link
              href='/contact'
              className='h-fit w-fit relative inline-flex justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-orange-500 shadow-sm hover:bg-orange-600'
            >
              <span>Get in touch</span>
            </Link>

            <Link
              href='/services'
              className='h-fit w-fit inline-flex justify-center px-1 sm:px-4 py-2 text-sm font-medium text-gray-800 hover:text-orange-500 bg-transparent hover:underline decoration-orange-500'
            >
              <span>Browse services</span>
            </Link>
          </div>
        </div>
      </div>

      <img
        className='w-full max-h-[560px] object-cover object-center hidden sm:block'
        src='/assets/hero-image.png'
        alt='Hero Image'
      />
      <img
        className='w-full h-fit object-cover object-center sm:hidden'
        src='/assets/hero-image-mobile.png'
        alt='Hero Image'
      />
    </section>
  )
}
