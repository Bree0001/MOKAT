import Balancer from "react-wrap-balancer"

export default function HeroServices() {
    return (
        <section>

            <div className="max-w-7xl relative mx-auto">

                <div className="absolute max-w-xl lg:max-w-2xl inset-x-4 sm:left-8 top-20 md:top-10 lg:top-20">

                    <h1 className='sm:mt-4 text-xl lg:text-3xl text-gray-800 font-semibold'>Services</h1>
                    <p className='mt-4 text-base sm:text-lg text-gray-500 font-normal'>
                        <Balancer>
                            Mokat Builders & General Agencies specialises in residential, commercial, <br className='hidden lg:block' />
                            institutional, and industrial construction projects.
                        </Balancer>
                    </p>

                </div>

            </div>

                <img className="w-full max-h-[360px] object-cover object-center hidden sm:block" src="/assets/services-hero-image.png" alt="Hero Image" />
                <img className="aspect-square object-cover object-center sm:hidden" src="/assets/services-hero-image.png" alt="Hero Image" />

        </section>
    )
}
