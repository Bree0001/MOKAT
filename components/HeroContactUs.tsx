import Balancer from "react-wrap-balancer"

export default function HeroContactUs() {
    return (
        <section>

            <div className="max-w-7xl relative mx-auto">

                <div className="absolute max-w-xl lg:max-w-2xl inset-x-4 sm:left-8 top-20 md:top-10 lg:top-20">

                    <h1 className='sm:mt-4 text-xl lg:text-3xl text-gray-800 font-semibold'>Contact Us</h1>
                    <p className='mt-4 text-base sm:text-lg text-gray-500 font-normal'>
                        <Balancer>
                            Have questions or a project in mind? We're here to help. Reach out by filling the contact form below.
                        </Balancer>
                    </p>

                </div>

            </div>

            <img className="w-full max-h-[400px] object-cover object-center hidden sm:block" src="/assets/hero-contact-us-image.png" alt="Hero Image" />
            <img className="aspect-square object-cover object-center sm:hidden" src="/assets/hero-contact-us-image.png" alt="Hero Image" />

        </section>
    )
}
