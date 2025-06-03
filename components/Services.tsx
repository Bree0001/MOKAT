import { mainServices } from "@/lib/services"
import Link from "next/link"
import Balancer from "react-wrap-balancer"



export default function Services() {
    return (
        <section className='bg-gray-50/50 p-4 md:p-8'>

            <div className='max-w-7xl mx-auto'>

                <div>
                    <span className='text-xs text-orange-500 font-medium'>Main Services</span>
                    <h2 className='text-xl sm:text-3xl text-gray-800 font-medium'>Building with precision</h2>
                </div>

                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">

                    {
                        mainServices.map(service =>

                            <div key={service.id} className="p-2 bg-gray-50 border border-gray-200 rounded-xl space-y-2">

                                <img className='rounded-lg aspect-square object-cover object-center' src={service.imageSrc} alt={service.imageAlt} />

                                <div className="space-y-4 px-2 pb-2">
                                    <h3 className="text-lg text-gray-800 font-medium">{service.title}</h3>

                                    <p className="text-base text-gray-500 font-normal leading-7">
                                        <Balancer> {service.description} </Balancer>
                                    </p>

                                    <Link
                                        href={`/services#${service.subLink}`}
                                        className="h-fit w-fit inline-flex justify-center py-2 text-sm font-medium rounded-lg text-orange-500 bg-transparent hover:underline decoration-orange-500">
                                        <span>Learn More</span>
                                    </Link>

                                </div>

                            </div>
                        )
                    }

                    <Link href='/services' className="lg:hidden p-2 bg-gray-50 border border-gray-200 rounded-xl space-y-2 flex flex-col justify-center items-center">


                        <img className='w-2/3 rounded-lg aspect-square object-cover object-center' src='/assets/3d-fluency-workers.png' alt='An illustration of construction workers' />
                        <h3 className="text-lg text-gray-800 font-medium">Explore More Services</h3>

                        <p className="text-base text-center text-gray-500 font-normal leading-7">
                            <Balancer>
                                We play a pivotal role in creating residential homes, commercial buildings, infrastructure, and a wide range of construction projects.
                            </Balancer>
                        </p>

                        <Link
                            href='/services'
                            className="h-fit w-fit inline-flex justify-center py-2 text-sm font-medium rounded-lg text-orange-500 bg-transparent hover:underline decoration-orange-500">
                            <span>Learn More</span>
                        </Link>

                    </Link>

                </div>

            </div>

        </section>
    )
}
