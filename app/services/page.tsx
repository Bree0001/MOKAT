import Link from 'next/link'
import Balancer from 'react-wrap-balancer'
import ShortExplainer from '@/components/ShortExplainer'
import { ConstructionIcon, DropletsIcon, LayoutDashboardIcon, ShapesIcon } from 'lucide-react'
import HeroServices from '@/components/HeroServices'

export default function Services() {
    return (
        <main>

            <HeroServices />

            <section className='mt-4 max-w-7xl mx-auto p-4 md:p-8'>
                <div className='p-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 bg-gray-50 border border-gray-200 rounded-3xl'>

                    <div id='new-properties' className='p-1 sm:p-4'>

                        <h2 className="mt-2 sm:mt-0 text-lg text-gray-800 font-medium">Build new properties</h2>

                        <div className='py-4 md:py-8 lg:py-12 flex flex-col justify-between'>

                            <div>
                                <p className='mt-2 text-base text-gray-500 font-normal leading-7 hidden lg:block'>
                                    <Balancer>
                                        Our skilled team of professionals excels in turning your concepts into tangible small, medium-sized and large structures.
                                        Whether it's an office building, retail space, residential building, institutional block, or industrial facility,
                                        we handle every aspect of the project, from initial design and permitting to construction and final inspection.
                                    </Balancer>
                                </p>
                                <p className='mt-2 text-base text-gray-500 font-normal leading-7'>
                                    <Balancer>
                                        From concept design and blueprints to groundbreaking, construction, interior design, and landscaping.
                                        Our experienced team works with you to turn your vision into reality and deliver a functional and aesthetically pleasing space.
                                    </Balancer>
                                </p>
                            </div>

                            <Link
                                href='/contact'
                                className="mt-2 sm:mt-4 h-fit w-fit inline-flex justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-orange-500 shadow-sm hover:bg-orange-600">
                                <span>Let&#39;s build together</span>
                            </Link>

                        </div>

                    </div>

                    <div className='lg:col-span-2 order-first md:order-last'>
                        <img className='rounded-2xl w-full h-full object-cover object-center' src="/assets/build-new-properties-image.png" alt="A new building currently being constructed" />
                    </div>

                </div>

                <div id='property-renovation' className='mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4'>

                    <div className='p-2 bg-gray-50 border border-gray-200 rounded-3xl'>
                        <img className='object-cover object-center rounded-2xl' src="/assets/property-renovation-image.png" alt="Picture of an old building be renovated" />

                        <div className='space-y-4 px-2 pb-4'>
                            <h2 className="mt-4 text-lg text-gray-800 font-medium">Property Renovations and Expansions</h2>

                            <div>
                                <p className='mt-2 text-base text-gray-500 font-normal leading-7'>
                                    <Balancer>
                                        We help you reimagine layouts, incorporate modern amenities, and upgrade infrastructure, 
                                        breathing new life into your property by refurbishing or enlarging it.
                                        Whether your facility needs a modern makeover, structural improvements, or a complete interior renovation, we have the expertise to transform it.
                                    </Balancer>
                                </p>

                            </div>

                            <Link
                                href='/contact'
                                className="h-fit w-fit inline-flex justify-center px-4 py-2 border border-orange-500 text-sm font-medium rounded-lg text-orange-500 bg-orange-100 shadow-sm hover:bg-orange-200/70">
                                <span>Rediscover your property&#39;s charm</span>
                            </Link>
                        </div>

                    </div>

                    <div id='road-works' className='p-2 bg-gray-50 border border-gray-200 rounded-3xl'>
                        <img className='object-cover object-center rounded-2xl' src="/assets/road-construction.png" alt="Picture of a road being constructed" />

                        <div className='space-y-4 px-2 pb-4'>
                            <h2 className="mt-4 text-lg text-gray-800 font-medium">Civil and Road Works</h2>

                            <div>
                                <p className='mt-2 text-base text-gray-500 font-normal leading-7'>
                                    <Balancer>
                                        We specialise in designing and constructing the essential infrastructure that supports your commercial projects.
                                        From grading and site preparation to installation of roadways, utilities, and drainage systems,
                                        we ensure that the essential infrastructure of your project is well-planned and executed.
                                    </Balancer>
                                </p>

                                <p className='mt-2 text-base text-gray-500 font-normal leading-7 hidden lg:block'>
                                    <Balancer>
                                        Safety, efficiency, and compliance with regulations are paramount in our civil and road works.
                                    </Balancer>
                                </p>
                            </div>

                            <Link
                                href='/contact'
                                className="h-fit w-fit inline-flex justify-center px-4 py-2 border border-orange-500 text-sm font-medium rounded-lg text-orange-500 bg-orange-100 shadow-sm hover:bg-orange-200/70">
                                <span>Let&#39;s pave the way together</span>
                            </Link>
                        </div>

                    </div>

                </div>

            <div className='mt-4  grid grid-cols-1 sm:grid-cols-2'>
                <ShortExplainer icon={props => <LayoutDashboardIcon {...props} />} title='Interior and Exterior Design' description={['Our interior and exterior design services are the cornerstone of creating spaces that inspire, captivate, and function seamlessly.', 'We meticulously plan and design every interior detail, including layout, colour schemes, furnishings, lighting, and décor.', 'Through landscaping, facade design and architectural elements, we transform outdoor areas that blend seamlessly with your property and surroundings.']} />

                <ShortExplainer icon={props => <ConstructionIcon {...props} />} title='Property Development' description={['From site selection and feasibility studies to design, permitting, and construction, we guide you through the entire development process for residential, commercial, and mixed-use properties.', 'The goal is to create sustainable, profitable, and attractive developments that meet the unique needs of our clients.']} />

                <ShortExplainer icon={props => <ShapesIcon {...props} />} title='Supply of Construction Material' description={['We supply a wide range of construction materials, including cement, steel, bricks, concrete blocks, insulation, and finishing materials and provide a one-stop solution for all your building needs.', 'Our materials are sourced from trusted suppliers, meeting industry standards for strength and durability and delivered on time to minimise delays and keep projects on schedule.']} />

                <ShortExplainer icon={props => <DropletsIcon {...props} />} title='Construction of Water Storage Facilities ' description={['We design and construct water          reservoirs and tanks of various sizes and capacities using durable materials and advanced engineering techniques.', 'These include raised water tanks and           underground water structures built to withstand the test of time and ensure a consistent and secure water supply for your community or project.']} />
            </div>

            </section>


        </main>
    )
}
