import Balancer from 'react-wrap-balancer'
import HeroAboutUs from '@/components/HeroAboutUs'
import ShortExplainer from '@/components/ShortExplainer'
import { BrainIcon, GoalIcon, HardHatIcon, HeartHandshakeIcon, LightbulbIcon, ScaleIcon, ShieldCheckIcon, UsersIcon } from 'lucide-react'

type member = { id: number, position: string, name: string, description: string }

const team: member[] = [
    { id: 1, name: 'Moses Kamau Thairu', position: 'Founder and Director', description: 'With a relentless passion for construction, Mr.Moses Kamau Thairu is the driving force behind Mokat Builders and General Agencies. As the founder and CEO, Moses has dedicated hithe last 20+ years of his career to shaping the landscape of our communities and building a legacy of excellence in the construction industry.' },
    { id: 2, name: 'Abdiaziz Maalim Mohammed', position: 'Director - Materials', description: 'Mr. Abdiaziz Maalim Mohammed plays a pivotal role in ensuring the structural integrity and quality of our construction projects. With a deep understanding of materials science and an unyielding commitment to excellence, his expertise brings our client’s vision’s to life.' },
    { id: 3, name: 'Elizabeth Cherotich Tanui', position: 'Lead Project Manager', description: 'Mrs. Elizabeth Cherotich Tanui embodies the driving force behind the successful execution of our construction projects. With 15 years of experience in project management and a commitment to delivering excellence, Elizabeth ensures that projects are completed on time and within budget.' },
    { id: 4, name: 'Javan Omondi Omiti', position: 'Lead Construction Manager', description: 'Javan Omondi Omiti has 8 years of experience in the construction industry, which he leverages to turning client’s blueprints into realities. As a master builder, David oversees all aspects of the construction process, from planning to completion. He is dedicated to ensuring that each project is executed to perfection, meeting or exceeding industry standards.' },
]

export default function About() {
    return (
        <main>

            <HeroAboutUs />

            <section className='max-w-7xl mx-auto p-4 md:p-8'>

                <div className='mt-4 grid grid-cols-1 sm:grid-cols-2'>

                    <ShortExplainer icon={props => <GoalIcon {...props} />} title='Mission' description="Be the premier construction and development partner of choice and transform the construction landscape by consistently delivering exceptional quality, ethical practices, and innovative solutions." />

                    <ShortExplainer icon={props => <LightbulbIcon {...props} />} title='Vision' description="Redefine the construction industry by building dreams, forging life-long partnerships, and creating lasting legacies." />

                </div>

                <div className='p-2 grid grid-cols-1 md:grid-cols-2 bg-gray-50 border border-gray-200 rounded-3xl gap-2'>

                    <img className='object-cover object-center rounded-2xl' src="/assets/20-years-of-building.png" alt="Picture of a Mokat construction workers busy working" />

                    <div className='p-2 md:p-4 lg:p-8 flex flex-col justify-center'>
                        <h2 className="text-xl md:text-2xl lg:text-3xl text-gray-800 font-medium">20 years of building</h2>

                        <div className='mt-0 sm:mt-4'>
                            <p className='mt-2 text-base text-gray-500 font-normal leading-7'>
                                <Balancer>
                                    We&#39;ve been in operation since 2003, undertaking large, complex projects, fostering innovation, embracing emerging technologies, and making a difference for our clients, employees and community.
                                </Balancer>
                            </p>

                            <p className='mt-2 text-base text-gray-500 font-normal leading-7 hidden lg:block'>
                                <Balancer>
                                    At Mokat, we strive to implement the right blend of innovative technologies to develop customised solutions that address industry-specific needs.
                                </Balancer>
                            </p>
                        </div>
                    </div>


                </div>

                <div className='mt-4 sm:mt-6 p-2 grid grid-cols-1 md:grid-cols-2 bg-gray-50 border border-gray-200 rounded-3xl gap-4'>

                    <div className='p-2 md:p-4 lg:p-8 flex flex-col justify-center'>
                        <h2 className="text-xl md:text-2xl lg:text-3xl text-gray-800 font-medium">A dedicated team</h2>

                        <div className='mt-0 sm:mt-4'>
                            <p className='mt-2 text-base text-gray-500 font-normal leading-7'>
                                <Balancer>
                                    With a highly trained crew, we are committed to serving our clients to the best of our ability, delivering high-quality projects on time and budget while providing a safe and secure work environment.
                                </Balancer>
                            </p>

                            <p className='mt-2 text-base text-gray-500 font-normal leading-7 hidden lg:block'>
                                <Balancer>
                                    Our goal is to meet our customers' construction needs through quality workmanship and successful relationships with owners, owner's management, and subcontractors.
                                </Balancer>
                            </p>
                        </div>
                    </div>

                    <img className='order-first md:order-last object-cover object-center rounded-2xl' src="/assets/dedicated-team.png" alt="Picture of a Mokat construction workers busy working" />

                </div>

                <section className='mt-4 md:mt-8 py-4 md:py-8 border-y border-gray-200'>

                    <span className='text-xs text-orange-500 font-medium'>Our Team</span>
                    <h2 className='text-2xl sm:text-3xl text-gray-800 font-medium'>Builders crafting success</h2>

                    <div className='mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-8'>
                        {
                            team.map(member =>
                                <div key={member.id} className='space-y-2'>

                                    <h3 className='text-lg text-gray-800 font-medium'>{member.name}</h3>
                                    <h4 className=' text-sm text-gray-600 font-normal'>{member.position}</h4>

                                    <p className='text-base text-gray-500 font-normal leading-7'>
                                        <Balancer>{member.description}</Balancer>
                                    </p>
                                    
                                </div>
                            )
                        }
                    </div>

                </section>


                <section className='mt-4 md:mt-8'>

                    <span className='text-xs text-orange-500 font-medium'>Core Values</span>
                    <h2 className='text-2xl sm:text-3xl text-gray-800 font-medium'>Why build with us</h2>

                    <div className='mt-4 grid grid-cols-1 sm:grid-cols-2'>

                        <ShortExplainer icon={props => <ScaleIcon {...props} />} title='Integrity' description="We uphold the highest standards of honesty, transparency, and ethical behaviour in all our interactions, both within our team and with our clients, suppliers, and partners." />

                        <ShortExplainer icon={props => <ShieldCheckIcon {...props} />} title='Quality Craftsmanship' description="We are committed to delivering exceptional quality in every project. Our work reflects our dedication to craftsmanship and attention to detail." />

                        <ShortExplainer icon={props => <HeartHandshakeIcon {...props} />} title='Customer Centric' description="Our clients are at the centre of everything we do. We actively listen to your needs, communicate openly, and go the extra mile to exceed your expectations." />

                        <ShortExplainer icon={props => <HardHatIcon {...props} />} title='Safety First' description="We prioritise the safety and well-being of our employees, subcontractors, and clients. We maintain rigorous safety standards and practices on all job sites." />

                        <ShortExplainer icon={props => <BrainIcon {...props} />} title='Innovation' description="We embrace innovative construction techniques, technology, and materials. We continuously seek new and better ways to deliver value to our clients and improve our processes." />

                        <ShortExplainer icon={props => <UsersIcon {...props} />} title='Community Engagement' description="We actively engage with and give back to the communities where we work. We support local initiatives and strive to be a responsible corporate citizen." />

                    </div>

                </section>

            </section>


        </main>
    )
}
