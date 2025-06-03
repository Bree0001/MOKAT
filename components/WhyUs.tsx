import { MapPin } from 'lucide-react'
import Balancer from 'react-wrap-balancer'

type Achievement = {
    id: number
    title: string
    achievement: string
    description: string
}

const achievements: Achievement[] = [
    { id: 1, achievement: '100+', title: 'Customers', description: 'Proven track record of success' },
    { id: 2, achievement: '20+', title: 'Years', description: 'Over two decades of experience' },
    { id: 3, achievement: '50+', title: 'Commercial Buildings', description: 'We have built and renovated numerous office buildings' },
    { id: 4, achievement: '30+', title: 'Residential Buildings', description: 'We have built numerous residential buildings' },
]

export default function WhyUs() {
    return (
        <section className='max-w-7xl mx-auto p-4 md:p-8'>

            <span className='text-xs text-orange-500 font-medium'>Why Us</span>
            <h2 className='text-xl sm:text-3xl text-gray-800 font-medium'>Build something great</h2>
            <p className='mt-2 text-base text-gray-500 font-normal'>
                <Balancer>
                    We leverage the latest technologies, materials, and construction techniques - <br />
                    from concept design and construction to final inspection
                </Balancer>
            </p>

            <div className='py-4 md:py-8 grid grid-cols-1 md:grid-cols-2 gap-4'>

                <div className='py-8 sm:py-0 lg:pr-20 grid grid-cols-2 gap-4'>

                    {achievements.map(achievement =>

                        <div key={achievement.id} className='sm:mt-8 flex flex-col items-center justify-center gap-1'>
                            <h3 className='text-3xl md:text-4xl lg:text-6xl text-orange-500 font-medium'>{achievement.achievement}</h3>
                            <h4 className='text-sm text-gray-800 font-medium text-center'>{achievement.title}</h4>
                            <p className='text-sm text-gray-400 font-normal text-center'>
                                <Balancer>
                                    {achievement.description}
                                </Balancer>
                            </p>
                        </div>
                    )}


                </div>

                <div className='order-first sm:order-last'>
                    <img className='w-full h-full object-center object-cover rounded-lg' src='/assets/kitambo-gardens.png' alt='Kitambo Gardens Building' />
                    <div className='flex gap-1 sm:justify-end items-center mt-2 text-sm text-gray-400 font-normal'>
                        <MapPin className='w-4 h-4' />
                        <p>Kitambo Gardens - Karen, Nairobi</p>
                    </div>
                </div>

            </div>

        </section>
    )
}
