import Balancer from 'react-wrap-balancer'
import ContactForm from './_components/ContactForm'
import ShortExplainer from '@/components/ShortExplainer'
import { BuildingIcon, MailCheckIcon, PhoneCall } from 'lucide-react'
import HeroContactUs from '@/components/HeroContactUs'

export default function Contact() {
    return (
        <main>

            <HeroContactUs />

            <section className='mt-4 grid grid-cols-1 sm:grid-cols-2 max-w-7xl mx-auto p-4 md:p-8'>

                <div>

                <h2 className="pb-4 text-2xl sm:text-3xl text-gray-800 font-medium">Fastest way to reach us</h2>

                    <ShortExplainer icon={props => <PhoneCall {...props} />} title='Call Us' description='+254 722 680 305' />
                    <ShortExplainer icon={props => <MailCheckIcon {...props} />} title='Email Us' description='mokatlimited@gmail.com' />
                    <ShortExplainer icon={props => <BuildingIcon {...props} />} title='Visit our office' description={['3rd Floor', 'Room 305, Nanak House', 'Nairobi CBD, Nairobi County']} />
                </div>

                <div>
                    <ContactForm />
                </div>

            </section>
        </main>
    )
}
