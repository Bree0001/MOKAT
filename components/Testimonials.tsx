import Balancer from "react-wrap-balancer"

type Testimonial = {
    id: number
    logoScr: string
    logoAlt: string
    review: string
    company: string
    reviewer: string
    position: string
}

const testimonials: Testimonial[] = [
    {
        id: 1,
        company: "Hajar Services",
        position: "Project Manager",
        logoAlt: "Hajar Services Logo",
        logoScr: "/assets/hajar-logo.png",
        reviewer: "Eng. Ephantus Kilonzon",
        review: "Mokat Builders & General Agencies Ltd. successfully undertook and completed the project for the construction of 120 Apartments in Loresho Springs, Nairobi. We congratulate and recommend them for works well done.",

    },
    {
        id: 2,
        reviewer: "Festus Omanga",
        company: "Tosha Petroleum",
        position: "Project Manager",
        logoAlt: "Tosha Petroleum Logo",
        logoScr: "/assets/tosha-logo.png",
        review: "Mokat Builders constructed of our new petrol station and the rehabilitation of two others in Ruiru. We’d like to recommend the Mokat for similar tasks and congratulate them for completing the works on time and as per the project’s specifications.",

    },
    {
        id: 3,
        company: "Hass Petroleum",
        reviewer: "Kenneth O. Ouko",
        logoAlt: "Hass Petroleum Logo",
        position: "Development Manager",
        logoScr: "/assets/hass-logo.png",
        review: "Mokat Builders & General Agencies Ltd. has effectively executed and accomplished the construction project of a new petrol station in Garissa. We congratulate Mokat for their outstanding work and wholeheartedly recommend their services.",

    },
]

export default function Testimonials() {
    return (
        <section className="bg-gray-50 p-4 md:p-8">
            <div className="max-w-7xl mx-auto">
                <span className='text-xs text-orange-500 font-medium'>Testimonials</span>
                <h2 className='text-xl sm:text-3xl text-gray-800 font-medium'>Building since 2003</h2>

                <div className="py-4 sm:py-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:last:gap-8">
                    {testimonials.map(testimonial =>
                        <div key={testimonial.id} className="first:mt-0 mt-8 sm:mt-0 space-y-4 sm:space-y-8">
                            <img className="h-12 w-fit" src={testimonial.logoScr} alt={testimonial.logoAlt} />
                            <p className="text-base sm:text-lg text-gray-500 font-normal leading-7 sm:leading-8"><Balancer>{testimonial.review}</Balancer></p>
                            <div>
                                <h3 className="text-lg text-gray-800 font-medium">{testimonial.reviewer},</h3>
                                <p className="text-sm text-gray-400 font-normal">{testimonial.position} - {testimonial.company}</p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </section>
    )
}
