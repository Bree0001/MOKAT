type service = {
    id: number
    title: string
    subLink: string
    imageSrc: string
    imageAlt: string
    description: string
}

export const mainServices: service[] = [
    {
        id: 1,
        subLink: 'new-properties',
        title: 'Build new properties',
        imageSrc: '/assets/build-new-properties-image.png',
        imageAlt: 'A new building currently being constructed',
        description: 'Our experienced team works with you to turn your vision into reality and deliver a functional and aesthetically pleasing space.'
    },
    {
        id: 2,
        subLink: 'property-renovation',
        imageSrc: '/assets/property-renovation-image.png',
        imageAlt: 'Picture of an old building be renovated',
        title: 'Property Renovations and Expansions',
        description: 'We help you reimagine layouts, incorporate modern amenities, and upgrade infrastructure and breathe new life into your property'
    },
    {
        id: 3,
        subLink: 'road-works',
        title: 'Civil and Road Works',
        imageSrc: '/assets/road-construction.png',
        imageAlt: 'Picture of a road being constructed',
        description: 'From site preparation to installation of roadways, and drainage systems, we ensure that the your project is well executed.'
    }
]