export type Project = {
    id: number
    location: string
    projectName: string
    projectImageAlt: string
    projectImageSrc: string[]
    type: 'commercial' | 'residential' | 'roads' | 'renovation'
}

export const projects: Project[] = [
    {
        id: 1,
        projectName: 'Don Bosco Shrine',
        location: 'Upper Hill, Nairobi',
        type: 'renovation',
        projectImageSrc: ['/assets/projects/Don-Bosco-Shrine/IMG-20230523-WA0047.jpg', '/assets/projects/Don-Bosco-Shrine/IMG-20230523-WA0055.jpg', '/assets/projects/Don-Bosco-Shrine/IMG-20230523-WA0049.jpg', ],
        projectImageAlt: '',
    },
    {
        id: 2,
        projectName: 'KIPS College',
        location: 'Donholm, Nairobi',
        type: 'commercial',
        projectImageSrc: ['/assets/projects/KIPS-College/IMG-20230523-WA0012.jpg', '/assets/projects/KIPS-College/IMG-20230523-WA0040.jpg', '/assets/projects/KIPS-College/IMG-20230523-WA0043.jpg', ],
        projectImageAlt: '',
    },
    {
        id: 3,
        projectName: 'Matuu Level 5 Isolation Ward',
        location: 'Matuu, Machakos',
        type: 'commercial',
        projectImageSrc: ['/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0035.jpg', '/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0021.jpg', '/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0022.jpg', '/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0024.jpg', '/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0025.jpg', '/assets/projects/Matuu-L5-Ward/IMG-20230523-WA0028.jpg', ],
        projectImageAlt: '',
    },
    {
        id: 4,
        projectName: 'Rubis Petrol Station',
        location: 'Ruiru, Kiambu',
        type: 'commercial',
        projectImageSrc: ['/assets/projects/Rubis-Petrol-Station/IMG-20230523-WA0013.jpg', '/assets/projects/Rubis-Petrol-Station/IMG-20230523-WA0003.jpg', '/assets/projects/Rubis-Petrol-Station/IMG-20230523-WA0041.jpg', ],
        projectImageAlt: '',
    },
    {
        id: 5,
        projectName: 'Thindigua Mall',
        location: 'Thindigua, Kiambu',
        type: 'commercial',
        projectImageSrc: ['/assets/projects/Thindigua-Mall/IMG-20230523-WA0004.jpg', '/assets/projects/Thindigua-Mall/IMG-20230523-WA0002.jpg', '/assets/projects/Thindigua-Mall/IMG-20230523-WA0006.jpg', ],
        projectImageAlt: '',
    },
    {
        id: 6,
        projectName: 'Vipro Go-Downs',
        location: 'Eastern By-Pass, Ruiru',
        type: 'commercial',
        projectImageSrc: ['/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0017.jpg', '/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0015.jpg', '/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0023.jpg', '/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0033.jpg', '/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0036.jpg', '/assets/projects/Vipro-Go-Downs/IMG-20230523-WA0046.jpg', ],
        projectImageAlt: '',
    },
]

projects.forEach(project => {
    project.projectImageAlt = `Picture of the ${project.projectName} construction project done by Mokat Builders`
})