export type NavRoute = {
    id: number
    name: string
    href: string
}

export const navigation: NavRoute[] = [
    { id: 1, name: 'Home', href: '/' },
    { id: 2, name: 'Services', href: '/services' },
    { id: 3, name: 'Projects', href: '/projects' },
    { id: 4, name: 'About Us', href: '/about' },
    { id: 5, name: 'Contact Us', href: '/contact' },
]

export const protectedNavigation: NavRoute[] = [
    { id: 1, name: 'Enquires', href: '/enquiries' },
]

export const defaultUrl =
  process.env.NODE_ENV === "production"
    ? "https://www.mokatbuilder.com/"
    : "http://localhost:3000"