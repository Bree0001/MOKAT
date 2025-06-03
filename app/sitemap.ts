import { MetadataRoute } from 'next'
 
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: 'https://www.mokatbuilder.com',
      lastModified: new Date(),
    },
    {
      url: 'https://www.mokatbuilder.com/services',
      lastModified: new Date(),
    },
    {
      url: 'https://www.mokatbuilder.com/projects',
      lastModified: new Date(),
    },
    {
        url: 'https://www.mokatbuilder.com/contact',
        lastModified: new Date(),
      },
      {
        url: 'https://www.mokatbuilder.com/about',
        lastModified: new Date(),
      },
  ]
}