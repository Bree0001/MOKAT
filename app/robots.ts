import { MetadataRoute } from "next"

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: ["/", "/services", "/projects", "/about", "/contact"],
      disallow: ["/enquiries", "/login", "/signup"],
    },
    sitemap: "https://www.mokatbuilder.com/sitemap.xml",
  }
}
