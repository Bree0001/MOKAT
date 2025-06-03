import ImageCarousel from "@/components/ImagesCarousel"
import { projects } from "@/lib/projects"
import Balancer from "react-wrap-balancer"

export default function Projects() {

    return (
        <main className='max-w-7xl mx-auto p-4 md:p-8 lg:pt-16'>

            <div>
                <h1 className='sm:mt-8 text-xl lg:text-3xl text-gray-800 font-semibold'>Projects</h1>
                <p className='mt-4 text-base sm:text-lg text-gray-500 font-normal'>
                    <Balancer>
                        Mokat Builders & General Agencies is a leading development contractor duly <br className='hidden lg:block' />
                        registered and certified to undertake residential, commercial, institutional, and <br className='hidden lg:block' />
                        industrial construction projects.
                    </Balancer>
                </p>
            </div>

            <section className='mt-4 space-y-4 sm:space-y-8'>

                {projects.map(project =>
                    <div key={project.id} className='p-1 gap-2 rounded-xl bg-gray-50 border border-gray-200 hover:cursor-pointer'>
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-1">

                            <div className="col-span-2 overflow-hidden rounded-xl group">
                                <img className="h-full w-full aspect-video object-cover object-center rounded-md transition ease-in-out group-hover:scale-125 duration-500 delay-150"
                                    src={project.projectImageSrc[0]} alt={project.projectImageAlt} />
                            </div>

                            <div className="p-2 sm:p-4 flex justify-between">

                                <div className="flex flex-col justify-between space-y-4">
                                    <div>
                                        <h2 className="text-lg text-gray-800 font-medium">{project.projectName}</h2>
                                        <h3 className="text-sm text-gray-500 font-normal">{project.location}</h3>
                                    </div>
                                    <ImageCarousel project={project} />
                                </div>

                                <p className='text-xs text-orange-500 font-medium'>#{project.type}</p>
                            </div>

                        </div>


                    </div>
                )}

            </section>
        </main>
    )
}
