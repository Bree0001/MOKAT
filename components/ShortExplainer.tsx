import React from "react"
import Balancer from "react-wrap-balancer"

type IconTypeProps = {
    className: string
}

type IconType = (props: IconTypeProps) => JSX.Element

type Explainer = {
    title: string
    icon: IconType
    description: string | string[]
}

export default function ShortExplainer({ icon, title, description }: Explainer) {
    return (
        <div className="mt-4 relative max-w-lg">

            <div>
                <div className="absolute">
                    {React.createElement(icon, { className: 'w-6 h-6 text-gray-800' })}
                </div>
                <dt className="ml-8 text-lg text-gray-800 font-medium"><Balancer>{title}</Balancer></dt>
            </div>

            <div className="ml-8 pb-6 sm:pb-7">
                {
                    typeof description === 'string' &&
                    <dd className="mt-2 text-base text-gray-500 font-normal">
                        <Balancer>
                            {description}
                        </Balancer>
                    </dd>
                }

                {
                    Array.isArray(description) &&
                    description.map((item, index) =>
                        <dd key={index} className="mt-2 text-base text-gray-500 font-normal">
                            {item}
                        </dd>
                    )
                }
            </div>
        </div>
    )
}