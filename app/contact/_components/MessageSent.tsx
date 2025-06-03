import React from 'react'
import Balancer from 'react-wrap-balancer'

export default function MessageSent() {
  return (
    <section className='mt-4 flex flex-col'>
      <img className='w-full max-w-md object-cover object-center' src="/assets/bouncy-a-paper-airplane-with-a-check-mark.gif" alt="Animated GIF illustrating a message being sent - GIF shown after contact form is successfully submitted" />
      <p className="text-base font-normal text-gray-600 text-center">
        <Balancer>
          We have received your meessage. <br />
          We will reach out soon.
        </Balancer>
      </p>
    </section>
  )
}
