'use client'
import { Next13ProgressBar } from 'next13-progressbar'

const Providers = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className=''>
      {children}
      <Next13ProgressBar height="2px" color="#f97316" options={{ showSpinner: true }} showOnShallow />
    </div>
  );
};

export default Providers;