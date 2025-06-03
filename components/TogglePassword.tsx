import { EyeIcon, EyeOffIcon } from "lucide-react"

type TogglePasswordProps = {
  onClick: () => void
  showPassword: Boolean
}

export default function TogglePassword({
  onClick,
  showPassword,
}: TogglePasswordProps) {
  return (
    <button
      type='button'
      className='text-slate-500 hover:text-orange-500'
      onClick={onClick}
    >
      {showPassword ? <EyeIcon size={16} /> : <EyeOffIcon size={16} />}
    </button>
  )
}
