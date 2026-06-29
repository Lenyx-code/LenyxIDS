export function Badge({ severity }) {
  const styles = {
    CRITICAL: "bg-red-500/20 text-red-400 border border-red-500/40",
    HIGH:     "bg-orange-500/20 text-orange-400 border border-orange-500/40",
    MEDIUM:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
    LOW:      "bg-blue-500/20 text-blue-400 border border-blue-500/40",
    open:     "bg-red-500/20 text-red-400 border border-red-500/40",
    closed:   "bg-green-500/20 text-green-400 border border-green-500/40",
  }

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${styles[severity] || styles.LOW}`}>
      {severity}
    </span>
  )
}