export function LiveIndicator({ connected }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`w-2 h-2 rounded-full ${connected ? "bg-cyber-green animate-pulse-live" : "bg-gray-500"}`} />
      <span className={`text-xs font-mono ${connected ? "text-cyber-green" : "text-gray-500"}`}>
        {connected ? "LIVE" : "OFFLINE"}
      </span>
    </div>
  )
}