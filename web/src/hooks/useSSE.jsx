import { useEffect, useRef, useState, useCallback } from "react"

let _toastCounter = 0
export const createToastId = () => `toast_${Date.now()}_${++_toastCounter}`

export function useSSE(url, { maxItems = 200, onMessage } = {}) {
  const [data,      setData]      = useState([])
  const [connected, setConnected] = useState(false)
  const esRef      = useRef(null)
  const retryRef   = useRef(null)
  const onMsgRef   = useRef(onMessage)

  useEffect(() => { onMsgRef.current = onMessage }, [onMessage])

  useEffect(() => {
    if (!url) return

    const connect = () => {
      const es = new EventSource(url)
      esRef.current = es

      es.onopen = () => setConnected(true)

      es.onmessage = (e) => {
        try {
          const item = JSON.parse(e.data)
          if (item?.connected === true) return

          // Callback optionnel (ex: toasts)
          onMsgRef.current?.(item)

          setData(prev => [item, ...prev].slice(0, maxItems))
        } catch {}
      }

      es.onerror = () => {
        setConnected(false)
        es.close()
        retryRef.current = setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      esRef.current?.close()
      clearTimeout(retryRef.current)
    }
  }, [url])

  const clear = useCallback(() => setData([]), [])

  return { data, connected, clear }
}