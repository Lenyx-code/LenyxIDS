import { useState, useEffect, useRef } from "react"

export function useSSE(url, maxItems = 100) {
  const [data, setData]       = useState([])
  const [connected, setConnected] = useState(false)
  const eventSourceRef            = useRef(null)

  useEffect(() => {
    if (!url) return

    const connect = () => {
      const es = new EventSource(url)
      eventSourceRef.current = es

      es.onopen = () => {
        setConnected(true)
        console.log(`[SSE] Connecté : ${url}`)
      }

      es.onmessage = (event) => {
        try {
          const item = JSON.parse(event.data)
          setData(prev => [item, ...prev].slice(0, maxItems))
        } catch (e) {
          console.error("[SSE] Parse error:", e)
        }
      }

      es.onerror = () => {
        setConnected(false)
        es.close()
        setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      eventSourceRef.current?.close()
      setConnected(false)
    }
  }, [url])

  return { data, connected }
}