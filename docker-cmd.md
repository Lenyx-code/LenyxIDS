# MEMO COMMANDE DOCKER

## Créer et lancer un container

```bash
    docker run <Nom de l'image>
```

## Démarrer un container

```bash
    docker start <id du container>
```

## Arrêter un container

```bash
    docker stop <id container>
```

## intéragir avec un container qu'on a démarrer

```bash
    docker exec -it <id du container> bash
    "exec" nous permet d'excécuter une commande dans un container sans entrer dans celui ci
```

## Lister les container

```bash
    docker ps
```

```bash
    docker container ls
```

## Lister tous les container

```bash
    docker ps -a
```

```bash
    docker container ps -a
```

## Lister les images

```bash
    docker images
```

```bash
    docker image ls
```

## Supprimer un container

```bash
    docker rm <id du container>
```

```bash
    docker container rm <id du container>
```

## Supprimer une image

```bash
    docker rmi <id de l'image>
```

```bash
    docker image rm <id de l'image>
```

# Installer docker sur ubuntu

```bash
    sudo apt-get install docker-ce docker-ce-cli container.io
```

## Volumes

### Mappé

```bash
    docker run -it --rm <dossier-local:dossier-container> <nom image>
```

### Manager

# Créer un volume

```bash
    docker volume create <nom-volume>
```
# Lister les volumes

```bash
    docker volume ls
```
# Supprimer un volume

```bash
    docker volume rm <nom-volume>
```
# Relier un volume

```bash
    docker run -it --rm <nom-volume:dossier-container> <nom image>
```
# Information du volume

```bash
    docker volume inspect <nom-volume>
```

## DOCKER HUB

# Récupérer une imgage

```bash
    docker pull <image>
```

## Mappge de ports

```bash
    docker run -it -p <port-local>:<port-container> <nom-image>
```

# Lister les réseaux disponibles

```bash
    docker network ls
```
# Isoler un conteneur

```bash
    docker run --rm -it --network=none <image>
```
# Créer un réseau bridge

```bash
    docker network create --driver=bridge <nom du réseau>
```
# Créer un conteneur et le connecter en même temps

```bash
   docker run -it --rm --network=<nom du réseau> --name=<nom du conteneur> <image>
```
# Créer et ensuite connecter

```bash
   docker run --rm -it --name=<nom du conteneur> <image>
   docker network connect <nom du réseau> <nom du conteneur>
```
# Liste des conteneurs dans un réseau Docker

```bash
   docker network inspect <nom du réseau>
```
# Déconnecter les conteneurs du réseau

```bash
   docker disconnect <nom du réseau> <conteneur>
```
# Supprimer des réseaux

```bash
   docker network rm <nom du réseau> <nom du réseau> ...
```

const MonitorAlertContext = createContext(null)  

  const [monitorAlerts,    setMonitorAlerts]    = useState([])
  const [monitorAlertConn, setMonitorAlertConn] = useState(false)

   useEffect(() => {
    let retry = null
    const connect = () => {
      const es = new EventSource(SSE_URLS.monitorAlerts)
      es.onopen    = () => setMonitorAlertConn(true)
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d?.connected) return
          setMonitorAlerts(prev => {
            // Dédoublonnage par _id
            if (d._id && prev.some(t => t._id === d._id)) return prev
            return [...prev.slice(-3), { ...d, id: createToastId() }]
          })
        } catch {}
      }
      es.onerror = () => {
        setMonitorAlertConn(false)
        es.close()
        retry = setTimeout(connect, 3000)
      }
    }
    connect()
    return () => clearTimeout(retry)
  }, [])

  const closeMonitorAlertToast = useCallback(
    (id) => setMonitorAlerts(p => p.filter(t => t.id !== id)), []
  )

const monitorAlertValue = useMemo(() => ({
    monitorAlerts, monitorAlertConn, closeMonitorAlertToast
  }), [monitorAlerts, monitorAlertConn, closeMonitorAlertToast])

  return (
    <AlertContext.Provider value={alertValue}>
      <PacketContext.Provider value={packetValue}>
        <MonitorAlertContext.Provider value={monitorAlertValue}>
          {children}
        </MonitorAlertContext.Provider>
      </PacketContext.Provider>
    </AlertContext.Provider>
  )