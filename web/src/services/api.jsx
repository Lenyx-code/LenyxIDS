import axios from "axios";

const BASE_URL =  "http://localhost:8000"

const api = axios.create({baseURL: BASE_URL});

export const API  = {
    getPackets : (lastId = null) => {
        api.get("api/packets",{ params : {last_id: lastId, limit: 50 }})
    }
}

export const SSE_URLS = {
  packets: `${BASE_URL}/api/stream/packets`,
  //alerts:  `${BASE_URL}/api/alerts/stream`,
}