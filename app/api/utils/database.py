from motor.motor_asyncio import AsyncIOMotorClient
from bson import json_util
from fastapi import Request

# Centralisation de la connexion Mongo
client = AsyncIOMotorClient("mongodb://database-mongo:27017/")
db = client.cyber_forensic_db

async def event_generator(request: Request, collection_name: str):
    collection = db[collection_name]

    cursor = collection.find().sort("_id", -1).limit(100)
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        yield f"data: {json_util.dumps(doc)}\n\n"
        
    async with collection.watch() as stream:
        async for change in stream:
            if await request.is_disconnected():
                break
            
            if change["operationType"] == "insert":
                doc = change["fullDocument"]
                doc["_id"] = str(doc["_id"])
                yield f"data: {json_util.dumps(doc)}\n\n"