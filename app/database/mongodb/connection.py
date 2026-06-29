from pymongo import MongoClient

class Connection:
   
    @staticmethod
    def get_mongodb_connection(collection_name: str): 
        MONGO_URI_TEST = "mongodb://database-mongo:27017/"
        # Configuration de la connexion
        client = MongoClient(MONGO_URI_TEST)
        db = client["cyber_forensic_db"]
        # Retourne la collection demandée
        return db[collection_name]
