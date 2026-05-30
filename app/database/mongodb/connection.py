from pymongo import MongoClient

class Connection:
    
    @staticmethod
    def get_mongodb_connection(collection_name: str): 
        # Configuration de la connexion
        client = MongoClient("mongodb://database-mongo:27017/")
        db = client["cyber_forensic_db"]
        # Retourne la collection demandée
        return db[collection_name]
