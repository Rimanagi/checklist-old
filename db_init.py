# db_init.py
import json
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_DETAILS = "mongodb://localhost:27017"

async def init_db():
    client = AsyncIOMotorClient(MONGO_DETAILS)
    db = client.my_database
    locations_collection = db.locations

    # Читаем файл data.json
    with open("data.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    # Если в коллекции уже есть данные, можно либо обновить, либо удалить и вставить заново.
    # Здесь мы просто удаляем все и вставляем новые данные.
    await locations_collection.delete_many({})
    # В данном примере мы вставляем один документ, содержащий весь объект.
    result = await locations_collection.insert_one(data)
    print("Inserted document id:", result.inserted_id)
    client.close()

if __name__ == "__main__":
    asyncio.run(init_db())