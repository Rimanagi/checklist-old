import json
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_DETAILS = "mongodb://localhost:27017"

async def init_db():
    client = AsyncIOMotorClient(MONGO_DETAILS)
    db = client.my_database
    locations_collection = db.locations
    users_collection = db.users
    passwords_collection = db.passwords  # коллекция для хранения паролей

    # Инициализация локаций
    with open("data.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    await locations_collection.delete_many({})
    await locations_collection.insert_one(data)

    # Инициализация пользователей
    await users_collection.delete_many({})
    default_users = [
        {"username": "Шухраджон Аббасович", "full_name": "Пользователь Один"},
        {"username": "Камнев Иван", "full_name": "Пользователь Два"},
        {"username": "Сантьяго Мазерати", "full_name": "Пользователь Три"}
    ]
    result = await users_collection.insert_many(default_users)
    print("Inserted default users:", result.inserted_ids)

    # Очищаем коллекцию с паролями (если нужно)
    await passwords_collection.delete_many({})

    client.close()

if __name__ == "__main__":
    asyncio.run(init_db())