# database.py
from motor.motor_asyncio import AsyncIOMotorClient

# URL для подключения к MongoDB (можно менять, если у вас иные настройки)
MONGO_DETAILS = "mongodb://localhost:27017"

# Инициализируем асинхронного клиента
client = AsyncIOMotorClient(MONGO_DETAILS)

# Выбираем базу данных (назовём её, например, "my_database")
database = client.my_database

# Получаем коллекцию (например, "locations")
locations_collection = database.get_collection("locations")

# Коллекция для сохранённых чеклистов
checklists_collection = database.get_collection("checklists")