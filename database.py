import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()
# URL для подключения к MongoDB (можно менять, если у вас иные настройки)
MONGO_DETAILS = os.getenv("MONGO_URL", "mongodb://localhost:27017")

# Инициализируем асинхронного клиента
client = AsyncIOMotorClient(MONGO_DETAILS)

# Выбираем базу данных (назовём её, например, "my_database")
database = client.my_database

# Получаем коллекцию (например, "locations")
locations_collection = database.get_collection("locations")

# Коллекция для сохранённых чеклистов
checklists_collection = database.get_collection("checklists")

# работяги
users_collection = database.get_collection("users")

# одноразовые пароли
passwords_collection = database.get_collection("passwords")
logs_collection = database.get_collection("logs")
checklists_received_collection = database.get_collection("checklists_received")
