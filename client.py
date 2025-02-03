import asyncio
import json
import websockets
from fastapi import FastAPI

app = FastAPI()

async def register_with_main():
    uri = "ws://localhost:8000/ws/servers/register"
    while True:
        try:
            async with websockets.connect(uri) as websocket:
                # Отправляем данные для регистрации: имя сервера
                registration_info = {"name": "Server 2"}
                await websocket.send(json.dumps(registration_info))
                # Поддерживаем соединение: отправляем heartbeat каждые 30 секунд
                while True:
                    await asyncio.sleep(30)
                    try:
                        await websocket.send("ping")
                    except Exception:
                        break
        except Exception as e:
            print("Ошибка подключения к главному серверу:", e)
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(register_with_main())

@app.get("/")
async def read_root():
    return {"message": "Это вторичное FastAPI приложение, подключенное к главному серверу."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)