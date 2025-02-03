import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import asyncio

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
# ALGORITHM = "SHA-3"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Простое хранилище пользователей (НЕ для продакшена)
fake_users_db = {}

# Глобальные переменные для регистрации внешних серверов
registered_servers = []  # Список словарей с информацией о сервере: { "name": ..., "ip": ... }
update_clients = set()   # WebSocket‑соединения браузеров, получающих обновления

class User(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password

def get_password_hash(password):
    return password

def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Функция для рассылки обновлённого списка серверов всем подключённым клиентам
async def broadcast_server_list():
    for client in list(update_clients):
        try:
            await client.send_json(registered_servers)
        except Exception:
            update_clients.remove(client)

#############################################
# Роуты для регистрации, логина и главной страницы
#############################################

@app.get("/register", response_class=HTMLResponse)
def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    if username in fake_users_db:
        # Если пользователь уже существует – возвращаем сообщение об ошибке
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пользователь с таким именем уже существует"}
        )
    fake_users_db[username] = get_password_hash(password)
    # При успешной регистрации перенаправляем на страницу логина с сообщением
    return RedirectResponse(url="/login?msg=Регистрация успешна! Теперь вы можете войти.", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request, msg: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})

@app.post("/login", response_class=HTMLResponse)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный логин или пароль"}
        )
    access_token = create_access_token({"sub": form_data.username})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/", response_class=HTMLResponse)
def main_page(request: Request):
    try:
        username = get_current_user_from_cookie(request)
    except HTTPException:
        return RedirectResponse(url="/register", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request, "username": username})

@app.get("/servers")
def get_servers(request: Request):
    try:
        username = get_current_user_from_cookie(request)
    except HTTPException:
        return RedirectResponse(url="/register", status_code=302)
    return {"message": f"Список серверов для пользователя {username}"}

#############################################
# WebSocket‑эндпоинты для регистрации серверов и рассылки обновлений
#############################################

# Эндпоинт для регистрации внешних FastAPI серверов
@app.websocket("/ws/servers/register")
async def ws_server_register(websocket: WebSocket):
    await websocket.accept()
    server_info = None
    try:
        # Ожидаем от сервера JSON с данными: {"name": "ServerName"}
        data = await websocket.receive_json()
        server_name = data.get("name", "Unnamed")
        server_ip = websocket.client.host  # IP адрес клиента
        server_info = {"name": server_name, "ip": server_ip}
        registered_servers.append(server_info)
        await broadcast_server_list()
        # Остаёмся в соединении (например, для heartbeat)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if server_info and server_info in registered_servers:
            registered_servers.remove(server_info)
            await broadcast_server_list()

# Эндпоинт для браузерных клиентов, которые получают обновления списка серверов
@app.websocket("/ws/servers/updates")
async def ws_server_updates(websocket: WebSocket):
    await websocket.accept()
    update_clients.add(websocket)
    # Отправляем сразу актуальный список
    await websocket.send_json(registered_servers)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        update_clients.remove(websocket)

# Дополнительный WebSocket‑эндпоинт (например, для других целей)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        pass

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)