import uvicorn
import json
import urllib.parse
import asyncio
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder
import jwt
from pydantic import BaseModel

# Импортируем коллекции из database.py
from database import locations_collection, checklists_collection
from bson import ObjectId  # Для преобразования ObjectId в строку

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Простое in‑memory хранилище пользователей (НЕ для продакшена)
fake_users_db = {}

# Глобальные переменные для регистрации внешних серверов
registered_servers = []  # Список серверов в формате { "name": ..., "ip": ... }
update_clients = set()   # WebSocket‑соединения браузеров для рассылки обновлений

# Функция для рассылки обновлённого списка серверов всем WebSocket‑клиентам
async def broadcast_server_list():
    for client in list(update_clients):
        try:
            await client.send_json(registered_servers)
        except Exception:
            update_clients.remove(client)

# ----------------------------
# Модель пользователя и вспомогательные функции
# ----------------------------
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

# ----------------------------
# Middleware для проверки аутентификации для всех HTTP-запросов
# (разрешены /login, /register, /static, /favicon.ico)
# ----------------------------
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    allowed_paths = ["/login", "/register", "/static", "/favicon.ico"]
    if any(request.url.path.startswith(path) for path in allowed_paths):
        return await call_next(request)
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return RedirectResponse(url="/login")
    return await call_next(request)

# ----------------------------
# Эндпоинт для получения локаций из MongoDB
# ----------------------------
@app.get("/locations")
async def get_locations():
    location_doc = await locations_collection.find_one({})
    return jsonable_encoder(location_doc, custom_encoder={ObjectId: str})

# ----------------------------
# Эндпоинты для регистрации и логина
# ----------------------------
@app.get("/register", response_class=HTMLResponse)
def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    if username in fake_users_db:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Пользователь с таким именем уже существует"})
    fake_users_db[username] = get_password_hash(password)
    return RedirectResponse(url="/login?msg=Регистрация успешна! Теперь вы можете войти.", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request, msg: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})

@app.post("/login", response_class=HTMLResponse)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль"})
    access_token = create_access_token({"sub": form_data.username})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

# Главная страница (с отображением подключенных серверов в виде сетки)
@app.get("/", response_class=HTMLResponse)
def main_page(request: Request):
    try:
        username = get_current_user_from_cookie(request)
    except HTTPException:
        return RedirectResponse(url="/register", status_code=302)
    # index.html теперь должен отображать подключенные серверы (например, через WebSocket)
    return templates.TemplateResponse("index.html", {"request": request, "username": username})

@app.get("/servers")
def get_servers(request: Request):
    try:
        username = get_current_user_from_cookie(request)
    except HTTPException:
        return RedirectResponse(url="/register", status_code=302)
    return {"message": f"Список серверов для пользователя {username}"}

# ----------------------------
# WebSocket‑эндпоинты для регистрации внешних серверов
# ----------------------------
@app.websocket("/ws/servers/register")
async def ws_server_register(websocket: WebSocket):
    await websocket.accept()
    server_info = None
    try:
        data = await websocket.receive_json()
        server_name = data.get("name", "Unnamed")
        server_ip = websocket.client.host
        server_info = {"name": server_name, "ip": server_ip}
        registered_servers.append(server_info)
        await broadcast_server_list()
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if server_info and server_info in registered_servers:
            registered_servers.remove(server_info)
            await broadcast_server_list()

@app.websocket("/ws/servers/updates")
async def ws_server_updates(websocket: WebSocket):
    await websocket.accept()
    update_clients.add(websocket)
    await websocket.send_json(registered_servers)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        update_clients.remove(websocket)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        pass

# ----------------------------
# Эндпоинты для работы с чеклистами
# ----------------------------

# Страница создания чеклиста. Состояние чеклиста передаётся через URL-параметр data.
@app.get("/create_checklist", response_class=HTMLResponse)
def create_checklist_page(request: Request, data: str = None):
    checklist = []
    if data:
        try:
            checklist = json.loads(urllib.parse.unquote(data))
        except Exception:
            checklist = []
    return templates.TemplateResponse("create_checklist.html", {"request": request, "checklist": checklist, "data": data or ""})

# Страница выбора локации в виде сетки.
@app.get("/select_location", response_class=HTMLResponse)
async def select_location(request: Request, data: str = None):
    doc = await locations_collection.find_one({})
    if doc:
        doc.pop("_id", None)
        locations = list(doc.keys())
    else:
        locations = []
    return templates.TemplateResponse("select_location.html", {"request": request, "locations": locations, "data": data or ""})

# Страница выбора объектов для выбранной локации.
# Параметр preselected (опционально) содержит JSON с предвыбранными объектами.
@app.get("/select_objects", response_class=HTMLResponse)
async def select_objects(request: Request, location: str, data: str = None, preselected: str = None):
    doc = await locations_collection.find_one({})
    if doc:
        doc.pop("_id", None)
        location_data = doc.get(location)
    else:
        location_data = None
    if not location_data:
        return HTMLResponse(f"Локация {location} не найдена", status_code=404)
    objects = location_data.get("object_list", [])
    return templates.TemplateResponse("select_objects.html", {
        "request": request,
        "location": location,
        "objects": objects,
        "data": data or "",
        "preselected": preselected or ""
    })

# Обработка добавления (или обновления) выбранной локации с объектами в чеклист.
# Если параметр index передан, обновляем существующий элемент.
@app.post("/add_location")
async def add_location(
    request: Request,
    location: str = Form(...),
    selected_objects: str = Form(...),
    data: str = Form("[]"),
    index: str = Form(None)
):
    try:
        current_checklist = json.loads(data)
    except Exception:
        current_checklist = []
    try:
        selected_objs = json.loads(selected_objects)
    except Exception:
        selected_objs = []
    new_item = {"location": location, "objects": selected_objs}
    if index is not None:
        try:
            idx = int(index)
            if 0 <= idx < len(current_checklist):
                current_checklist[idx] = new_item
            else:
                current_checklist.append(new_item)
        except ValueError:
            current_checklist.append(new_item)
    else:
        current_checklist.append(new_item)
    new_data = urllib.parse.quote(json.dumps(current_checklist))
    return RedirectResponse(url=f"/create_checklist?data={new_data}", status_code=302)

# Удаление локации из чеклиста по индексу.
@app.get("/delete_location", response_class=HTMLResponse)
def delete_location(request: Request, index: int, data: str):
    try:
        current_checklist = json.loads(urllib.parse.unquote(data))
    except Exception:
        current_checklist = []
    if 0 <= index < len(current_checklist):
        current_checklist.pop(index)
    new_data = urllib.parse.quote(json.dumps(current_checklist))
    return RedirectResponse(url=f"/create_checklist?data={new_data}", status_code=302)

# Редактирование локации: перенаправляем пользователя в выбор объектов с предвыбранными значениями.
@app.get("/edit_location", response_class=HTMLResponse)
def edit_location(request: Request, index: int, data: str):
    try:
        current_checklist = json.loads(urllib.parse.unquote(data))
    except Exception:
        current_checklist = []
    if 0 <= index < len(current_checklist):
        item = current_checklist[index]
        location = item.get("location")
        preselected = urllib.parse.quote(json.dumps(item.get("objects", [])))
        # Передаём index, чтобы /add_location знал, что обновляем элемент.
        redirect_url = f"/select_objects?location={urllib.parse.quote(location)}&data={urllib.parse.quote(data)}&preselected={preselected}&index={index}"
        return RedirectResponse(url=redirect_url, status_code=302)
    return RedirectResponse(url=f"/create_checklist?data={urllib.parse.quote(data)}", status_code=302)

# Сохранение чеклиста в базу данных (коллекция checklists)
@app.post("/save_checklist")
async def save_checklist(request: Request, data: str = Form("[]")):
    try:
        checklist = json.loads(data)
    except Exception:
        checklist = []
    if not checklist:
        return RedirectResponse(url="/create_checklist", status_code=302)
    document = {
        "checklist": checklist,
        "created_at": datetime.utcnow()
    }
    await checklists_collection.insert_one(document)
    return RedirectResponse(url="/checklists", status_code=302)

# Страница просмотра сохранённых чеклистов.
@app.get("/checklists", response_class=HTMLResponse)
async def get_checklists(request: Request):
    checklists = []
    cursor = checklists_collection.find({})
    async for document in cursor:
        document.pop("_id", None)
        if "created_at" in document and isinstance(document["created_at"], datetime):
            document["created_at"] = document["created_at"].strftime("%d-%m-%y %H:%M")
        checklists.append(document)
    return templates.TemplateResponse("checklists.html", {"request": request, "checklists": checklists})

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)