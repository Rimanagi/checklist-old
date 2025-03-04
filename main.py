import os
import string
import random
from dotenv import load_dotenv
import uvicorn
import json
import urllib.parse
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request, Form, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder
import jwt
from pydantic import BaseModel

from database import (locations_collection,
                      checklists_collection,
                      users_collection,
                      passwords_collection,
                      logs_collection,
                      checklists_received_collection)
from bson import ObjectId

load_dotenv()  # Загружаем переменные из файла .env
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Простое in‑memory хранилище пользователей (для теста)
fake_users_db = {}

# Глобальные переменные для регистрации внешних серверов
# Каждый сервер сохраняется как {"name": ..., "ip": ..., "ws": ...}
registered_servers = []
update_clients = set()  # WebSocket‑соединения браузеров для рассылки обновлений


async def broadcast_server_list():
    sanitized_servers = [{"name": s["name"], "ip": s["ip"]} for s in registered_servers]
    for client in list(update_clients):
        try:
            await client.send_json(sanitized_servers)
        except Exception:
            update_clients.remove(client)


class User(BaseModel):
    username: str
    password: str


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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
        if username is None or username != ADMIN_USERNAME:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


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
# Эндпоинты для работы с базой (локации, регистрация, логин)
# ----------------------------
@app.get("/locations")
async def get_locations():
    location_doc = await locations_collection.find_one({})
    return jsonable_encoder(location_doc, custom_encoder={ObjectId: str})


@app.get("/register", response_class=HTMLResponse)
def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": "Регистрация отключена"})


@app.post("/register", response_class=HTMLResponse)
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    return templates.TemplateResponse("register.html", {"request": request, "error": "Регистрация отключена"})


@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request, msg: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or form_data.password != ADMIN_PASSWORD:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин или пароль"})
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


# ----------------------------
# WebSocket-эндпоинты
# ----------------------------
@app.websocket("/ws/servers/register")
async def ws_server_register(websocket: WebSocket):
    await websocket.accept()
    server_info = None
    try:
        data = await websocket.receive_json()
        server_name = data.get("name", "Unnamed")
        server_ip = websocket.client.host
        # Сохраняем ws‑соединение вместе с данными о сервере
        server_info = {"name": server_name, "ip": server_ip, "ws": websocket}
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
    await websocket.send_json([{"name": s["name"], "ip": s["ip"]} for s in registered_servers])
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


@app.websocket("/ws/receive")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("✅ Cоединение на подключение")

    try:
        while True:
            message = await websocket.receive_text()
            data = json.loads(message)

            if "filename" in data and "content" in data:
                file_name = data["filename"]
                file_id, file_ext = file_name.split(".")
                content = data["content"]

                # Определяем тип файла
                if file_ext == "json":
                    collection = checklists_received_collection
                    content = json.loads(content)  # Преобразуем JSON-строку в объект
                elif file_id == "txt":
                    collection = logs_collection
                else:
                    print(f"⚠️ Неподдерживаемый формат: {file_id}")
                    continue

                # Вставка в MongoDB (заменяет, если ID уже существует)
                await collection.update_one(
                    {"_id": file_id},
                    {"$set": {"content": content}},
                    upsert=True  # если документа нет, то создается новый
                )

                print(f"📁 Файл {file_id} сохранен в коллекции {collection.name}")

    except Exception as e:
        print(f"⚠️ Ошибка: {e}")
    finally:
        await websocket.close()


# ----------------------------
# Эндпоинты для работы с чеклистами
# ----------------------------

# Единый маршрут для создания/редактирования чеклиста.
# Параметр selected_user передаётся, чтобы не выбирать его повторно при переходах.
@app.get("/create_checklist", response_class=HTMLResponse)
async def create_checklist_page(
        request: Request,
        data: str = None,
        checklist_id: str = None,
        selected_user: str = None
):
    checklist = []
    if data:
        try:
            checklist = json.loads(urllib.parse.unquote(data))
        except Exception:
            checklist = []
    # Получаем список пользователей
    users = []
    cursor = users_collection.find({})
    async for user in cursor:
        user["id"] = str(user["_id"])
        users.append(user)
    return templates.TemplateResponse("create_checklist.html", {
        "request": request,
        "checklist": checklist,
        "data": data or "",
        "checklist_id": checklist_id or "",
        "users": users,
        "selected_user": selected_user or ""
    })


# Страница выбора локации (с добавлением selected_user).
@app.get("/select_location", response_class=HTMLResponse)
async def select_location(request: Request, data: str = None, checklist_id: str = None, selected_user: str = None):
    doc = await locations_collection.find_one({})
    if doc:
        doc.pop("_id", None)
        locations = list(doc.keys())
    else:
        locations = []
    return templates.TemplateResponse("select_location.html", {
        "request": request,
        "locations": locations,
        "data": data or "",
        "checklist_id": checklist_id or "",
        "selected_user": selected_user or ""
    })


# Страница выбора объектов для выбранной локации (selected_user передаётся дальше).
@app.get("/select_objects", response_class=HTMLResponse)
async def select_objects(request: Request, location: str, data: str = None, preselected: str = None, index: str = None,
                         checklist_id: str = None, selected_user: str = None):
    doc = await locations_collection.find_one({})
    if doc:
        doc.pop("_id", None)
        location_data = doc.get(location)
    else:
        location_data = None
    if not location_data:
        return HTMLResponse(f"Локация {location} не найдена", status_code=404)
    objects = location_data.get("object_list", [])
    preselected_list = []
    if preselected:
        try:
            preselected_list = json.loads(preselected)
        except Exception:
            preselected_list = []
    preselected_codes = [item.get("cr_code") for item in preselected_list]
    return templates.TemplateResponse("select_objects.html", {
        "request": request,
        "location": location,
        "objects": objects,
        "data": data or "",
        "preselected": preselected_list,
        "preselected_codes": preselected_codes,
        "index": index,
        "checklist_id": checklist_id,
        "selected_user": selected_user or ""
    })


# Добавление (или обновление) локации в чеклист.
@app.post("/add_location")
async def add_location(
        request: Request,
        location: str = Form(...),
        selected_objects: str = Form(...),
        data: str = Form("[]"),
        index: str = Form(None),
        checklist_id: str = Form(None),
        selected_user: str = Form(None)
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
    if checklist_id is not None and checklist_id.strip() != "":
        redirect_url = f"/create_checklist?data={new_data}&checklist_id={checklist_id}"
    else:
        redirect_url = f"/create_checklist?data={new_data}"
    if selected_user:
        redirect_url += f"&selected_user={selected_user}"
    return RedirectResponse(url=redirect_url, status_code=302)


# Удаление локации из чеклиста по индексу.
@app.get("/delete_location", response_class=HTMLResponse)
def delete_location(request: Request, index: int, data: str, checklist_id: str = None, selected_user: str = None):
    try:
        current_checklist = json.loads(urllib.parse.unquote(data))
    except Exception:
        current_checklist = []
    if 0 <= index < len(current_checklist):
        current_checklist.pop(index)
    new_data = urllib.parse.quote(json.dumps(current_checklist))
    if checklist_id is not None and checklist_id.strip() != "":
        redirect_url = f"/create_checklist?data={new_data}&checklist_id={checklist_id}"
    else:
        redirect_url = f"/create_checklist?data={new_data}"
    if selected_user:
        redirect_url += f"&selected_user={selected_user}"
    return RedirectResponse(url=redirect_url, status_code=302)


# Редактирование локации: переход на выбор объектов с предвыбранными значениями.
@app.get("/edit_location", response_class=HTMLResponse)
def edit_location(request: Request, index: int, data: str, checklist_id: str = None, selected_user: str = None):
    try:
        current_checklist = json.loads(urllib.parse.unquote(data))
    except Exception:
        current_checklist = []
    if 0 <= index < len(current_checklist):
        item = current_checklist[index]
        location = item.get("location")
        preselected = urllib.parse.quote(json.dumps(item.get("objects", [])))
        if checklist_id is not None and checklist_id.strip() != "":
            redirect_url = (f"/select_objects?location={urllib.parse.quote(location)}"
                            f"&data={urllib.parse.quote(data)}&preselected={preselected}"
                            f"&index={index}&checklist_id={checklist_id}")
        else:
            redirect_url = (f"/select_objects?location={urllib.parse.quote(location)}"
                            f"&data={urllib.parse.quote(data)}&preselected={preselected}&index={index}")
        if selected_user:
            redirect_url += f"&selected_user={selected_user}"
        return RedirectResponse(url=redirect_url, status_code=302)
    return RedirectResponse(url=f"/create_checklist?data={urllib.parse.quote(data)}", status_code=302)


# Сохранение чеклиста: обновление, если передан checklist_id, или создание нового.
@app.post("/save_checklist")
async def save_checklist(
        request: Request,
        data: str = Form("[]"),
        checklist_id: str = Form(None),
        selected_user: str = Form(...),
):
    if not selected_user:
        return HTMLResponse("Ошибка: необходимо выбрать пользователя", status_code=400)
    try:
        checklist = json.loads(data)
    except Exception:
        checklist = []
    if not checklist:
        return RedirectResponse(url="/create_checklist", status_code=302)

    if checklist_id is not None and checklist_id.strip() != "":
        await checklists_collection.update_one(
            {"_id": ObjectId(checklist_id)},
            {"$set": {"checklist": checklist, "created_at": datetime.now()}}
        )
        await passwords_collection.update_one(
            {"checklist_id": checklist_id},
            {"$set": {"user": selected_user}}
        )
    else:
        document = {
            "checklist": checklist,
            "created_at": datetime.now()
        }
        result = await checklists_collection.insert_one(document)
        new_checklist_id = str(result.inserted_id)
        generated_password = ''.join(random.choices(string.digits, k=8))
        password_doc = {
            "checklist_id": new_checklist_id,
            "user": selected_user,
            "password": generated_password,
            "created_at": datetime.now()
        }
        await passwords_collection.insert_one(password_doc)
    return RedirectResponse(url="/checklists", status_code=302)


# Просмотр сохранённых чеклистов.
@app.get("/checklists", response_class=HTMLResponse)
async def get_checklists(request: Request):
    checklists = []
    async for document in checklists_collection.find({}):
        checklist_id = str(document["_id"])
        document["id"] = checklist_id
        document.pop("_id", None)
        if "created_at" in document and isinstance(document["created_at"], datetime):
            document["created_at"] = document["created_at"].strftime("%d-%m-%y %H:%M")
        password_doc = await passwords_collection.find_one({"checklist_id": checklist_id})
        if password_doc:
            document["user"] = password_doc.get("user", "")
            document["password"] = password_doc.get("password", "")
        else:
            document["user"] = ""
            document["password"] = ""
        checklists.append(document)
    return templates.TemplateResponse("checklists.html", {"request": request, "checklists": checklists})


# Удаление чеклиста.
@app.post("/delete_checklist")
async def delete_checklist(request: Request, checklist_id: str = Form(...)):
    await checklists_collection.delete_one({"_id": ObjectId(checklist_id)})
    return RedirectResponse(url="/checklists", status_code=302)


# Редактирование чеклиста: перенаправляем на create_checklist с данными.
@app.get("/edit_checklist", response_class=HTMLResponse)
async def edit_checklist(request: Request, checklist_id: str, selected_user: str = None):
    document = await checklists_collection.find_one({"_id": ObjectId(checklist_id)})
    if not document:
        return HTMLResponse("Чеклист не найден", status_code=404)
    data = urllib.parse.quote(json.dumps(document.get("checklist", [])))
    password_doc = await passwords_collection.find_one({"checklist_id": checklist_id})
    if password_doc:
        selected_user = password_doc.get("user")
    else:
        selected_user = ""
    return RedirectResponse(
        url=f"/create_checklist?data={data}&checklist_id={checklist_id}&selected_user={selected_user}",
        status_code=302
    )


# Новый эндпоинт для отправки чеклиста на внешний сервер по WebSocket.
@app.post("/send_checklist")
async def send_checklist(
        checklist: dict = Body(...),
        server_ip: str = Body(...),
        current_user: str = Depends(get_current_user_from_cookie)
):
    target_server = None
    for s in registered_servers:
        if s["ip"] == server_ip:
            target_server = s
            break
    if not target_server:
        raise HTTPException(status_code=404, detail="Server not found or not connected")
    try:
        await target_server["ws"].send_text(json.dumps(checklist))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send checklist: {str(e)}")
    return {"detail": "Checklist sent successfully"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
