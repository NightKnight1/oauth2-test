import json
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated

import jwt
import redis
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

import constants

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/token')


@asynccontextmanager
async def lifespan(app: FastAPI):
    # drop_db()
    init_db()
    yield


app = FastAPI(lifespan=lifespan)

redis_client = redis.Redis(
    host=constants.REDIS_HOST,
    port=constants.REDIS_PORT,
    decode_responses=True
)


#################### DATA VALIDATION ####################

class UserRegister(BaseModel):
    login: str
    password: str
    roles: str = 'default'


class Token(BaseModel):
    access_token: str
    token_type: str


class AddContent(BaseModel):
    text: str
    roles: str = 'default'


#################### DATABASE ####################

def drop_db():
    tables = ['users', 'contents']
    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()
    for table in tables:
        cursor.execute(f"""
        DROP TABLE IF EXISTS {table} 
        """)

    conn.commit()
    conn.close()


def init_db():
    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        roles TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT,
        roles TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def get_table_info(table_name: str, columns: list):
    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    columns_to_get = ', '.join(columns)
    cursor.execute(f"""
        SELECT {columns_to_get} FROM {table_name} 
    """)
    tmp_res = cursor.fetchall()

    table_info = list()
    for row in tmp_res:
        el = dict()
        for i, val in enumerate(row):
            el[columns[i]] = val

        if 'roles' in columns:
            el['roles'] = ', '.join(json.loads(el['roles']))

        table_info.append(el)

    conn.close()

    return table_info


@app.get('/users/all', tags=["DB info 🗄️"])
def get_all_users():
    columns = ['id', 'login', 'password', 'roles']
    table_name = constants.USERS_TABLE_NAME

    table_info = get_table_info(table_name, columns)

    return table_info


@app.get('/contents/all', tags=["DB info 🗄️"])
def get_all_contents():
    columns = ['id', 'text', 'roles']
    table_name = constants.CONTENTS_TABLE_NAME

    table_info = get_table_info(table_name, columns)

    return table_info


#################### REDIS ####################

def get_redis_elements_by_key(key):
    res = list()
    for el in redis_client.scan_iter(key):
        res.append(el)

    return {"result": res}


@app.get('/redis/whitelist', tags=["DB info 🗄️"])
def get_redis_whitelist():
    key = 'whitelist:*'
    res = get_redis_elements_by_key(key)

    return {"result": res}


@app.get('/redis/blacklist', tags=["DB info 🗄️"])
def get_redis_blacklist():
    key = 'blacklist:*'
    res = get_redis_elements_by_key(key)

    return {"result": res}


#################### TEST ####################


@app.post("/contents/add", status_code=status.HTTP_201_CREATED, tags=["Test ✏️"])
def add_content(content: Annotated[AddContent, Depends()]):
    try:
        content.roles = list(set(content.roles.strip().split()))
    except:
        raise HTTPException(400, "Bad roles input. Separate roles by space.")

    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    roles = json.dumps(content.roles)

    cursor.execute("""
        INSERT INTO contents 
        (text, roles)
        VALUES (?, ?)
    """, (content.text, roles))

    conn.commit()
    conn.close()

    return {"message": f"Content added"}


@app.post("/users/register", status_code=status.HTTP_201_CREATED, tags=["Test ✏️"])
def register_user(user: Annotated[UserRegister, Depends()]):
    try:
        user.roles = sorted(list(set(user.roles.strip().split())))
    except:
        raise HTTPException(400, "Bad roles input. Separate roles by space.")

    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)
    """, (user.login,)
                   )
    tmp = cursor.fetchone()

    if tmp[0] == 1:
        raise HTTPException(409, "User already exists")

    hashed_password = bcrypt_context.hash(user.password)
    roles = json.dumps(user.roles)
    # roles = json.dumps(user.roles)
    cursor.execute("""
        INSERT INTO users 
        (login, password, roles)
        VALUES (?, ?, ?)
    """, (user.login, hashed_password, roles))

    conn.commit()
    conn.close()
    return {"message": f"User {user.login} added"}


#################### TOKEN ####################

def create_access_token(user_info: dict, expires_delta: timedelta):
    payload = {"id": user_info['id'],
               "sub": user_info['login'],
               "roles": user_info['roles'],
               "exp": datetime.now() + expires_delta,
               }
    return jwt.encode(payload, constants.JWT_SECRET_KEY, algorithm=constants.JWT_ALGORITHM)


def validate_token(token):
    if (token is None) or (not redis_client.exists(f"whitelist:{token}")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")

    try:
        payload = jwt.decode(token, constants.JWT_SECRET_KEY, algorithms=[constants.JWT_ALGORITHM])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="BAD JWT TOKEN.")


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_info = authenticate_user(form_data.username, form_data.password)
    if user_info is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate user.")
    token = create_access_token(user_info, timedelta(seconds=constants.JWT_TOKEN_TTL_SECONDS))

    # payload = jwt.decode(token, constants.JWT_SECRET_KEY, algorithms=[constants.JWT_ALGORITHM])
    redis_client.setex(
        f"whitelist:{token}",
        timedelta(seconds=constants.JWT_TOKEN_TTL_SECONDS),
        "valid"
    )

    return {"access_token": token, "token_type": "bearer"}


def authenticate_user(login: str, password: str):
    data_to_get = ['id', 'password', 'roles']
    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    cursor.execute(f"""
        SELECT {', '.join(data_to_get)}
        FROM users
        WHERE login = ?
    """, (login,))
    tmp_res = cursor.fetchone()
    if not tmp_res:
        return None

    user_info = dict()
    for i, el in enumerate(data_to_get):
        user_info[el] = tmp_res[i]

    if not bcrypt_context.verify(password, user_info['password']):
        return None

    user_info['roles'] = json.loads(user_info['roles'])
    user_info['login'] = login

    print(user_info)
    return user_info


#################### MAIN ####################

@app.get("/contents/{content_id}", tags=["Main ⚙️"])
def get_content_by_id(content_id: int, token: Annotated[str, Depends(oauth2_bearer)]):
    validate_token(token)
    columns = ['id', 'text', 'roles']

    conn = sqlite3.connect(constants.DB_NAME)
    cursor = conn.cursor()

    columns_to_get = ', '.join(columns)
    cursor.execute(f"""
        SELECT {columns_to_get}
        FROM contents
        WHERE id = ?
    """, (content_id,))
    tmp_res = cursor.fetchone()
    if not tmp_res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Content not found")

    content_info = dict()

    for i, el in enumerate(columns):
        content_info[el] = tmp_res[i]

    if 'roles' in columns:
        content_info['roles'] = json.loads(content_info['roles'])

    payload = jwt.decode(token, constants.JWT_SECRET_KEY, algorithms=[constants.JWT_ALGORITHM])
    user_roles = payload['roles']
    if set(user_roles) & set(content_info['roles']):
        return content_info
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )


@app.post("/users/logout", tags=["Main ⚙️"])
def logout(token: Annotated[str, Depends(oauth2_bearer)]):
    if (token is None) or (not redis_client.exists(f"whitelist:{token}")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")

    try:
        payload = jwt.decode(token, constants.JWT_SECRET_KEY, algorithms=[constants.JWT_ALGORITHM])
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="BAD JWT TOKEN.")

    redis_client.delete(f"whitelist:{token}")
    redis_client.setex(f"blacklist:{token}",
                       constants.JWT_TOKEN_BLACKLIST_TTL_SECONDS,
                       "revoked")
    return {"detail": "Successfully logged out"}


if __name__ == "__main__":
    uvicorn.run(app='main:app', host=constants.APP_HOST, port=constants.APP_PORT, reload=True)
