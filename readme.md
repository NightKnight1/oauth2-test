# FastAPI Authentication and Authorization System

## Endpoints

### **User Management**

#### **Register a New User**

`POST /users/register`

- **Description**: Registers a new user with login, password, and roles.
- **Request Body:**
  ```json
  {
    "login": "Username_1",
    "password": "password",
    "roles": "role1 role2"
  }
  ```
- **Response:**
  ```json
  {
    "message": "User Username_1 added"
  }
  ```

#### **Login and Get Token**

`POST /token`

- **Description**: Authenticates user and provides a JWT token.
- **Request Body:** (form-data)
  ```
  username=Username_1
  password=password
  ```
- **Response:**
  ```json
  {
    "access_token": "eyJhb...",
    "token_type": "bearer"
  }
  ```

#### **Logout**

`POST /users/logout`

- **Description**: Revokes the user's token.
- **Headers:**
  ```
  Authorization: Bearer <token>
  ```
- **Response:**
  ```json
  {
    "detail": "Successfully logged out"
  }
  ```

### **Content Management**

#### **Add Content**

`POST /contents/add`

- **Description**: Adds content with specific roles.
- **Request Body:**
  ```json
  {
    "text": "Restricted content",
    "roles": "admin"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Content added"
  }
  ```

#### **Get Content by ID**

`GET /contents/{content_id}`

- **Description**: Retrieves content by ID if the user has the required role.
- **Headers:**
  ```
  Authorization: Bearer <token>
  ```
- **Response (if authorized):**
  ```json
  {
    "id": 1,
    "text": "Restricted content",
    "roles": ["admin"]
  }
  ```
- **Response (if unauthorized):**
  ```json
  {
    "detail": "Insufficient permissions"
  }
  ```

### **Database Information**

#### **Get All Users**

`GET /users/all`

- **Description**: Retrieves a list of all registered users.
- **Response:**
  ```json
  [
    { "id": 1, "login": "User_1", "password": "hashed_password", "roles": "admin" },
    { "id": 2, "login": "User_2", "password": "hashed_password", "roles": "user" },
    { "id": 3, "login": "User_3", "password": "hashed_password", "roles": "moderator" },
    { "id": 4, "login": "User_4", "password": "hashed_password", "roles": "admin" },
    { "id": 5, "login": "User_5", "password": "hashed_password", "roles": "guest" }
  ]
  ```

#### **Get All Contents**

`GET /contents/all`

- **Description**: Retrieves a list of all stored contents.
- **Response:**
  ```json
  [
    { "id": 1, "text": "Admin-only content", "roles": "admin" },
    { "id": 2, "text": "User-accessible content", "roles": "user" },
    { "id": 3, "text": "Moderator notes", "roles": "moderator" },
    { "id": 4, "text": "Public announcement", "roles": "admin user" },
    { "id": 5, "text": "Guest welcome message", "roles": "guest" }
  ]
  ```

### **Redis (Token Management)**

#### **Get Whitelisted Tokens**

`GET /redis/whitelist`

- **Description**: Lists all active tokens.
- **Response:**
  ```json
  {
    "result": [
      "whitelist:eyJhb123...",
      "whitelist:eyJhb456...",
      "whitelist:eyJhb789...",
      "whitelist:eyJhbabc...",
      "whitelist:eyJhbxyz..."
    ]
  }
  ```

#### **Get Blacklisted Tokens**

`GET /redis/blacklist`

- **Description**: Lists all revoked tokens.
- **Response:**
  ```json
  {
    "result": [
      "blacklist:eyJhbdef...",
      "blacklist:eyJhbghi...",
      "blacklist:eyJhbjkl...",
      "blacklist:eyJhbmn0...",
      "blacklist:eyJhbopq..."
    ]
  }
  ```

## Running the Project

### **Using Docker Compose**

1. Ensure you have **Docker** and **Docker Compose** installed.
2. Build and run the containers:
   ```sh
   docker compose up --build
   ```
3. The API will be available at: `http://localhost:8000`

### **Without Docker**

1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

2. Run Redis server.

3. Change 'REDIS_HOST' environment variable (`constants.py`).

   ```python
    REDIS_HOST = 'YOUR_HOST'
   ```
   or if run local Redis server:
   ```python
    REDIS_HOST = 'localhost'
   ```


3. Run the application:
   ```sh
   python main.py
   ```

---
This API provides a complete authentication and authorization system using FastAPI, SQLite, and Redis for managing JWT
tokens efficiently.

