# Flask REST API with PostgreSQL and SQLAlchemy
 All the APIs are created following OpenAPI Standards.

## Features
- User registration
- User login with JWT authentication
- Change password
- Edit user details
- Password reset request and reset

## Prerequisites

- Python
- PostgreSQL
- pip (Python package installer)

## Setup Instructions

1. **Clone the repository:**
    ```bash
    git clone https://github.com/mashrufehsan/W3-Flask-Assignment.git
    cd W3-Flask-Assignment
    ```

2. **Create a virtual environment and activate it:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Configure environment variables:**

    Copy the .env.sample file to .env and fill in the required configuration:
    ```bash
    cp .env.sample .env
    ```
    Edit .env to include your database URI and secret key.

5. **Set up the database:**
Make sure PostgreSQL is running and the database specified in `SQLALCHEMY_DATABASE_URI` in the `.env` file exists.

6. **Run the application:**
    ```bash
    python app.py
    ```

7. **Access Swagger-UI:**
    Open your web browser and go to `http://localhost:5000/swagger-ui`.

## ! Important
Upon first run a table named ```users``` will be created along with a user by default with *****admin***** privilege.

        "username": "admin",
        "password": "admin"
This user is needed to perform further operations like promoting other users to admin.

Also, another table named `reset_tokens` will be created to store password reset tokens.

## API Endpoints

### Register a User

- **Endpoint:** `/register`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "email": "johndoe@example.com",
        "password": "password123"
    }
    ```
- **Responses:**
    - `201`: User registered successfully.
    - `400`: Username or Email already exists.

### Login a User

- **Endpoint:** `/login`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "username": "johndoe",
        "password": "password123"
    }
    ```
- **Responses:**
    - `200`: Login successful. Returns a JWT token.
    - `401`: Invalid username or password.

### Change Password

- **Endpoint:** `/change-password`
- **Method:** `POST`
- **Headers:**
    - `Authorization: Bearer <token>`
- **Request Body:**
    ```json
    {
        "current_password": "password123",
        "new_password": "newpassword123"
    }
    ```
- **Responses:**
    - `200`: Password change successful.
    - `400`: Current password is incorrect or user does not exist.
    - `401`: Token is missing, expired, or invalid.

### Edit User

- **Endpoint:** `/edit-user` or `/edit-user/<username>`
- **Method:** `PUT`
- **Headers:**
    - `Authorization: Bearer <token>`
- **Request Body:**
    ```json
    {
        "username": "newusername",
        "first_name": "NewFirstName",
        "last_name": "NewLastName",
        "email": "newemail@example.com",
        "role": "admin",  // Only for admin
        "active": true  // Only for admin
    }
    ```
- **Responses:**
    - `200`: User details updated successfully.
    - `400`: User not found.
    - `401`: Token is missing, expired, or invalid.
    - `403`: Permission denied.

### Forgot Password

- **Endpoint:** `/forgot-password`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "username": "johndoe"
    }
    ```
- **Responses:**
    - `200`: Reset token generated. Provides a reset URL.
    - `400`: Username not found.

### Reset Password

- **Endpoint:** `/reset-password/<token>`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "new_password": "newpassword123"
    }
    ```
- **Responses:**
    - `200`: Password reset successful.
    - `400`: User not found.
    - `401`: Invalid or expired token.


## Models

### User

- **Columns:**
  - `id`: Integer, primary key.
  - `username`: String(50), unique, not nullable.
  - `first_name`: String(50), not nullable.
  - `last_name`: String(50), not nullable.
  - `email`: String(120), unique, not nullable.
  - `password`: String(255), encrypted, not nullable.
  - `role`: Enum(User, Admin), default is `User`, not nullable.
  - `create_date`: DateTime, default is current timestamp.
  - `update_date`: DateTime, auto-updates on REST API call.
  - `active`: Boolean, default is `True`.

### ResetToken

- **Columns:**
  - `id`: Integer, primary key.
  - `username`: String(50), not nullable.
  - `token`: String(100), unique, not nullable.
  - `is_used`: Boolean, default is `False`.
  - `create_date`: DateTime, default is current timestamp.


## Notes

- Ensure your PostgreSQL database is running and the connection details are correctly set in the configuration.
- The default admin user is created automatically if no users exist in the database.
- This project uses JWT for authentication. Ensure you keep your `SECRET_KEY` safe and secure.
