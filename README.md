# Auth Service DJango

This project is a Django authentication service implemented with Django Rest Framework (DRF). It includes functionality
for user authentication using tokens and token blacklist management.

## Features

- Django version: 5.0
- Django Rest Framework version: 3.14.0
- Token-based authentication
- Token blacklist functionality
- User registration, login, logout

## Installation

1. Clone the repository
    ```bash
    git clone https://github.com/edonssfall/edAuth-BE.git 
    ```
2. Enter the project directory
    ```bash
    cd edAuth-BE
    ```
3. Copy the `.env.example` file to `.env` and update the environment variables
    ```bash
    cp .env.example .env
    ```
4. Create a virtual environment and activate it
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
5. Install the dependencies
    ```bash
    pip install -r requirements.txt
    ```
6. Run the migrations
    ```bash
    python manage.py migrate
    ```

## Usage

1. Run the development server
    ```bash
    python manage.py runserver
    ```

## Configuration

### Authentication
Token-based authentication is used in this project. Users can register, login, and logout using their email and
password. Tokens are issued upon successful login and must be included in the Authorization header for authenticated
requests.

### Token Blacklist
Token blacklist functionality is implemented to invalidate tokens upon logout. When a user logs out, their token is
added to the blacklist and cannot be used for authentication thereafter.