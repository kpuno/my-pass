def test_create_user(client):
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 200
    data = response.json()
    assert "email" in data
    assert data["email"] == new_user["email"]
    assert "id" in data


def test_create_user_with_short_password(client):
    new_user = {
        "email": "shortpass@example.com",
        "username": "shortpassuser",
        "password": "Short1!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert errors[0]["msg"] == "Value error, Password must be at least 8 characters."


def test_create_user_with_no_uppercase(client):
    new_user = {
        "email": "noupper@example.com",
        "username": "noupperuser",
        "password": "nouppercase1!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert (
        errors[0]["msg"]
        == "Value error, Password must contain at least one uppercase letter"
    )


def test_create_user_with_no_lowercase(client):
    new_user = {
        "email": "nolower@example.com",
        "username": "noloweruser",
        "password": "NOLOWERCASE1!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert (
        errors[0]["msg"]
        == "Value error, Password must contain at least one lowercase letter"
    )


def test_create_user_with_no_digit(client):
    new_user = {
        "email": "nodigit@example.com",
        "username": "nodigituser",
        "password": "NoDigitPass!",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert errors[0]["msg"] == "Value error, Password must contain at least one digit"


def test_create_user_with_no_special_char(client):
    new_user = {
        "email": "nospecialchar@example.com",
        "username": "nospecialcharuser",
        "password": "NoSpecialChar1",
    }
    response = client.post("/users/", json=new_user)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert (
        errors[0]["msg"]
        == "Value error, Password must contain at least one special character"
    )


def test_create_existing_username(client):
    new_user = {
        "email": "uniqueuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    client.post("/users/", json=new_user)

    duplicate_user = {
        "email": "differentemail@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    response = client.post("/users/", json=duplicate_user)
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}


def test_create_existing_email(client):
    new_user = {
        "email": "testuser@example.com",
        "username": "uniqueuser",
        "password": "TestPassword123!",
    }
    client.post("/users/", json=new_user)

    duplicate_user = {
        "email": "testuser@example.com",
        "username": "differentusername",
        "password": "TestPassword123!",
    }
    response = client.post("/users/", json=duplicate_user)
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}


def test_read_users(client):
    # Create users
    users = [
        {"email": "user1@example.com", "username": "user1", "password": "Password123!"},
        {"email": "user2@example.com", "username": "user2", "password": "Password123!"},
    ]
    for user in users:
        client.post("/users", json=user)

    # Access the /users/ endpoint
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["username"] == "user1"
    assert data[1]["username"] == "user2"


def test_read_user(client):
    # Create a user
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    response = client.post("/users/", json=new_user)
    user_id = response.json()["id"]

    # Access the /users/{user_id} endpoint
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"

    # Access a non-existing user
    response = client.get("/users/9999")
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}


def test_read_users_me(client, db_session):
    # Create a user
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    client.post("/users", json=new_user)

    # Get a token
    response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "TestPassword123!"},
    )
    token_data = response.json()
    assert "access_token" in token_data
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Access the /users/me/ endpoint
    response = client.get("/users/me", headers=headers)
    print("Response Text:", response.text)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"
