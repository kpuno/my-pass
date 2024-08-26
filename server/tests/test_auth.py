def test_login(client, db_session):
    # Create a user for authentication test
    new_user = {
        "email": "testuser@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
    }
    client.post("/users/", json=new_user)

    # Test successful login
    response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "TestPassword123!"},
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Test failed login
    response = client.post(
        "/auth/token",
        data={"username": "testuser", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}
