from fastapi.testclient import TestClient

from pufferblow.tests.conftest import ValueStorage

route = "/api/v1/users/signin"

def test_user_signin(client: TestClient):
    """
    Test signin to a user account
    """
    params =  {
        "username": ValueStorage.username,
        "password": ValueStorage.password
    } 
    
    response = client.get(route, params=params)
    
    auth_token = response.json()["auth_token"]
    
    assert response.status_code == 200
    assert auth_token == ValueStorage.auth_token

def test_username_not_found(client: TestClient):
    """
    Test username not found when singin up.
    """
    params =  {
        "username": ValueStorage.new_username,
        "password": ValueStorage.password
    }
    
    response = client.get(route, params=params)
    
    assert response.status_code == 404

def test_password_is_incorrect(client: TestClient):
    """
    Test password is incorrect
    """
    params =  {
        "username": ValueStorage.username,
        "password": ValueStorage.new_password
    }
    
    response = client.get(route, params=params)
    
    assert response.status_code == 401
