import pytest

from datetime import timedelta
from fastapi.testclient import TestClient

from pufferblow.api import api
from pufferblow.tests.conftest import ValueStorage

from pufferblow.api_initializer import api_initializer


# Middlewares
from pufferblow.middlewares import (
    RateLimitingMiddleware,
    SecurityMiddleware
)
# NOTE: The tests won't function now that we have added
# a middleware to handle security. So we need to figure
# a way to fix that.

route = "/api/v1/users/signup"

def test_signup(client: TestClient):
    data = {
        "username": ValueStorage.username,
        "password": ValueStorage.password
    }

    response = client.post(route, params=data)

    assert response.status_code == 201
    
    response = response.json()

    ValueStorage.auth_token = response["auth_token"]

def test_signup_username_duplicate_exception(client: TestClient):
    """ Test the exception that will get raised if the username
    used is repeated or duplicated
    """
    data = {
        "username": ValueStorage.username,
        "password": ValueStorage.password
    }

    response = client.post(route, params=data)

    assert response.status_code ==  409
    assert response.json() == {
        "error": "username already exists. Please change it and try again later",
    }
