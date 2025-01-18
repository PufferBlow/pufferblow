import pytest

from datetime import timedelta
from fastapi.testclient import TestClient

from pufferblow.api import api
from pufferblow.api_initializer import api_initializer

# Middlewares
from pufferblow.middlewares import (
    RateLimitingMiddleware,
    SecurityMiddleware
)

api_initializer.load_objects()

@pytest.fixture
def client():
    with TestClient(api) as test_client: 
        return test_client

# Global storage class
class ValueStorage:
    """
    Value storage class for sharing constants across tests cases
    """
    username                    :   str     =   "user1"
    password                    :   str     =   "12345678"
    new_username                :   str     =   "new_user1"
    new_password                :   str     =   "123456789"
    auth_token                  :   None
    moke_auth_token             :   str     =   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.apo0widnjtr456yjabmtoa02pgh6547heydbnh1ph"
    moke_user_id                :   str     =   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    bad_formated_auth_token     :   str     =   "abcd"

