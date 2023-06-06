import os
import random
import string

def auth_token_generator(auth_tokens: str) -> str:
    """ Generates a unique auth token for a user """
    size = 41
    ascii_charachters = [char for char in string.ascii_lowercase + string.ascii_uppercase] 

    for _ in range(10):
        ascii_charachters.append(str(_))
    
    auth_token = ""
    
    while True:
        for i in range(size):
            auth_token += random.choice(ascii_charachters)
        
        if auth_token not in auth_tokens:
            break
        else:
            auth_token = ""
    
    return auth_token
