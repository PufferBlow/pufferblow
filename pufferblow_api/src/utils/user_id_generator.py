import os
import random
import string

def user_id_generator(user_ids: list) -> str:
    """ Generates a unique user id for a user """
    size = 17
    ascii_charachters = [char for char in string.ascii_lowercase + string.ascii_uppercase] 

    for _ in range(10):
        ascii_charachters.append(str(_))
    
    user_id = ""
    
    while True:
        for i in range(size):
            user_id += random.choice(ascii_charachters)
        
        if user_id not in user_ids:
            break
        else:
            user_id = ""
    
    return user_id
