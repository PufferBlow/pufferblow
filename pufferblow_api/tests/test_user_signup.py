# import os
# import datetime

# from pufferblow_api.src.hasher.hasher import Hasher
# from pufferblow_api.src.models.user_model import User
# from pufferblow_api.src.models.tests_model import Test
# from pufferblow_api.src.database.database_handler import DatabaseHandler
# from pufferblow_api.src.database.database_session import DatabaseSession
# from pufferblow_api.src.utils.user_id_generator import user_id_generator
# from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIConfig

# PUFFERBLOW_API_CONFIG = PufferBlowAPIConfig()

# DATABASE_SESSION = DatabaseSession(
#     PUFFERBLOW_API_CONFIG.SUPABASE_URL,
#     PUFFERBLOW_API_CONFIG.SUPABASE_KEY,
#     PUFFERBLOW_API_CONFIG
# )
# HASHER = Hasher()
# DATABASE_HANDLER = DatabaseHandler(
#     database_connenction    =   DATABASE_SESSION.database_connection_session(),
#     hasher                  =   HASHER    
# )

# def test_user_signup() -> bool:
#     """ Test the user signup functionality """
#     user = User()

#     user.username       = "test_user_signup"
#     user.password_hash  = "f7xoIhlivCegtS6T0YzbTw+4Xqcp2wNa"
#     user.contacts       = []
#     user.conversations  = []
#     user.email          = "0ramsy0@gmail.com"
#     user.status         = "ONLINE"

#     user.auth_token, user.auth_token_expire_time, user.user_id = DATABASE_HANDLER.sign_up(
#         user,
#         is_test_mode=True
#     )

#     CURSOR = DATABASE_SESSION.database_connection_session().cursor()

#     sql = f"SELECT * FROM users WHERE user_id = '{user.user_id}'"

#     CURSOR.execute(sql)

#     users = CURSOR.fetchall()

#     if len(users) > 0:
#         return True
#     else:
#         False
