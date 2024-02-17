
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
