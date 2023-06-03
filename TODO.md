<div align="center">
    <h1> PufferBlow-api's working plan </h1>
</div>

# Versions

- [0.1.0]() **_latest_**

# TO-DO

## 0.1.0

- Add a Database handler
  - Users
    - Add new users
    - delete users
    - list users
  - messages
    - Send messages
    - deletes messages
    - forward messages
    - list messages (implement a SSE)
- Security
  - Implement the PufferBlow encrypting algorithm for encrypt all the data in the database
  - Implement a token system, so that the owner of the server get to have root preveilges
  - Implement a anit-DDOS attack
  - Implement a timeout for users who send too many messages
  - Add a message-length limit
  - Add a users number limit
- Add all the needed route to the API
  - Main routes
    - Redirect route `"/"` (redirects to the home route)
    - Home route `"/api/v1"`
    - Server logs route `"/api/v1/server/logs"`
  - Users routes
    - List users route `"/api/v1/users/list"`
      - Parameters:
        ``` json
        {
            "access_token": str
        }
        ```      
    - Add new user route `"/api/v1/users/add"`
      - Parameters:
          ``` json
          {
              "username": str,
              "password": str
          }
          ```
    
    - Remove users route `"/api/v1/users/delete"`
      - Parameters:
          ``` json
          {
              "username": str,
              "access_token": str
          }
          ```
  - Messages routes
    - List messages route `"/api/v1/messages/list"`
      - Parameters:
        ``` json
        {
            "channel_id": str,
            "access_token": str
        }
        ```
    - Send messages route `"/api/v1/messages/send"`
      - Parameters:
        ``` json
        {
            "message_content": str,
            "channel_id": str,
            "access_token": str
        }
        ```
    - Delete messages route `"/api/v1/messages/delete"`
      - Parameters:
        ``` json
        {
            "message_id": str,
            "channel_id": str,
            "access_token": str
        }
        ```
- Create a documentation for the all the routes
- Add costum exceptions for all the possible erros and show them in the server logs
