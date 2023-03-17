## Setting up locally

Create an environment and activate it

```shell
python3 -m venv .venv
source .venv/bin/activate
```

Install required dependencies.

```shell
pip3 install -r requirements.txt
```

To run the server in development mode

```shell
python3 runserver.py
```

## API

- POST `/token`

    ```shell
    #body (multipart structured)
    username: johndoe
    password: ***
    scope: me items

    #response
    {
        "access_token": "...",
        "token_type": "bearer"
    }
    ```

- GET `/users/me`, `/users/me/items` and `/status`

    ```shell
    Authorization: Bearer {access_token}
    ```


## Generate password hash

```shell
python3 app/generate_password_hash.py -p plain_password_here
```