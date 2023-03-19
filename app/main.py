from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import (
    OAuth2PasswordRequestForm,
)
from fastapi.middleware.cors import CORSMiddleware

import app.auth as auth

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/token", response_model=auth.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth.authenticate_user(auth.fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email, "scopes": form_data.scopes},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=auth.User)
async def read_users_me(current_user: auth.User = Depends(auth.get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: auth.User = Security(auth.get_current_active_user, scopes=["items"])
):
    return [{"item_id": "Foo", "owner": current_user.email}]


@app.get("/status/")
async def read_system_status(current_user: auth.User = Depends(auth.get_current_user)):
    return {"status": "ok"}