from datetime import datetime, timedelta
from typing import List, Union

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "2f820a69dbabc7bee7bbfe836db2d1e5b26f4504f637f7384af7390aa2ba2ea9"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe@example.com": {
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$c82gByJCfFBVAtV5J9EIr.PiAfTRFTQcjqS4e6ZSH8aGfJc0qWkh2", #123456
        "disabled": False,
    },
    "alicechains@example.com": {
        "full_name": "Alice Chains",
        "email": "alicechains@example.com",
        "hashed_password": "$2b$12$as1CoEvYWepO2Fe/bxvSF.xJ.h76brXIDf7pzizU.XBBvGYH7uNNi", #123456
        "disabled": True,
    },
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Union[str, None] = None
    scopes: List[str] = []


class User(BaseModel):
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(db, email: str):
    if email in db:
        user_dict = db[email]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, email: str, password: str):
    user = get_user(fake_db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, email=email)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(fake_users_db, email=token_data.email)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=["me"])
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user