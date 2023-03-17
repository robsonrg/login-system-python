import argparse
from passlib.context import CryptContext

ap = argparse.ArgumentParser()
ap.add_argument("-p", "--password", required=True,
   help="input the plain password")
args = vars(ap.parse_args())

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

hashed_password = pwd_context.hash(args['password'])

print(hashed_password)
