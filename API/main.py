import os
import time

import requests
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from jose.jwk import construct
from starlette import status

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")

REPORT_ALLOW_ROLE = "prothetic_user"

TARGET_ALGORITHMS = ["HS256", "RS256"]

security = HTTPBearer()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def compute_public_key():
    url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    response = requests.get(url)
    jwks = response.json()
    return jwks['keys'][0]


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        key = compute_public_key()
        public_key = construct(key)
        token_payload = jwt.decode(token, key=public_key, algorithms=TARGET_ALGORITHMS,
                                   options={"verify_aud": False})
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User token is not valid")

    if token_payload["exp"] < time.time():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )

    roles = token_payload['realm_access']['roles']
    if REPORT_ALLOW_ROLE not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="The required role is missing")

    return token_payload


@app.get("/reports")
def get_all_reports(user=Depends(verify_token)):
    return {"user": user['name'], "reports": "report.zip"}
