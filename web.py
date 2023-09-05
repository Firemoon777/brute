import base64
import json
import os
from datetime import datetime

from fastapi import FastAPI, Request, Response
from sqlalchemy.orm import Session

from brute.db import make_engine, WebLoginAttempt, Base

app = FastAPI()

engine = make_engine(os.environ["SQLALCHEMY_URL"])
Base.metadata.create_all(engine)


def basic_auth():
    headers = {'WWW-Authenticate': 'Basic realm="Admin zone", charset="UTF-8"'}
    response = Response(status_code=401, headers=headers)
    return response


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /", media_type="text/plain")


@app.get("/{full_path:path}")
@app.post("/{full_path:path}")
@app.patch("/{full_path:path}")
@app.put("/{full_path:path}")
@app.delete("/{full_path:path}")
@app.options("/{full_path:path}")
async def read_root(request: Request, full_path: str):
    if request.url.path.startswith("/admin"):
        cred = str(request.headers.get("Authorization"))
        if not cred:
            return basic_auth()

        if cred.startswith("Basic ") is False:
            return basic_auth()

        data = base64.b64decode(cred[6:]).decode("utf8", errors="ignore")
        if ":" not in data:
            return basic_auth()

        login, password = data.split(":", 1)
    else:
        login = None
        password = None

    headers = {k: v for k, v in request.headers.items()}
    cookies = {k: v for k, v in request.cookies.items()}
    query = {k: v for k, v in request.query_params.items()}
    body = await request.body()
    with Session(engine) as session:
        session.add(WebLoginAttempt(
            attempt_time=datetime.now(),
            attacker_ip=request.headers.get("x-real-ip"),
            attacker_user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            content_type=request.headers.get("content-type"),
            headers=headers,
            cookies=cookies,
            query=query,
            login=login,
            password=password,
            body=body,
            body_decoded=body.decode(encoding="utf-8", errors="ignore")
        ))
        session.commit()

    return {"result": True}

