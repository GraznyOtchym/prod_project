from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/ping")
def ping():
    return {"status": "ok"}