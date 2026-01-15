# Local run

Full requirements and environment variables are in `./assignment.md` and `../openapi.yml`.

## Docker image requirements

The Docker image must include the `curl` utility — autotests use it for health checks. Project templates already have `curl` installed. If you change the base image or Dockerfile, make sure `curl` is present.

## Quick check, what's "alive"

1) Start the dependencies (minimum PostgreSQL):

```bash
docker run -d --name postgres \
  -e POSTGRES_USER=testuser \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_DB=antifraud \
  -p 5432:5432 \
  postgres:16-alpine
```

2) Build and run the application (for example, the path to the Dockerfile depends on the starter template, often `solution/`):

```bash
cd solution
docker build -t antifraud .
docker run -d --name app \
  -e SERVER_PORT=8080 \
  -e POSTGRES_HOST=host.docker.internal \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_DATABASE=antifraud \
  -e POSTGRES_USERNAME=testuser \
  -e POSTGRES_PASSWORD=testpass \
  -p 8080:8080 \
  antifraud
```

3) Check that the server responds:

```bash
curl http://localhost:8080/api/v1/ping
```
