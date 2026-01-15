# Локальный запуск

Полные требования и переменные окружения — в `./assignment.md` и `../openapi.yml`.

## Требования к Docker-образу

Docker-образ должен содержать утилиту `curl` — автопроверка использует её для health-check. В шаблонах `curl` уже установлен. Если меняете базовый образ или Dockerfile, убедитесь, что `curl` присутствует.

## Быстрая проверка, что «живет».

1) Поднимите зависимости (минимум PostgreSQL):

```bash
docker run -d --name postgres \
  -e POSTGRES_USER=testuser \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_DB=antifraud \
  -p 5432:5432 \
  postgres:16-alpine
```

2) Соберите и запустите приложение (пример; путь к Dockerfile зависит от стартового шаблона, часто это `solution/`):

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

3) Проверьте, что сервер отвечает:

```bash
curl http://localhost:8080/api/v1/ping
```
