# Stage 1: Build dependencies
FROM python:3.10-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /usr/src/app

RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    python3-dev 

COPY requirements.txt .

RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

# Stage 2
FROM python:3.10-alpine

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .

RUN apk add --no-cache libpq \
    && pip install --no-cache /wheels/* \
    && rm -rf /wheels

COPY --chown=appuser:appgroup . .

USER appuser

EXPOSE 8000

CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]