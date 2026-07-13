FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
RUN addgroup --gid 10001 threatcommand \
    && adduser --system --uid 10001 --ingroup threatcommand --home /app threatcommand \
    && mkdir -p /app/data/imports /app/data/exports /app/data/logs \
    && chown -R threatcommand:threatcommand /app

EXPOSE 8000
USER threatcommand
