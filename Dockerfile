FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
ENV TZ=UTC
WORKDIR /app

RUN apt-get update && \
    apt-get install -y cron tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

COPY . .

RUN chmod 0644 cron/2fa-cron && \
    crontab cron/2fa-cron

RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

EXPOSE 8080

CMD cron && uvicorn api:app --host 0.0.0.0 --port 8080
