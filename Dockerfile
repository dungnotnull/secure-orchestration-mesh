FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proto/ ./proto/
COPY agent_sdk/ ./agent_sdk/
COPY orchestrator/ ./orchestrator/
COPY anomaly/ ./anomaly/
COPY translator/ ./translator/
COPY llm/ ./llm/
COPY self_update/ ./self_update/
COPY config.yaml .

RUN mkdir -p /app/data /app/models /app/reports /app/config

EXPOSE 50051

CMD ["python", "-m", "orchestrator.main"]
