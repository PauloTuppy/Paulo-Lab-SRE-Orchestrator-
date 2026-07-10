FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Install kubectl matching standard cluster deployment requirements
RUN curl -L https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/ ./orchestrator/
COPY sql/ ./sql/

# Create database directory
RUN mkdir -p /var/lib/incident-db

# Default environment variables
ENV DB_PATH=/var/lib/incident-db/incident_history.sqlite3
ENV EXECUTION_MODE=production
ENV ORCHESTRATOR_ENABLED=true

# By default, run the SRE worker daemon.
# To run the API container in production, override the CMD with:
# CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "orchestrator.api:app", "--bind", "0.0.0.0:8000"]
CMD ["python", "-m", "orchestrator.worker"]
