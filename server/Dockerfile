FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates curl gnupg && \
    curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg | gpg --dearmor -o /usr/share/keyrings/smallstep-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/smallstep-archive-keyring.gpg] https://packages.smallstep.com/stable/debian debs main" | tee /etc/apt/sources.list.d/smallstep.list && \
    apt-get update && apt-get install -y step-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock* ./

RUN uv sync --frozen --no-cache

COPY . .

EXPOSE 8000

CMD ["uv", "run", "python", "manage.py", "runserver", "0.0.0.0:8000"]

