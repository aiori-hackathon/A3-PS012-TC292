FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir dnspython PyYAML Jinja2
WORKDIR /app
CMD ["sleep", "infinity"]
