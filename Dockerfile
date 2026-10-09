FROM python:3.12-slim

# nmap fournit aussi la base constructeurs (nmap-mac-prefixes)
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY web ./web

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    NETWATCH_DATA_DIR=/data \
    NETWATCH_PORT=8484

VOLUME ["/data"]
EXPOSE 8484

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('NETWATCH_PORT','8484'), timeout=4)"

CMD ["python", "-m", "app.main"]
