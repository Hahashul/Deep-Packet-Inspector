# Linux/demo deployment: dashboard + passive analysis. Firewall/RST enforcement needs Windows (netsh + Npcap).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV IFACE="" API_TOKEN="" RETENTION_DAYS=30
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
# Needs raw capture rights and the host's network namespace:
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -e IFACE=eth0 -e API_TOKEN=change-me traffic-analyzer
CMD ["uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8000"]
