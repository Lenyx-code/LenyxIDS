FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN ls -la

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt 


ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]