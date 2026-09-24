FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV IN_DOCKER=1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip3 install --break-system-packages -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "main.py"]