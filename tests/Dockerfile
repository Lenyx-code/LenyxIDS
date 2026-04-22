FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    iputils-ping \
    iproute2 \
    python3 \
    python3-pip \
    scapy \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3 /usr/bin/python

CMD ["sleep", "infinity"]