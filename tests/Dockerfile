FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    siege \
    wrk \
    iputils-ping \
    iproute2 \
    net-tools \
    curl \
    wget \
    arping \
    dsniff \
    sqlmap \
    wfuzz \
    stress-ng \
    openssh-server \
    apache2 \
    python3 \
    python3-pip \
    && pip3 install scapy psutil pymongo --break-system-packages \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN ln -sf /usr/bin/python3 /usr/bin/python

RUN mkdir -p /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]