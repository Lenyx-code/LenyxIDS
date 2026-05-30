FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    # Scan & reconnaissance
    nmap \
    # Flood & DoS
    hping3 \
    # Réseau
    iputils-ping \
    iproute2 \
    net-tools \
    # ARP Spoofing
    arping \
    dsniff \
    # Services à attaquer
    openssh-server \
    apache2 \
    # Python
    python3 \
    python3-pip \
    && pip3 install scapy --break-system-packages \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN ln -sf /usr/bin/python3 /usr/bin/python

# Configuration SSH sur la victime
RUN mkdir -p /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]