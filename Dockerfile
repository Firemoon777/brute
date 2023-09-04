FROM ubuntu:22.04

RUN apt update && apt install -y ssh wget curl iputils-ping && mkdir /run/sshd && echo "root:root" | chpasswd

COPY sshd_config /etc/ssh/sshd_config

ENTRYPOINT ["/bin/bash", "-c", "/usr/sbin/sshd -D & sleep 60"]
