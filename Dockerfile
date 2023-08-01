FROM ubuntu:20.04
RUN apt update && apt upgrade && \
apt install git && apt install curl && apt install build-essential && \
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && \
mkdir /home/projects && cd /home/projects &&  \
git clone git@github.com:flucium/xck.git \
ENV PATH="/root/.cargo/bin:$PATH"