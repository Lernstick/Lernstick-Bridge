FROM debian:bullseye-slim

# Header files are needed for tpm2-pytss
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
    python3 \
    python3-pip \
    git \
    pkg-config \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-fapi1 \
    libtss2-mu0 \
    libcurl4-openssl-dev \
    libssl-dev \
    libjson-c-dev \
    tpm2-tools

COPY requirements.txt /requirements.txt
RUN pip3 install -r requirements.txt

# Ship cert store in the container by default
COPY tpm_cert_store /lernstick/tpm_cert_store

RUN --mount=target=/bridge,type=bind,source=.,rw \
    cd bridge && python3 setup.py install

EXPOSE 8080

ENTRYPOINT ["lernstick_bridge"]

