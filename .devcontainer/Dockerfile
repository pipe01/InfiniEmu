FROM debian:12
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# RUN apk add --no-cache git wget capstone-dev shadow gcc musl-dev make gdb openssh
RUN apt update && apt install -y git wget gcc make gdb xz-utils unzip

ARG toolchain_ver=13.2.rel1 
RUN wget -q -O toolchain.tar.xz https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu/${toolchain_ver}/binrel/arm-gnu-toolchain-${toolchain_ver}-x86_64-arm-none-eabi.tar.xz
RUN tar xf toolchain.tar.xz -C /opt && mv /opt/arm-gnu-toolchain* /opt/arm-gnu-toolchain
RUN rm toolchain.tar.xz

RUN cd opt && \
    mkdir nrfx && cd nrfx && \
    wget -q -O nrfx.zip https://github.com/NordicSemiconductor/nrfx/releases/download/v3.4.0/nrfx-v3.4.0-7c47cc0a.zip && \
    unzip nrfx.zip && \
    rm nrfx.zip

RUN wget -q -O sdk.zip https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v15.x.x/nRF5_SDK_15.3.0_59ac345.zip && \
    unzip -q sdk.zip -d /opt && \
    rm sdk.zip

RUN cd /tmp && \
    wget -q -O capstone.tar.gz https://github.com/capstone-engine/capstone/archive/5.0.1.tar.gz && \
    tar xf capstone.tar.gz && \
    cd capstone* && \
    ./make.sh install && \
    rm -r capstone*

RUN nproc

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -s /bin/bash -m $USERNAME

ENV NRFX_PATH /opt/nrfx
ENV NRF5_SDK_PATH /opt/nRF5_SDK_15.3.0_59ac345
ENV ARM_TOOLCHAIN_PATH /opt/arm-gnu-toolchain

USER $USERNAME