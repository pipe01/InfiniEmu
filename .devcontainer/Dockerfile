FROM alpine:3.19
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ARG toolchain_ver=arm-gnu-toolchain-13.2.rel1-x86_64-arm-none-eabi
RUN wget -q -O toolchain.tar.xz https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu/13.2.rel1/binrel/${toolchain_ver}.tar.xz
RUN tar xf toolchain.tar.xz -C /opt && mv /opt/arm-gnu-toolchain* /opt/arm-gnu-toolchain
RUN rm toolchain.tar.xz

RUN apk add --no-cache git wget capstone-dev shadow gcc musl-dev make gdb openssh

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

USER $USERNAME
