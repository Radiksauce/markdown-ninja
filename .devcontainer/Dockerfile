FROM golang:1.24 AS go

FROM ubuntu:24.04

ENV TZ="UTC"
RUN echo "${TZ}" > /etc/timezone

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt upgrade -y
RUN apt-get install -y --no-install-recommends \
    # base system. psmisc for killall. openssh-client for git over SSH. netbase for whois.
    bash curl wget psmisc ca-certificates lsb-release openssh-client netbase whois sqlite3 less netcat-openbsd \
    # dev tools. dnsutils for dig.
    git vim make binutils coreutils build-essential pkg-config \
    zip gnupg gcc libc6-dev htop wrk zstd gzip upx gdb dnsutils jq b3sum \
    #  g++ musl musl-dev musl-tools clang libclang-dev lld cmake \
    # useful data. mailcap for mimetypes. tzdata for timezones.
    mailcap tzdata libpcre3-dev \
    # mdninja-server specific dependencies
    postgresql-client-16 nodejs npm libimage-exiftool-perl

# setup node
RUN npm config set ignore-scripts true
# npm@10 is the last version compatible with nodejs@18 shipped with Ubuntu 24.04
RUN npm i -g npm@10

# Setup dev user
ARG USERNAME=dev
ARG USER_UID=10001
ARG USER_GID=$USER_UID

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/home/${USERNAME}" \
    --shell "/bin/bash" \
    --uid "${USER_UID}" \
    "${USERNAME}"


USER $USERNAME

COPY --chown=$USERNAME bashrc /home/$USERNAME/.bashrc
COPY --chown=$USERNAME vimrc /home/$USERNAME/.vimrc

# setup go
RUN mkdir -p /home/$USERNAME/.local/gopath
COPY --from=go /usr/local/go /usr/local/go
RUN /usr/local/go/bin/go telemetry off

# setup git
RUN git config --global push.autoSetupRemote true
RUN git config --global init.defaultBranch main

# setup node (again, as a normal user this time)
RUN npm config set ignore-scripts true

WORKDIR /
