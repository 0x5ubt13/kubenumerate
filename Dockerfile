# syntax=docker/dockerfile:1

# Comments are provided throughout this file to help you get started.
# If you need more help, visit the Dockerfile reference guide at
# https://docs.docker.com/go/dockerfile-reference/

# Want to help us make this template better? Share your feedback here: https://forms.gle/ybq9Krt8jtBL3iCk7

ARG PYTHON_VERSION=3.11.6
FROM python:${PYTHON_VERSION}-slim as base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# From https://hub.docker.com/r/linuxbrew/linuxbrew/dockerfile: Install all needed packages to run brew
RUN apt-get update \
	&& apt-get install -y software-properties-common \
	&& apt-get update \
	&& apt-get install -y \
		bzip2 \
		ca-certificates \
		curl \
		file \
		fonts-dejavu-core \
		g++ \
		git \
		locales \
		make \
		openssh-client \
		patch \
        sudo \
		uuid-runtime \
        wget \
	&& rm -rf /var/lib/apt/lists/*

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/home/linuxbrew/" \
    --shell "/bin/bash" \
    --uid "${UID}" \
    subtle

# Kinda defeating the best practices above, we need sudo later on
RUN localedef -i en_US -f UTF-8 en_US.UTF-8 \
	&& echo 'subtle ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers 

USER subtle

RUN git clone https://github.com/Homebrew/brew ~/.linuxbrew/Homebrew \
&& mkdir ~/.linuxbrew/bin \
&& ln -s ../Homebrew/bin/brew ~/.linuxbrew/bin \
&& eval $(~/.linuxbrew/bin/brew shellenv) \
&& brew --version

WORKDIR /home/linuxbrew
ENV PATH=/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:$PATH

# Ugly hack to download kube-bench, yes I know
RUN curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | grep amd64.deb | grep browser_download | awk '{ print $2 }' | xargs wget \
    && sudo apt-get install -y ./kube-bench*

# Install kubectl, kubeaudit and trivy
RUN HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_AUTO_UPDATE=1 brew install \
    kubectl \
    kubeaudit \
    trivy

WORKDIR /tmp

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
# Copy the source code into the container.
COPY --chown=linuxbrew:linuxbrew ./kubenumerate.py ./requirements.txt ./

RUN pip install --upgrade pip \
    && pip install -r ./requirements.txt

# Run the application.
CMD python kubenumerate.py
