# syntax=docker/dockerfile:1

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
        jq \
		locales \
		make \
		openssh-client \
		patch \
		sudo \
		uuid-runtime \
		wget \
	&& rm -rf /var/lib/apt/lists/* \
    # Get latest version of kube-bench directly from GitHub
	&& curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | jq -r '.assets[] | select(.name | test("amd64.deb")) | .browser_download_url' | wget -i - \
    # planned upgrade: including rbac-police: curl -s https://api.github.com/repos/PaloAltoNetworks/rbac-police/releases/latest | jq -r '.assets[] | select(.name | test("linux_amd64")) | .browser_download_url' | wget -i - \
    && sudo apt-get install -y ./kube-bench* \
	# Kinda defeating the best practices above, we need sudo later on
	&& localedef -i en_US -f UTF-8 en_US.UTF-8 \
	&& echo 'subtle ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
	# Create a non-privileged user that the app will run under.
	# See https://docs.docker.com/go/dockerfile-user-best-practices/
	&& adduser \
    	--disabled-password \
    	--gecos "" \
    	--home "/home/subtle" \
    	--shell "/bin/bash" \
    	--uid 10001 \
    	subtle

USER subtle

# Create all needed folders for brew and kubeconfig
RUN git clone https://github.com/Homebrew/brew ~/.linuxbrew/Homebrew \
	&& mkdir ~/.linuxbrew/bin \
	&& ln -s ../Homebrew/bin/brew ~/.linuxbrew/bin \
	&& eval $(~/.linuxbrew/bin/brew shellenv) \
	&& brew --version \
	&& mkdir ~/.kube/ \
	# Install kubectl, kubeaudit and trivy
	&& brew install \
    		kubectl \
    		kubeaudit \
    		trivy 

ENV PATH=/home/subtle/.linuxbrew/bin:/home/subtle/.linuxbrew/sbin:$PATH

WORKDIR /tmp/

# Copy script, reqs and kubeconfig file inside the container
COPY --chown=subtle:subtle ./kubenumerate.py ./requirements.txt ./

RUN pip install --upgrade pip \
    && pip install -r ./requirements.txt

# Run the application.
ENTRYPOINT [ "python", "kubenumerate.py" ]
