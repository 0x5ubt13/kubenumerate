# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.6
FROM python:${PYTHON_VERSION}-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

# Create non-privileged user early
RUN groupadd --gid 10001 subtle && \ 
    useradd --uid 10001 --gid subtle --shell /bin/bash --create-home subtle

# Install system dependencies
RUN apt-get update && \ 
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        unzip \
        sudo \
        locales \
        gnupg \
        lsb-release && \
    # Configure locale
    localedef -i en_US -f UTF-8 en_US.UTF-8 && \
    # Configure sudo for user
    echo 'subtle ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    # Clean up
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install build dependencies
RUN apt-get update && \ 
    apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
        make \
        patch \
        file \
        bzip2 && \
    # Clean up
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install additional tools
RUN apt-get update && \ 
    apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
        openssh-client \
        uuid-runtime \
        zip && \
    # Clean up
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install kubectl
RUN curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | \ 
    gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg && \
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | \
    tee /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update && \
    apt-get install -y kubectl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash && \ 
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Trivy
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | \ 
        jq -r '.tag_name') && \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz" | \
    tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy

# Install kubelogin
RUN KUBELOGIN_VERSION=$(curl -s https://api.github.com/repos/Azure/kubelogin/releases/latest | \ 
        jq -r '.tag_name') && \
    curl -fsSL "https://github.com/Azure/kubelogin/releases/download/${KUBELOGIN_VERSION}/kubelogin-linux-amd64.zip" \
        -o /tmp/kubelogin.zip && \
    unzip /tmp/kubelogin.zip -d /tmp/ && \
    mv /tmp/bin/linux_amd64/kubelogin /usr/local/bin/ && \
    chmod +x /usr/local/bin/kubelogin && \
    rm -rf /tmp/kubelogin.zip /tmp/bin

# Install kube-bench
RUN KUBE_BENCH_URL=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | \ 
        jq -r '.assets[] | select(.name | test("amd64.deb")) | .browser_download_url') && \
    wget -O /tmp/kube-bench.deb "$KUBE_BENCH_URL" && \
    apt-get update && \
    apt-get install -y /tmp/kube-bench.deb && \
    rm -f /tmp/kube-bench.deb && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install KubiScan
RUN mkdir -p /tmp/kubiscan && \ 
    KUBISCAN_URL=$(curl -s https://api.github.com/repos/cyberark/KubiScan/releases/latest | \
        jq -r '.zipball_url') && \
    wget -O /tmp/kubiscan/kubiscan.zip "$KUBISCAN_URL" && \
    unzip /tmp/kubiscan/kubiscan.zip -d /tmp/kubiscan/ && \
    chmod -R 755 /tmp/kubiscan && \
    rm -f /tmp/kubiscan/kubiscan.zip

# Switch to non-privileged user
USER subtle

# Create kube config directory
RUN mkdir -p ~/.kube/

# Set PATH to include /usr/local/bin for installed tools
ENV PATH=/usr/local/bin:/home/subtle/.local/bin:$PATH

# Set working directory
WORKDIR /app

# Copy Python requirements first (for better caching)
COPY --chown=subtle:subtle requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir --user -r requirements.txt

# Copy application files
COPY --chown=subtle:subtle kubenumerate.py ExtensiveRoleCheck.py summary_table.py ./

# Set entrypoint
ENTRYPOINT ["python3", "kubenumerate.py"]
