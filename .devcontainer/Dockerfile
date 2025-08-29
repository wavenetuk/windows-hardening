# Use a more minimal base image if possible, but keep devcontainers/base for full compatibility with VS Code Dev Containers
# mcr.microsoft.com/devcontainers/base:ubuntu-22.04 is already a good choice for development environments
FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# Set noninteractive to prevent prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Define pip packages in a single ENV variable for better readability and maintainability
ENV pip_packages="cryptography pywinrm kerberos requests_kerberos passlib msrest PyVmomi pymssql pre-commit"

# Install system deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        gcc \
        ca-certificates \
        curl \
        git \
        gnupg \
        jq \
        krb5-user \
        krb5-config \
        libffi-dev \
        libkrb5-dev \
        libssl-dev \
        lsb-release \
        openssh-client \
        python3-dev \
        python3-gssapi \
        python3-pip \
        python3-netaddr \
        python3-jmespath \
        python3-setuptools \
        python3-wheel \
        python3-pymssql \
        python3-venv \
        sshpass \
        unzip \
    && apt-get update \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create and activate Python virtualenv
RUN python3 -m venv /opt/ansible_venv
ENV VIRTUAL_ENV=/opt/ansible_venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Combine pip installs into a single RUN layer for efficiency
# Use the --no-cache-dir flag to prevent caching of downloaded packages, which saves space
# Install pre-commit separately if it's a dev-only tool, or combine it if always needed
#ts:skip=AC_DOCKER_0010
RUN pip install --upgrade pip --no-cache-dir \
    && pip install $pip_packages --no-cache-dir

# Set the default command for the container
CMD ["pwsh"]
