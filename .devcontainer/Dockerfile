FROM mcr.microsoft.com/devcontainers/python:3.11

ENV DEBIAN_FRONTEND=noninteractive

# Install system packages including zsh
RUN echo "\n=============== Setting up environment... ===============\n" && \
    sudo apt-get update && sudo apt-get install -y \
    git \
    wget \
    curl \
    iputils-ping \
    fping \
    zsh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set zsh as the default shell for vscode user
RUN chsh -s $(which zsh) vscode

# # Add ll alias to zsh configuration
# RUN echo "alias ll='ls -alF'" >> /home/vscode/.zshrc

# Install Python packages
RUN echo "\n=============== Upgrading pip and installing python packages... ===============\n" && \
    pip install --upgrade pip && \
    pip install \
    ansible \
    asyncio \
    black \
    click \
    Jinja2 \
    netbox-initializers \
    netmiko \
    nornir \
    nornir_ansible \
    nornir_napalm \
    nornir_utils \
    ntc-templates \
    pylint \
    python-decouple \
    pytz \
    pyyaml \
    regex \
    requests \
    rich \
    xmltodict \
    yamlordereddictloader \ 
    'anta[cli]'

# # Ensure vscode owns the zshrc file
# RUN chown vscode:vscode /home/vscode/.zshrc
