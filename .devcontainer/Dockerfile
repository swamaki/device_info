# Using Microsoft Devcontainers Python base image
FROM mcr.microsoft.com/devcontainers/python:3.11

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set zsh as the default shell for vscode user
RUN chsh -s $(which zsh) vscode
