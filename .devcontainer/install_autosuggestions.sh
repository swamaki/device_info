#!/usr/bin/env bash
set -e

# Install zsh-autosuggestions plugin
git clone https://github.com/zsh-users/zsh-autosuggestions \
    ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

# Make sure .zshrc exists
if [ ! -f ~/.zshrc ]; then
    cp /usr/share/oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
fi

# Add plugin if not already added
if ! grep -q "zsh-autosuggestions" ~/.zshrc; then
    sed -i 's/plugins=(/plugins=(zsh-autosuggestions /' ~/.zshrc
fi

echo "Autosuggestions installed."
