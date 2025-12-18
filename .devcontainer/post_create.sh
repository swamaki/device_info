#!/usr/bin/env bash
# set -e

echo -e "\n=============== \e[1;30;42m Installing ZSH Autosuggestions... \e[0m ===============\n"

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

echo -e "\n=============== \e[1;30;42m Autosuggestions installed. \e[0m ===============\n"


# echo -e "\n=============== \e[1;30;42m Upgrading pip... \e[0m ===============\n"
# pip install --upgrade pip

# echo -e "\n=============== \e[1;30;42m Installing ANTA... \e[0m ===============\n"
# pip install 'anta[cli]'

# echo -e "\n=============== \e[1;30;42m Setting up environment... \e[0m ===============\n"
# sudo apt-get update
# sudo apt-get install -y git
# sudo apt-get install -y wget
# sudo apt-get install -y curl
# sudo apt-get install -y iputils-ping
# sudo apt-get install -y fping

echo -e "\n=============== \e[1;30;42m ✅ loaded vars in .env for ANTA  \e[0m ===============\n"

echo -e "\n=============== \e[1;30;42m Installing Asyncio netdev...  \e[0m ===============\n"
rm -rf /tmp/netdev/
git clone https://github.com/swamaki/netdev.git /tmp/netdev/
pip install /tmp/netdev/
rm -rf /tmp/netdev/
