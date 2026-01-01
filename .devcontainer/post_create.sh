#!/usr/bin/env bash
# set -e

#------------------------------------------------------------
######################### setup #########################
#------------------------------------------------------------

# Define color variables
# 0 = Black, 1 = Red, 2 = Green, 3 = Yellow, 4 = Blue, 7 = White
BLACK_FG := $(shell tput setaf 0)
GREEN_BG := $(shell tput setab 2)
YELLOW_BG := $(shell tput setab 3)
RESET  := $(shell tput sgr0)
BOLD   := $(shell tput bold)

# Style
HEADER_START := \n=============== $(BOLD)$(BLACK_FG)$(YELLOW_BG)
HEADER_END   := $(RESET) ===============\n

#------------------------------------------------------------
########################## script ###########################
#------------------------------------------------------------

echo -e "$(HEADER_START) Installing ZSH Autosuggestions... $(HEADER_END)"

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

echo -e "$(HEADER_START) Autosuggestions installed. $(HEADER_END)"


# echo -e "$(HEADER_START) Upgrading pip... $(HEADER_END)"
# pip install --upgrade pip

# echo -e "$(HEADER_START) Installing ANTA... $(HEADER_END)"
# pip install 'anta[cli]'

# echo -e "$(HEADER_START) Setting up environment... $(HEADER_END)"
# sudo apt-get update
# sudo apt-get install -y git
# sudo apt-get install -y wget
# sudo apt-get install -y curl
# sudo apt-get install -y iputils-ping
# sudo apt-get install -y fping

echo -e "$(HEADER_START) ✅ loaded vars in .env for ANTA  $(HEADER_END)"

echo -e "$(HEADER_START) Installing Asyncio netdev...  $(HEADER_END)"
rm -rf /tmp/netdev/
git clone https://github.com/swamaki/netdev.git /tmp/netdev/
pip install /tmp/netdev/
rm -rf /tmp/netdev/
