#!/usr/bin/env bash
set -e

rm -rf ./netdev/ 
git clone git@github.com:swamaki/netdev.git
pip install ./netdev/ 

echo "Asyncio netdev installed."
