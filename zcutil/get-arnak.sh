#!/bin/bash

sudo apt -y update
sudo apt-get install -y libc6-dev g++-multilib python p7zip-full pwgen jq curl
cd ~

if [ -f arnak.zip ]
then
    rm arnak.zip
fi
wget -O arnak.zip `curl -s 'https://api.github.com/repos/arnak/arnak/releases/latest' | jq -r '.assets[].browser_download_url' | egrep "arnak.+x64.zip"`
7z x -y arnak.zip
chmod -R a+x ~/arnak-pkg
rm arnak.zip

cd ~/arnak-pkg
./fetch-params.sh

if ! [[ -d ~/.arnak ]]
then
    mkdir -p ~/.arnak
fi

if ! [[ -f ~/.arnak/arnak.conf ]]
then
    echo "rpcuser=rpc`pwgen 15 1`" > ~/.arnak/arnak.conf
    echo "rpcpassword=rpc`pwgen 15 1`" >> ~/.arnak/arnak.conf
fi

./arnakd
