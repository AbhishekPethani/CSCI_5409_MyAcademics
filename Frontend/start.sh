#!/bin/bash

sudo apt-get update

curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
sudo apt install nodejs

npm install
npm start