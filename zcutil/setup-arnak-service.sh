#!/bin/bash

if [ $# -eq 0 ]
then
    echo "Arnak systemd unit setup."
    echo -e "Run:\n$0 user\nor install for current user\n$0 $USER"
    exit 1
fi

if id "$1" >/dev/null 2>&1
then
    echo "Installing Arnak service for $1 user..."
else
    echo -e "User $1 does not exist.\nTo add user run the following command:\nsudo adduser --disabled-password --gecos '' $1"
    exit 1
fi

cat > /tmp/config_setup.sh << EOF
#!/bin/bash
if ! [[ -d ~/.arnak ]]
then
    mkdir -p ~/.arnak
fi

if ! [[ -f ~/.arnak/arnak.conf ]]
then
    echo "rpcuser=rpc`pwgen 15 1`" > ~/.arnak/arnak.conf
    echo "rpcpassword=rpc`pwgen 15 1`" >> ~/.arnak/arnak.conf
fi
EOF
chmod +x /tmp/config_setup.sh
sudo -H -u $1 /tmp/config_setup.sh
sudo -H -u $1 ~/arnak-pkg/fetch-params.sh


cat > /etc/systemd/system/arnak.service << EOF
[Unit]
Description=arnak

[Service]
ExecStart=`cd ~; pwd`/arnak-pkg/arnakd
User=$1
Restart=always


[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable arnak
systemctl start arnak

systemctl status arnak
