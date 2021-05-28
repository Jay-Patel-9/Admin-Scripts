#!/bin/sh
set -e #exit script on any error.
# set -x
service_name=jettyservicename #jetty app service name
app_kestore_path="/apps/etc/" #app directory where keystore exists
keystore_name="app.keystore" #keystore name in use
time=$(date +%d%m%y_%H%M%S) #timestap
pkpass="myPassword" #.pk12 certificate password
storepass=${pkpass} #new keystore password (good to have it same from jetty-ssl-contex.xml)
domain=domain.company.com #domain against which we want to generate certificate
letsencryptpath=/etc/letsencrypt/live/${domain}/ #let's encrypt path
openssl version > /dev/null #checking open ssl installation
openssl_status=$?
certbot --version #checking certbot installation
keytool > /dev/null #checking keytool installation
keytool_status=$?

generatekeystore() {
    cd ${letsencryptpath} || { echo "[!] unable to cd ${letsencryptpath}, EXITING"; exit 1; }

    echo "[#] Generating key store"
    openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -certfile cert.pem -name ${domain} -out jetty.pkcs12 -passout "pass:$pkpass"

    sudo mv ${app_kestore_path}/${keystore_name} ${app_kestore_path}/${keystore_name}_${time}

    echo "[#] Applying key store"
    keytool -importkeystore -noprompt -srckeystore jetty.pkcs12 -srcstoretype PKCS12 -srcstorepass "$pkpass" -destkeystore ${app_kestore_path}/${keystore_name} -deststorepass "$storepass"

}

if [ "$keytool_status" = 0 ] && [ "$openssl_status" = 0 ]; then
    echo "[#] Verified openssl & keytool"
    if [ -d ${letsencryptpath} ]; then
        #cert renew
        echo "[!] Certificate already exists! Do you want to renew it?"
        read -p "Yes(y) or No(n)?" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            generatekeystore
        else
            echo "[#] Exiting.!"
            exit 1
        fi
    else
        echo "[#] Stopping service ${service_name}"
        sudo service ${service_name} stop
        sudo certbot certonly --standalone --agree-tos --preferred-challenges http -d ${domain}
        if [ $? -eq 0 ]; then
            generatekeystore
        else
            echo "[!] Fail to create SSL, please check letsencrypt logs."
        fi
    fi
    echo "[#] Starting service $service_name"
    sudo service ${service_name} start

else
    echo "[!] Openssl or keytool isn't installed."
fi
