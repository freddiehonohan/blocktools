#!/bin/bash
pw="m1.firstname.lastname.country.descr"
getpw () { 
        echo -n "$1" | openssl base64 -A | sha256sum | sha256sum | sha256sum | openssl base64 -A 
}
pw2=$(getpw "$pw")
pw3=$(getpw "$pw2.fuckyou.$pw3.fuckyou")
pw4=$(getpw "$pw3.scrypt")
echo "scrypt: $pw4"
scrypt enc -M 1000000000 input.txt input.scrypt
pw5=$(getpw "$p4.openssl")
echo "openssl: $pw5"
openssl aes-192-cbc -e -a < input.scrypt > output.aes
                  �ջD^�EA��!�]�M�G�w�p���ۼ[/I�0c0ւx�	
