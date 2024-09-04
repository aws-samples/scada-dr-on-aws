#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
echo '====== Starting script ======'>> /var/log/cloud-init-output.log
echo 'install this please https://files.inductiveautomation.com/release/ia/8.1.36/20240102-1152/Enterprise%20Administration-module.modl?first-download=1' 

function register_password() {
  local SQLITE3=( sqlite3 $1 ) password_hash

  echo "Registering Admin Password with Configuration DB"

  # Generate Salted PW Hash
  password_hash=$(generate_salted_hash "$3")

  # Update INTERNALUSERTABLE
  echo "  Setting default admin user to USERNAME='$2' and PASSWORD='${password_hash}'"
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE INTERNALUSERTABLE SET USERNAME='"'$2'"', PASSWORD='"'$password_hash'"' WHERE PROFILEID=1 AND USERID=1'
}


# Function to hash user password.
function generate_salted_hash() {
  local -u auth_salt
  local auth_pwhash auth_pwsalthash auth_password password_input
  password_input="${1}"

  auth_salt=$(date +%s | sha256sum | head -c 8)
  auth_pwhash=$(printf %s "${password_input}" | sha256sum - | cut -c -64)
  auth_pwsalthash=$(printf %s "${password_input}${auth_salt}" | sha256sum - | cut -c -64)
  auth_password="[${auth_salt}]${auth_pwsalthash}"
  echo "${auth_password}"
}

while [ $# -gt 0 ] ; do
  case $1 in
    --stackname)              stackname=$2;;
    --cloudregion)              cloudregion=$2;;
	--gwname)                 gwname=$2;;
    --gwusername)             gwusername=$2;;
    --gwpassword)             gwpassword=$2;;
    --redundancyrole)         redundancyrole=$2;;
    --masterip)               masterip=$2;;
    --dbip)                   dbip=$2;;
    --dbschema)               dbschema=$2;;
    --dbusername)             dbusername=$2;;
    --dbpassword)             dbpassword=$2;;
    --dbport)                 dbport=$2;;
	--ganoutgoingip)          ganoutgoingip=$2;;
    --ganoutgoinggwname)      ganoutgoinggwname=$2;;
	--gansecuritygwnames)     gansecuritygwnames=$2;;
	--gancertingwname)        gancertingwname=$2;;
	--ganincominggwname1)     ganincominggwname1=$2;;
	--ganincomingip1)         ganincomingip1=$2;;
	--ganincominghost1)       ganincominghost1=$2;;
    --ganincominggwname2)     ganincominggwname2=$2;;
	--ganincomingip2)         ganincomingip2=$2;;
	--ganincominghost2)       ganincominghost2=$2;;
    --ganincominggwname3)     ganincominggwname3=$2;;
	--ganincomingip3)         ganincomingip3=$2;;
	--ganincominghost3)       ganincominghost3=$2;;
	--generateclientvpncerts) generateclientvpncerts=$2;;
  esac
  shift
done

sudo yum -y update openssl
sudo yum install sqlite-devel -y

echo "stack name" $stackname >> /var/log/cloud-init-output.log
echo "finished updating OPENSSL" >> /var/log/cloud-init-output.log

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
echo "Token" $TOKEN >> /var/log/cloud-init-output.log
region=$cloudregion
echo "region" $region >> /var/log/cloud-init-output.log
localip=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
echo "localip" $localip >> /var/log/cloud-init-output.log
localhostname=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-hostname)
echo "localhostname" $localhostname >> /var/log/cloud-init-output.log
publicstatuscode=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s -o /dev/null -I -w "%{http_code}" http://169.254.169.254/latest/meta-data/public-ipv4)
echo "publicstatuscode" $publicstatuscode >> /var/log/cloud-init-output.log
publicip=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
echo "publicip" $publicip >> /var/log/cloud-init-output.log
publichostname=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-hostname)
echo "publichostname" $publichostname >> /var/log/cloud-init-output.log

if [ "$generateclientvpncerts" = "true" ]; then
  echo "generateclientvpncerts" >> /var/log/cloud-init-output.log
  sudo openssl genrsa -out ca.key 2048
  touch careq.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nCN = vpnrootca\n[req_ext]\nkeyUsage = keyCertSign, cRLSign\nbasicConstraints = CA:TRUE\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = vpnrootca' > careq.conf
  sudo openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -config careq.conf -out ca.crt
  cacert=$(sudo cat ca.crt)
  echo "creating cert for vpn" >> /var/log/cloud-init-output.log
  cat careq.conf >> /var/log/cloud-init-output.log
  echo "put parameter /clientvpncerts/cacert " $cacert >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/clientvpncerts/cacert" --value "$cacert" --type String --overwrite

  sudo openssl genrsa -out server.key 2048
  touch serverreq.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nCN = vpnserver\n[req_ext]\nkeyUsage = digitalSignature, keyEncipherment\nbasicConstraints = CA:FALSE\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = vpnserver' > serverreq.conf
  sudo openssl req -new -key server.key -sha256 -config serverreq.conf -out server.csr
  sudo openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1825 -sha256 -extensions req_ext -extfile serverreq.conf
  serverarn=$(aws acm import-certificate --region "$region" --certificate fileb://server.crt --private-key fileb://server.key --certificate-chain fileb://ca.crt | python3 -c "import sys, json; print(json.load(sys.stdin)['CertificateArn'])")
  echo "serverreq.conf" >> /var/log/cloud-init-output.log
  cat serverreq.conf >> /var/log/cloud-init-output.log
  echo "serverarn parameter put" $serverarn >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/clientvpncerts/serverarn" --value "$serverarn" --type String --overwrite
  
  sudo openssl genrsa -out client.key 2048
  touch clientreq.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nCN = vpnclient\n[req_ext]\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\nextendedKeyUsage = clientAuth\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = vpnclient' > clientreq.conf
  sudo openssl req -new -key client.key -sha256 -config clientreq.conf -out client.csr
  sudo openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 1825 -sha256 -extensions req_ext -extfile clientreq.conf
  clientarn=$(aws acm import-certificate --region "$region" --certificate fileb://client.crt --private-key fileb://client.key --certificate-chain fileb://ca.crt | python3 -c "import sys, json; print(json.load(sys.stdin)['CertificateArn'])")
  echo "client arn" $clientarn >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/clientvpncerts/clientarn" --value "$clientarn" --type String --overwrite
  clientkey=$(sudo cat client.key)
  echo "clientkey " $clientkey >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/clientvpncerts/clientkey" --value "$clientkey" --type String --overwrite
  clientcert=$(sudo cat client.crt)
  echo "clientcert " $clientcert >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/clientvpncerts/clientcert" --value "$clientcert" --type String --overwrite
fi

echo "installing ignition" >> /var/log/cloud-init-output.log

echo "Download Ignition Installer. (Needs to get latest version) (Rename installer to generic name)" >> /var/log/cloud-init-output.log

if [ -f ./ignition-installer.run ]; then
    echo 'Found ignition-installer in the folder, proceeding using it'
else
     echo 'Ignition-installer not found in the folder, proceeding downloading it'
     wget -q --referer="https://inductiveautomation.com/downloads/" https://inductiveautomation.com/downloads/latest-linux -O ignition-installer.run
fi

echo "Make Ignition Installer executable. (Take version out of name)" >> /var/log/cloud-init-output.log
sudo chmod +x ignition-installer.run

echo "Run Ignition Installer silently." >> /var/log/cloud-init-output.log
sudo ./ignition-installer.run -- "unattended=none" "user=root"

# Shutdown Ignition
sudo /usr/local/bin/ignition/./ignition.sh stop

echo "Copy over config.idb (Need to get this from fileserver)" >> /var/log/cloud-init-output.log
wget -q -O /usr/local/bin/ignition/data/db/config.idb "http://files.inductiveautomation.com/aws-quick-starts/config_v2.idb"

# Keep track of config.idb location
dblocation="/usr/local/bin/ignition/data/db/config.idb"

register_password "$dblocation" "$gwusername" "$gwpassword" 
echo $dblocation " " $gwusername " " $gwpassword  >> /var/log/cloud-init-output.log

# Set Ignition to run on 80/443
sudo sed -i  "s@<entry key=\"gateway.port\">.*/@<entry key=\"gateway.port\">80</entry>@g" /usr/local/bin/ignition/data/gateway.xml
sudo sed -i  "s@<entry key=\"gateway.sslport\">.*/@<entry key=\"gateway.sslport\">443</entry>@g" /usr/local/bin/ignition/data/gateway.xml
sudo sed -i  "s@<entry key=\"gateway.forceSecureRedirect\">.*/@<entry key=\"gateway.forceSecureRedirect\">true</entry>@g" /usr/local/bin/ignition/data/gateway.xml

# Get the memory size of system, calculate initmem to be 1/3 of memory and maxMem to be 2/3 of the memory, and update ignition.conf file
minMem=$(awk '/MemTotal/ {print int(($2/1024)/1000)*1000/3}' /proc/meminfo)
maxMem=$(awk '/MemTotal/ {print int(($2/1024)/1000)*1000/1.5}' /proc/meminfo)
sudo sed -i "s/wrapper.java.initmemory=.*/\wrapper.java.initmemory=$minMem/g" /usr/local/bin/ignition/data/ignition.conf
sudo sed -i "s/wrapper.java.maxmemory=.*/\wrapper.java.maxmemory=$maxMem/g" /usr/local/bin/ignition/data/ignition.conf

# Change Gateway name
if [ -z "$gwname" ]; then
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SYSPROPS SET SYSTEMNAME="Ignition Gateway" WHERE ID=0'
else
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SYSPROPS SET SYSTEMNAME='"'$gwname'"' WHERE ID=0'
fi

# Create commissioning.json file in data directory.
#sudo touch /usr/local/bin/ignition/data/commissioning.json
printf '{"isCommissioned":"COMMISSIONED",\n "connections.useSsl":"false",\n "eulaSetup.accepted": "true",\n "eulaSetup.eula": "JMAIXBhen9IvmZSF03ynrKPbH7dbgArFcjMDfIHSgDk="\n}' > /usr/local/bin/ignition/data/commissioning.json

# Create SSL Cert.
sudo touch req.conf

echo "Create SSL Cert" >> /var/log/cloud-init-output.log

if [ "$publicstatuscode" = "200" ]; then
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = WebServer\nCN = %s\n[req_ext]\nkeyUsage = critical, digitalSignature, keyAgreement\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nIP.2 = %s\nDNS.1 = %s\nDNS.2 = %s' $localhostname $localip $publicip $localhostname $publichostname > req.conf
  echo "==CERT-CONFIG-FILE-START==" >> /var/log/cloud-init-output.log
  cat req.conf >> /var/log/cloud-init-output.log
  echo "==CERT-CONFIG-FILE-END==" >> /var/log/cloud-init-output.log
else
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = WebServer\nCN = %s\n[req_ext]\nkeyUsage = critical, digitalSignature, keyAgreement\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nDNS.1 = %s' $localhostname $localip $localhostname > req.conf
  echo "==CERT-CONFIG-FILE-START==" >> /var/log/cloud-init-output.log
  cat req.conf >> /var/log/cloud-init-output.log
  echo "==CERT-CONFIG-FILE-END==" >> /var/log/cloud-init-output.log
fi

sudo openssl req -x509 -passout pass:ignition -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -config req.conf
sudo openssl pkcs12 -passin pass:ignition -export -out ssl.pfx -inkey key.pem -in cert.pem -passout pass:ignition -name ignition
sudo cp ssl.pfx /usr/local/bin/ignition/webserver/ssl.pfx
sudo rm cert.pem ssl.pfx req.conf key.pem

if [[ -z "$gancertingwname" ]]; then
  sudo touch req.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = GatewayNetwork\nCN = %s:8060\n[req_ext]\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nDNS.1 = %s\nURI.1 = %s/metro' $localhostname $localip $localhostname $localhostname > req.conf
  sudo openssl req -x509 -passout pass:metro -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -config req.conf
  sudo openssl pkcs12 -passin pass:metro -export -out metro-keystore -inkey key.pem -in cert.pem -passout pass:metro -name metro-key
  sudo cp metro-keystore /usr/local/bin/ignition/webserver/metro-keystore
  sudo rm cert.pem metro-keystore req.conf key.pem
else
  echo "gancertingwname get-parameter /$gancertingwname/gwuuid" >> /var/log/cloud-init-output.log
  gancertinuuid=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwuuid" --query 'Parameter.Value' --output text)
  gancertincert=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwcert" --query 'Parameter.Value' --output text)
  gancertinkey=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwkey" --query 'Parameter.Value' --output text)
  sudo touch /usr/local/bin/ignition/data/.uuid
  sudo echo "$gancertinuuid" | tr -d "\n\r" >> /usr/local/bin/ignition/data/.uuid
  sudo echo "$gancertincert" > cert.pem
  sudo echo "$gancertinkey" > key.pem
  sudo openssl pkcs12 -passin pass:metro -export -out metro-keystore -inkey key.pem -in cert.pem -passout pass:metro -name metro-key
  sudo cp metro-keystore /usr/local/bin/ignition/webserver/metro-keystore
  sudo rm cert.pem metro-keystore key.pem
fi

if [[ ! -z "$ganincominggwname1" && ! -z "$ganincominghost1" && ! -z "$ganincomingip1" ]]; then
  echo "ganincominggwname1 ganincominghost1 ganincomingip1" >> /var/log/cloud-init-output.log
  sudo touch req.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = GatewayNetwork\nCN = %s:8060\n[req_ext]\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nDNS.1 = %s\nURI.1 = %s/metro' $ganincominghost1 $ganincomingip1 $ganincominghost1 $ganincominghost1 > req.conf
  sudo openssl req -x509 -passout pass:metro -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -config req.conf
  ganincominguuid1=$(cat /proc/sys/kernel/random/uuid)
  ganincomingcert1=$(sudo cat cert.pem)
  ganincomingkey1=$(sudo cat key.pem)
  echo "SSM put parameters in overwrite: " $ganincominguuid1 " " $ganincomingcert1 " " $ganincomingkey1 >> /var/log/cloud-init-output.log

  echo "put parameter /$ganincominggwname1/gwuuid" >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname1/gwuuid" --value "$ganincominguuid1" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname1/gwcert" --value "$ganincomingcert1" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname1/gwkey" --value "$ganincomingkey1" --type String --overwrite
  sudo rm cert.pem req.conf key.pem
fi

if [[ ! -z "$ganincominggwname2" && ! -z "$ganincominghost2" && ! -z "$ganincomingip2" ]]; then
  sudo touch req.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = GatewayNetwork\nCN = %s:8060\n[req_ext]\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nDNS.1 = %s\nURI.1 = %s/metro' $ganincominghost2 $ganincomingip2 $ganincominghost2 $ganincominghost2 > req.conf
  sudo openssl req -x509 -passout pass:metro -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -config req.conf
  ganincominguuid2=$(cat /proc/sys/kernel/random/uuid)
  ganincomingcert2=$(sudo cat cert.pem)
  ganincomingkey2=$(sudo cat key.pem)
  echo "SSM put parameters in overwrite 2:" $ganincominguuid2 " " $ganincomingcert2 " " $ganincomingkey2  >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname2/gwuuid" --value "$ganincominguuid2" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname2/gwcert" --value "$ganincomingcert2" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname2/gwkey" --value "$ganincomingkey2" --type String --overwrite
  sudo rm cert.pem req.conf key.pem
fi

if [[ ! -z "$ganincominggwname3" && ! -z "$ganincominghost3" && ! -z "$ganincomingip3" ]]; then
  sudo touch req.conf
  sudo printf '[req]\ndistinguished_name = req_distinguished_name\nx509_extensions = req_ext\nprompt = no\n[req_distinguished_name]\nC = US\nST = CA\nL = Folsom\nO = Inductive Automation\nOU = GatewayNetwork\nCN = %s:8060\n[req_ext]\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyCertSign\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = %s\nDNS.1 = %s\nURI.1 = %s/metro' $ganincominghost3 $ganincomingip3 $ganincominghost3 $ganincominghost3 > req.conf
  sudo openssl req -x509 -passout pass:metro -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -config req.conf
  ganincominguuid3=$(cat /proc/sys/kernel/random/uuid)
  ganincomingcert3=$(sudo cat cert.pem)
  ganincomingkey3=$(sudo cat key.pem)
  echo "SSM put parameters in overwrite 3:" $ganincominguuid3 " " $ganincomingcert3 " " $ganincomingkey3  >> /var/log/cloud-init-output.log
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname3/gwuuid" --value "$ganincominguuid3" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname3/gwcert" --value "$ganincomingcert3" --type String --overwrite
  aws ssm put-parameter --region "$region" --name "/$ganincominggwname3/gwkey" --value "$ganincomingkey3" --type String --overwrite
  sudo rm cert.pem req.conf key.pem
fi

if [ "$redundancyrole" = "master"  ] || [ "$redundancyrole" = "independent"  ] || [ -z "$redundancyrole" ]; then
  if [[ ! -z "$dbip" ]]; then
    if [[ -z "$dbport" ]]; then
      dbport=5432
    fi
	
	passwordE=$(echo -n "$dbpassword" | openssl enc -e -des-ede3 -K c1ab7f797ad60eeafbc77ac76832c42c86152a9476325efe | hexdump -ve '1/1 "%.2x"')
		
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO DATASOURCES (DATASOURCES_ID, NAME, DESCRIPTION, DRIVERID, TRANSLATORID, INCLUDESCHEMAINTABLENAME, CONNECTURL, USERNAME, PASSWORD, PASSWORDE, CONNECTIONPROPS, ENABLED, CONNECTIONRESETPARAMS, DEFAULTTRANSACTIONLEVEL, POOLINITSIZE, POOLMAXACTIVE, POOLMAXIDLE, POOLMINIDLE, POOLMAXWAIT, VALIDATIONQUERY, TESTONBORROW, TESTONRETURN, TESTWHILEIDLE, EVICTIONRATE, EVICTIONTESTS, EVICTIONTIME, FAILOVERPROFILEID, FAILOVERMODE, SLOWQUERYLOGTHRESHOLD, VALIDATIONSLEEPTIME) VALUES (1, "Aurora_PostgreSQL", null, 3, 3, 0, "jdbc:postgresql://'$dbip':'$dbport'/'$dbschema'", "'$dbusername'", null, "'$passwordE'", null, 1, "", "DEFAULT", 0, 8, 8, 0, 5000, "SELECT 1", 1, 0, 0, -1, 3, 1800000, null, "STANDARD", 60000, 10000)'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name="DATASOURCES_SEQ"'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO STOREANDFORWARDSYSSETTINGS VALUES(1,"Aurora_PostgreSQL",250,1,25000,25,5000,0,25,1000,0,NULL,0);'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO TAGHISTORIANPROVIDERSETTINGS VALUES(1,1,1,"MONTH",0,60,0,1,"YEAR",1,2);'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO TAGHISTORYPROVIDEREP VALUES(1,"Aurora_PostgreSQL",1,"datasource","");'
	
    # Add audit log.
    sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO AUDITPROFILES (AUDITPROFILES_ID, NAME, TYPE, DESCRIPTION, RETENTION) VALUES (1, "Audit_Log", "DATASOURCE", null, 90)'
    sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO AUDITPROFILEPROPERTIES_DATASOURCE (PROFILEID, DATASOURCEID, AUTOCREATE, PRUNEENABLED, TABLENAME, KEYCOLUMN, TIMESTAMPCOLUMN, ACTORCOLUMN, ACTORHOSTCOLUMN, ACTIONCOLUMN, ACTIONTARGETCOLUMN, ACTIONVALUECOLUMN, STATUSCODECOLUMN, ORIGINATINGSYSTEMCOLUMN, ORIGINATINGCONTEXTCOLUMN) VALUES (1, 1, 1, 0, "AUDIT_EVENTS", "AUDIT_EVENTS_ID", "EVENT_TIMESTAMP", "ACTOR", "ACTOR_HOST", "ACTION", "ACTION_TARGET", "ACTION_VALUE", "STATUS_CODE", "ORIGINATING_SYSTEM", "ORIGINATING_CONTEXT")'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name="AUDITPROFILES_SEQ"'
	
    # Add alarm journal.
    sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO ALARMJOURNALS (ALARMJOURNALS_ID, NAME, TYPE, ENABLED, DESCRIPTION, QUERYONLY) VALUES (1, "Alarm_Journal", "DATASOURCE", "1", null, 0)'
    sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO DATABASEJOURNALSETTINGS (PROFILEID, DATASOURCEID, MINPRIORITY, STORE_SHELVEDEVENTS, STORE_FROMENABLEDCHANGE, EVENTDATA_STATCONF, EVENTDATA_DYNCONF, EVENTDATA_STATASSCDATA, EVENTDATA_DYNASSCDATA, USESTOREANDFORWARD, TABLENAME, DATATABLENAME, FILTER_SOURCE, FILTER_DISPLAYPATH, FILTER_DISPLAYPATHORSOURCE, PRUNINGENABLED, PRUNEAGE, PRUNEAGEUNITS) VALUES (1, 1, "Low", 0, 0, 0, 1, 1, 1, 1, "alarm_events", "alarm_event_data", null, null, null, 0, 90, "DAY")'
    sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name="ALARMJOURNALS_SEQ"'
  fi
fi

ganseq=1
# Create Redundancy.
if [[ ! -z "$redundancyrole" ]]; then
  sudo touch /usr/local/bin/ignition/data/redundancy.xml

  # Set up redudancy on Master GW.
  if [[ "$redundancyrole" = "master" ]]; then
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n<properties>\n<comment>Redundancy Settings</comment>\n<entry key="redundancy.noderole">Master</entry>\n<entry key="redundancy.gan.pingTimeout">300</entry>\n<entry key="redundancy.gan.pingMaxMissed">10</entry>\n<entry key="redundancy.activehistorylevel">Full</entry>\n<entry key="redundancy.standbyactivitylevel">Cold</entry>\n<entry key="redundancy.gan.pingRate">1000</entry>\n<entry key="redundancy.bindinterface"></entry>\n<entry key="redundancy.runtimeupdatequeuemax">200</entry>\n<entry key="redundancy.gan.enableSsl">true</entry>\n<entry key="redundancy.backupreconnectperiod">10000</entry>\n<entry key="redundancy.joinwaittime">30000</entry>\n<entry key="redundancy.gan.websocketTimeout">10000</entry>\n<entry key="redundancy.systemstaterevision">4</entry>\n<entry key="redundancy.maxdisk_mb">100</entry>\n<entry key="redundancy.systemstateuid"></entry>\n<entry key="redundancy.masterrecoverymode">Automatic</entry>\n<entry key="redundancy.gan.httpConnectTimeout">10000</entry>\n<entry key="redundancy.gan.httpReadTimeout">60000</entry>\n<entry key="redundancy.gan.host"></entry>\n<entry key="redundancy.backupfailovertimeout">10000</entry>\n<entry key="redundancy.gan.port">8060</entry>\n<entry key="redundancy.autodetectlocalinterface">true</entry>\n</properties>' > /usr/local/bin/ignition/data/redundancy.xml
  
  # Set up redundancy for Backup GW.
  elif [[ "$redundancyrole" = "backup" ]]; then
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n<properties>\n<comment>Redundancy Settings</comment>\n<entry key="redundancy.noderole">Backup</entry>\n<entry key="redundancy.gan.pingTimeout">300</entry>\n<entry key="redundancy.gan.pingMaxMissed">10</entry>\n<entry key="redundancy.activehistorylevel">Full</entry>\n<entry key="redundancy.standbyactivitylevel">Cold</entry>\n<entry key="redundancy.gan.pingRate">1000</entry>\n<entry key="redundancy.bindinterface"></entry>\n<entry key="redundancy.runtimeupdatequeuemax">200</entry>\n<entry key="redundancy.gan.enableSsl">true</entry>\n<entry key="redundancy.backupreconnectperiod">10000</entry>\n<entry key="redundancy.joinwaittime">30000</entry>\n<entry key="redundancy.gan.websocketTimeout">10000</entry>\n<entry key="redundancy.systemstaterevision">0</entry>\n<entry key="redundancy.maxdisk_mb">100</entry>\n<entry key="redundancy.systemstateuid">5a94a0e6-10b2-42f6-a2fb-064c286bd29c</entry>\n<entry key="redundancy.masterrecoverymode">Automatic</entry>\n<entry key="redundancy.gan.httpConnectTimeout">10000</entry>\n<entry key="redundancy.gan.httpReadTimeout">60000</entry>\n<entry key="redundancy.gan.host">%s</entry>\n<entry key="redundancy.backupfailovertimeout">10000</entry>\n<entry key="redundancy.gan.port">8060</entry>\n<entry key="redundancy.autodetectlocalinterface">true</entry>\n</properties>' $masterip > /usr/local/bin/ignition/data/redundancy.xml
  fi
fi

# Create Gateway Network outgoing connection (if available).
if [[ ! -z "$ganoutgoingip" ]]; then
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO WSCONNECTIONSETTINGS (WSCONNECTIONSETTINGS_ID, HOST, PORT, ENABLED, SSL, PINGRATE, PINGTIMEOUT, PINGMAXMISSED, WEBSOCKETTIMEOUT, HTTPCONNECTTIMEOUT, HTTPREADTIMEOUT) VALUES ("'$ganseq'","'$ganoutgoingip'",8060,1,1,1000,300,30,10000,10000,60000)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "WSCONNECTIONSETTINGS_SEQ"'
  ((ganseq++))
  
  if [[ ! -z "$ganoutgoinggwname" ]]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
	
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'DELETE FROM INTERNALTAGPROVIDER WHERE PROFILEID = 0'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'DELETE FROM TAGPROVIDERSETTINGS WHERE TAGPROVIDERSETTINGS_ID = 0'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO TAGPROVIDERSETTINGS (TAGPROVIDERSETTINGS_ID, NAME, PROVIDERID, DESCRIPTION, ENABLED, TYPEID, ALLOWBACKFILL) VALUES (4, "default", "'$UUID'", null, 1, "gantagprovider", 0)'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO GANTAGPROVIDERSETTINGS (PROFILEID, SERVERNAME, PROVIDERNAME, HISTORYMODE, HISTORYDATASOURCEID, HISTORYDRIVERNAME, HISTORYPROVIDERNAME, ALARMSTATUSENABLED, ALARMMODE) VALUES (4, "'$ganoutgoinggwname'", "default", "Database", 1, "'$ganoutgoinggwname'", "default", 1, "Subscribed")'
	sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "TAGPROVIDERSETTINGS_SEQ"'
  fi
fi

# Approve Gateway Network incoming connection (if needed)
if [[ ! -z "$ganincominggwname1" ]]; then
  echo "ganincominggwname1 get parameter /$ganincominggwname1/gwuuid" >> /var/log/cloud-init-output.log
  ganincominguuid1=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname1/gwuuid" --query 'Parameter.Value' --output text)
  ganincomingcert1=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname1/gwcert" --query 'Parameter.Value' --output text)
  sudo echo "$ganincomingcert1" > gwcert.pem
  gwcertprint=$(sudo openssl x509 -noout -fingerprint -sha256 -inform pem -in gwcert.pem | sed 's/://g' | sed 's/SHA256 Fingerprint=//g' | cut -c1-7 | tr '[:upper:]' '[:lower:]')
  gwcertcn=$(sudo openssl x509 -noout -subject -in gwcert.pem | sed -n '/^subject/s/^.*CN=//p' | sed 's/:/%3A/g')
  gwcertpath=$(sudo printf '/usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs/%s [%s] x1.crt.pem' $gwcertprint $gwcertcn)
  sudo mkdir -p /usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs
  sudo mv gwcert.pem "$gwcertpath"
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO WSINCOMINGCONNECTION (WSINCOMINGCONNECTION_ID, CONNECTIONID, SECURITYSTATUS) VALUES ("'$ganseq'", lower("'$ganincominggwname1'-backup|'$ganincominguuid1'"), "Approved")'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "WSINCOMINGCONNECTION_SEQ"'
  ((ganseq++))
fi

# Approve Gateway Network incoming connection (if needed)
if [[ ! -z "$ganincominggwname2" ]]; then
  echo "ganincominggwname2 get parameter /$ganincominggwname2/gwuuid" >> /var/log/cloud-init-output.log
  ganincominguuid2=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname2/gwuuid" --query 'Parameter.Value' --output text)
  ganincomingcert2=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname2/gwcert" --query 'Parameter.Value' --output text)
  sudo echo "$ganincomingcert2" > gwcert.pem
  gwcertprint=$(sudo openssl x509 -noout -fingerprint -sha256 -inform pem -in gwcert.pem | sed 's/://g' | sed 's/SHA256 Fingerprint=//g' | cut -c1-7 | tr '[:upper:]' '[:lower:]')
  gwcertcn=$(sudo openssl x509 -noout -subject -in gwcert.pem | sed -n '/^subject/s/^.*CN=//p' | sed 's/:/%3A/g')
  gwcertpath=$(sudo printf '/usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs/%s [%s] x1.crt.pem' $gwcertprint $gwcertcn)
  sudo mkdir -p /usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs
  sudo mv gwcert.pem "$gwcertpath"
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO WSINCOMINGCONNECTION (WSINCOMINGCONNECTION_ID, CONNECTIONID, SECURITYSTATUS) VALUES ("'$ganseq'", lower("'$ganincominggwname2'|'$ganincominguuid2'"), "Approved")'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "WSINCOMINGCONNECTION_SEQ"'
  ((ganseq++))
fi

# Approve Gateway Network incoming connection (if needed)
if [[ ! -z "$ganincominggwname3" ]]; then
  echo "ganincominggwname3 get parameter /$ganincominggwname3/gwuuid" >> /var/log/cloud-init-output.log
  ganincominguuid3=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname3/gwuuid" --query 'Parameter.Value' --output text)
  ganincomingcert3=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname3/gwcert" --query 'Parameter.Value' --output text)
  sudo echo "$ganincomingcert3" > gwcert.pem
  gwcertprint=$(sudo openssl x509 -noout -fingerprint -sha256 -inform pem -in gwcert.pem | sed 's/://g' | sed 's/SHA256 Fingerprint=//g' | cut -c1-7 | tr '[:upper:]' '[:lower:]')
  gwcertcn=$(sudo openssl x509 -noout -subject -in gwcert.pem | sed -n '/^subject/s/^.*CN=//p' | sed 's/:/%3A/g')
  gwcertpath=$(sudo printf '/usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs/%s [%s] x1.crt.pem' $gwcertprint $gwcertcn)
  sudo mkdir -p /usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs
  sudo mv gwcert.pem "$gwcertpath"
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO WSINCOMINGCONNECTION (WSINCOMINGCONNECTION_ID, CONNECTIONID, SECURITYSTATUS) VALUES ("'$ganseq'", lower("'$ganincominggwname3'|'$ganincominguuid3'"), "Approved")'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "WSINCOMINGCONNECTION_SEQ"'
  ((ganseq++))
fi

# Create Gateway Network incoming security policy (if needed).
if [[ ! -z "$gansecuritygwnames" ]]; then
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECURITYZONES (SECURITYZONES_ID, NAME, DESC, IP_ADDRESS, HOST_NAME, GATEWAY_NAME, IS_SECURE, DIRECT_CONNECTION, SCOPE_CLIENT, SCOPE_DESIGNER, SCOPE_GATEWAY) VALUES (1, "Frontend", null, null, null, "'$gansecuritygwnames'", 0, 0, 1, 1, 1)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "SECURITYZONES_SEQ"'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "TagProvider", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "TagProvider", "impersonationRole", null, 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "TagHistoryProvider", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "AuditProfileProvider", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "alm-query", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "alarm_notification_svc", "alm-allowed-pipelines", null, 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "alarm_notification_svc", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (0, "AlarmJournalProvider", "accessLevel", "Deny", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "TagProvider", "defaultTagAccess", "ReadWrite", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "TagProvider", "trustRemoteRoles", "true", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "TagProvider", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "TagProvider", "impersonationRole", null, 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "TagHistoryProvider", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "AuditProfileProvider", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "alm-query", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "alarm_notification_svc", "alm-allowed-pipelines", null, 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "alarm_notification_svc", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYPOLICY (ZONEID, ENTITYID, PROPNAME, VALUE, NONUSECOUNT) VALUES (1, "AlarmJournalProvider", "accessLevel", "Allow", 0)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYZONEPOLICY (ZONEID, PRIORITY) VALUES (0, 1)'
  sudo sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO SECUREDENTITYZONEPOLICY (ZONEID, PRIORITY) VALUES (1, 2)'
fi

echo "End" >> /var/log/cloud-init-output.log

# Remove installer
sudo rm ignition-installer.run

# Start Ignition
sudo /usr/local/bin/ignition/./ignition.sh start