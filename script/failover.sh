#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
nodeType=$(cat /usr/local/bin/ignition/data/redundancy.xml | grep "redundancy.noderole")
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone -H "X-aws-ec2-metadata-token: $TOKEN" | sed 's/\(.*\)[a-z]/\1/')
stackname="CloudScadaDrOnAwsStack-"$region
bucket=$(aws ssm get-parameter --region $region --name 'SCADABackupsBucket' --query 'Parameter.Value' --output text)

if [[ "$nodeType" == *Backup* ]]; then
  echo '====== Backup starting script ======'> /var/log/cloud-failover-output.log
  echo 'Restoring the latest backup from s3' 
  lastBackupBackup=$(aws s3api list-objects-v2 --bucket $bucket --query 'sort_by(Contents, &LastModified)[-1].Key' --output=text --prefix backup)
  mkdir /backup
  mkdir /backup/backup
  aws s3 cp s3://$bucket/$lastBackupBackup /backup/backup/
  /usr/local/bin/ignition/gwcmd --restore /backup/$lastBackupBackup -y
  
  gancertingwname="OnPremise_Backup_Ignition_Server"
  gancertinuuid=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwuuid" --query 'Parameter.Value' --output text)
  gancertincert=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwcert" --query 'Parameter.Value' --output text)
  gancertinkey=$(aws ssm get-parameter --region "$region" --name "/$gancertingwname/gwkey" --query 'Parameter.Value' --output text)
  sudo touch /usr/local/bin/ignition/data/.uuid
  sudo echo "$gancertinuuid" | tr -d "\n\r" > /usr/local/bin/ignition/data/.uuid
  sudo echo "$gancertincert" > cert.pem
  sudo echo "$gancertinkey" > key.pem
  sudo openssl pkcs12 -passin pass:metro -export -out metro-keystore -inkey key.pem -in cert.pem -passout pass:metro -name metro-key
  sudo cp metro-keystore /usr/local/bin/ignition/webserver/metro-keystore
  sudo rm cert.pem metro-keystore key.pem

else
  echo '====== Primary starting script ======'> /var/log/cloud-failover-output.log
  echo 'Restoring the latest backup from the s3' 
  lastBackupPrimary=$(aws s3api list-objects-v2 --bucket $bucket --query 'sort_by(Contents, &LastModified)[-1].Key' --output=text --prefix primary)
  mkdir /backup
  mkdir /backup/primary
  aws s3 cp s3://$bucket/$lastBackupPrimary /backup/primary/
  /usr/local/bin/ignition/gwcmd --restore /backup/$lastBackupPrimary -y
  
  ganincominggwname1="Cloud_Backup_Ignition_Server"
  ganseq=11
  ganincominguuid1=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname1/gwuuid" --query 'Parameter.Value' --output text)
  ganincomingcert1=$(aws ssm get-parameter --region "$region" --name "/$ganincominggwname1/gwcert" --query 'Parameter.Value' --output text)
  echo "$ganincomingcert1" > gwcert.pem
  gwcertprint=$(sudo openssl x509 -noout -fingerprint -sha256 -inform pem -in gwcert.pem | sed 's/://g' | sed 's/SHA256 Fingerprint=//g' | cut -c1-7 | tr '[:upper:]' '[:lower:]')
  gwcertcn=$(sudo openssl x509 -noout -subject -in gwcert.pem | sed -n '/^subject/s/^.*CN=//p' | sed 's/:/%3A/g')
  gwcertpath=$(sudo printf '/usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs/%s [%s] x1.crt.pem' $gwcertprint $gwcertcn)
  mkdir -p /usr/local/bin/ignition/data/gateway-network/server/security/pki/trusted/certs
  mv gwcert.pem "$gwcertpath"
  sqlite3 /usr/local/bin/ignition/data/db/config.idb 'INSERT INTO WSINCOMINGCONNECTION (WSINCOMINGCONNECTION_ID, CONNECTIONID, SECURITYSTATUS) VALUES ("'$ganseq'", lower("'$ganincominggwname1'-backup|'$ganincominguuid1'"), "Approved")'
  sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE SEQUENCES SET val=val+1 WHERE name = "WSINCOMINGCONNECTION_SEQ"'
fi

# double restart is required to handle DB change
/usr/local/bin/ignition/gwcmd -r

cloudDBPasswd=$(aws secretsmanager get-secret-value --region $region --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.password')
cloudDBPort=$(aws secretsmanager get-secret-value --region $region --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.port')
cloudDBHost=$(aws secretsmanager get-secret-value --region $region --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.host')
cloudDBUser=$(aws secretsmanager get-secret-value --region $region --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.username')
passwordE=$(echo -n "$cloudDBPasswd" | openssl enc -e -des-ede3 -K c1ab7f797ad60eeafbc77ac76832c42c86152a9476325efe | hexdump -ve '1/1 "%.2x"')

sqlite3 /usr/local/bin/ignition/data/db/config.idb 'UPDATE DATASOURCES SET CONNECTURL = "jdbc:postgresql://'$cloudDBHost':'$cloudDBPort'/postgres", USERNAME = "'$cloudDBUser'", PASSWORDE = "'$passwordE'"'
echo "Updating the database conection" >> /var/log/cloud-failover-output.log
sqlite3 /usr/local/bin/ignition/data/db/config.idb "SELECT * FROM DATASOURCES" >> /var/log/cloud-failover-output.log

# Start Ignition
/usr/local/bin/ignition/gwcmd -r