#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
sudo yum install jq -y
aws ssm put-parameter --region $1 --name 'IgnitionOnPremBackupHostname' --value $(hostname) --type String --overwrite
aws ssm put-parameter --region $1 --name 'IgnitionOnPremBackupIP' --value $(hostname -I) --type String --overwrite
echo 'Calling the Ignitition creation_v2 script'
onpremDBPasswd=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.password')
counter=0
masterHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremHostname' --query 'Parameter.Value' --output text)
while [ "null" = "$masterHostname" ] && [ $counter -lt 1000 ]; do masterHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremHostname' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
masterIP=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremIP' --query 'Parameter.Value' --output text)
while [ "null" = "$masterIP" ] && [ $counter -lt 1000 ]; do masterIP=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremIP' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
gancertingwname=$(aws ssm get-parameter --region $1 --name '/OnPremise_Backup_Ignition_Server/gwuuid' --query 'Parameter.Value' --output text)
while [ "null" = "$gancertingwname" ] && [ $counter -lt 1000 ]; do gancertingwname=$(aws ssm get-parameter --region $1 --name '/OnPremise_Backup_Ignition_Server/gwuuid' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
sudo ./creation_v2.sh --stackname $3 --cloudregion $1 --gwname OnPremise_Backup_Ignition_Server --gwusername admin --gwpassword admin --redundancyrole backup --masterip $masterHostname --dbip $4 --dbport $5 --dbschema postgres --dbusername $6 --dbpassword $onCloudDBPasswd --gancertingwname OnPremise_Backup_Ignition_Server
sudo yum install cronie -y
sudo systemctl enable crond.service
sudo systemctl start crond.service
mkdir /backup
(crontab -l ; echo "* * * * * su root -c '/usr/local/bin/ignition/gwcmd --backup /backup/;aws s3 sync /backup $7/backup --region us-east-1 --endpoint-url https://bucket$8'") | crontab -
aws ssm put-parameter --region $1 --name 'FailoverFlag' --value 'false' --type String --overwrite