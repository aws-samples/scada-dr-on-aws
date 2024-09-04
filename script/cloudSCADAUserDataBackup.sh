#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
sudo yum install jq -y
aws ssm put-parameter --region $1 --name 'IgnitionCloudBackupHostname' --value $(hostname) --type String --overwrite
aws ssm put-parameter --region $1 --name 'IgnitionCloudBackupIP' --value $(hostname -I) --type String --overwrite
echo 'Calling the Ignitition creation_v2 script'
onCloudDBPasswd=$(aws secretsmanager get-secret-value --region $1 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.password')
sudo chmod +x ./creation_v2.sh
counter=0
masterHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionMasterHostname' --query 'Parameter.Value' --output text)
while [ "null" = "$masterHostname" ] && [ $counter -lt 1000 ]; do masterHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionMasterHostname' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
masterIP=$(aws ssm get-parameter --region $1 --name 'IgnitionMasterIP' --query 'Parameter.Value' --output text)
while [ "null" = "$masterIP" ] && [ $counter -lt 1000 ]; do masterIP=$(aws ssm get-parameter --region $1 --name 'IgnitionMasterIP' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
gancertingwname=$(aws ssm get-parameter --region $1 --name '/Cloud_Backup_Ignition_Server/gwuuid' --query 'Parameter.Value' --output text)
while [ "null" = "$gancertingwname" ] && [ $counter -lt 1000 ]; do gancertingwname=$(aws ssm get-parameter --region $1 --name '/Cloud_Backup_Ignition_Server/gwuuid' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
sudo ./creation_v2.sh --stackname $2 --cloudregion $1 --gwname Cloud_Backup_Ignition_Server --gwusername admin --gwpassword admin --redundancyrole backup  --masterip $masterHostname --dbip $3 --dbport $4 --dbschema temp --dbusername $5 --dbpassword $onCloudDBPasswd --gancertingwname Cloud_Backup_Ignition_Server 