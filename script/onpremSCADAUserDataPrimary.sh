#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
aws ssm put-parameter --region $1 --name 'IgnitionOnPremHostname' --value $(hostname) --type String --overwrite
aws ssm put-parameter --region $1 --name 'IgnitionOnPremIP' --value $(hostname -I) --type String --overwrite
sudo yum install jq -y
counter=0
backupHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremBackupHostname' --query 'Parameter.Value' --output text)
while [ "null" = "$backupHostname" ] && [ $counter -lt 1000 ]; do backupHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremBackupHostname' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
backupIP=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremBackupIP' --query 'Parameter.Value' --output text)
while [ "null" = "$backupIP" ] && [ $counter -lt 1000 ]; do backupIP=$(aws ssm get-parameter --region $1 --name 'IgnitionOnPremBackupIP' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
echo 'Calling the Ignitition creation_v2 script'
onpremDBPasswd=$(aws secretsmanager get-secret-value --region $2 --secret-id 'onPremDBCredentials' --output text --query 'SecretString' | jq -r '.password')
sudo ./creation_v2.sh --stackname $3 --cloudregion $1 --gwname OnPremise_Ignition_Server --gwusername admin --gwpassword admin --redundancyrole master --dbip $4 --dbport $5 --dbschema postgres --dbusername $6 --dbpassword $onpremDBPasswd --ganincominggwname1 OnPremise_Backup_Ignition_Server --ganincomingip1 $backupIP --ganincominghost1 $backupHostname
sudo yum install cronie -y
sudo systemctl enable crond.service
sudo systemctl start crond.service
counter=0;twstate=""
while [ "available" != "$twstate" ] && [ $counter -lt 10000 ]; do twstate=$(aws ec2 describe-transit-gateway-attachments --region $2 --query 'TransitGatewayAttachments[?ResourceType==`peering` && State!=`deleted`].State' --output text); echo 'Waiting for TGW Attachment to become active' >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
transitGatewayRouteTableId=$(aws ec2 describe-transit-gateway-route-tables --region $2 --query 'TransitGatewayRouteTables[0].TransitGatewayRouteTableId' --output text)
tgwattachid=$(aws ec2 describe-transit-gateway-attachments --region $2 --query 'TransitGatewayAttachments[?ResourceType==`peering` && State!=`deleted`].TransitGatewayAttachmentId' --output text)
aws ec2 create-transit-gateway-route --destination-cidr-block '10.2.0.0/20' --region $2 --transit-gateway-route-table-id $transitGatewayRouteTableId --transit-gateway-attachment-id $tgwattachid
sudo ./postgres_replication.sh onprem $2 $1

mkdir /backup
(crontab -l ; echo "* * * * * su root -c '/usr/local/bin/ignition/gwcmd --backup /backup/;aws s3 sync /backup $7/primary --region us-east-1 --endpoint-url https://bucket$8'") | crontab -
echo "" > /backupdb.sql

