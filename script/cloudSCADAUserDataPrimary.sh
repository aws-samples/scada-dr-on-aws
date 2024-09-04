#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
aws ssm put-parameter --region $1 --name 'IgnitionMasterHostname' --value $(hostname) --type String --overwrite
aws ssm put-parameter --region $1 --name 'IgnitionMasterIP' --value $(hostname -I) --type String --overwrite
sudo yum install jq -y
echo 'Calling the Ignitition creation_v2 script'
onCloudDBPasswd=$(aws secretsmanager get-secret-value --region $1 --secret-id 'onCloudDBCredentials' --output text --query 'SecretString' | jq -r '.password')
counter=0
backupHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionCloudBackupHostname' --query 'Parameter.Value' --output text)
while [ "null" = "$backupHostname" ] && [ $counter -lt 1000 ]; do backupHostname=$(aws ssm get-parameter --region $1 --name 'IgnitionCloudBackupHostname' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
counter=0
backupIP=$(aws ssm get-parameter --region $1 --name 'IgnitionCloudBackupIP' --query 'Parameter.Value' --output text)
while [ "null" = "$backupIP" ] && [ $counter -lt 1000 ]; do backupIP=$(aws ssm get-parameter --region $1 --name 'IgnitionCloudBackupIP' --query 'Parameter.Value' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
sudo ./creation_v2.sh --stackname $2 --cloudregion $1 --gwname Cloud_Primary_Ignition_Server --gwusername admin --gwpassword admin --redundancyrole master --dbip $3 --dbport $4 --dbschema temp --dbusername $5 --dbpassword $onCloudDBPasswd --ganincominggwname1 Cloud_Backup_Ignition_Server --ganincomingip1 $backupIP --ganincominghost1 $backupHostname >> /var/log/cloud-init-output.log
tgwattachid=$(aws ec2 describe-transit-gateway-attachments --region $1 --query 'TransitGatewayAttachments[?ResourceType==`peering` && (State==`pendingAcceptance` || State==`available`)].TransitGatewayAttachmentId' --output text)
counter=0
while [[ -z "$tgwattachid" ]] && [ $counter -lt 10000 ]; do tgwattachid=$(aws ec2 describe-transit-gateway-attachments --region $1 --query 'TransitGatewayAttachments[?ResourceType==`peering` &&  (State==`pendingAcceptance` || State==`available`)].TransitGatewayAttachmentId' --output text); echo "Waiting for the peering to work " $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
aws ec2 accept-transit-gateway-peering-attachment --transit-gateway-attachment-id $tgwattachid --region $1
counter=0;twstate=""
while [ "available" != "$twstate" ] && [ $counter -lt 10000 ]; do twstate=$(aws ec2 describe-transit-gateway-attachments --region $1 --query 'TransitGatewayAttachments[?ResourceType==`peering` && State!=`deleted`].State' --output text); echo $counter >> /var/log/cloud-init-output.log; sleep 1;((counter++)); done
transitGatewayRouteTableId=$(aws ec2 describe-transit-gateway-route-tables --region $1 --query 'TransitGatewayRouteTables[0].TransitGatewayRouteTableId' --output text)
aws ec2 create-transit-gateway-route --destination-cidr-block '10.1.0.0/20' --region $1 --transit-gateway-route-table-id $transitGatewayRouteTableId --transit-gateway-attachment-id $tgwattachid
aws ec2 create-transit-gateway-route --destination-cidr-block '10.3.0.0/20' --region $1 --transit-gateway-route-table-id $transitGatewayRouteTableId --transit-gateway-attachment-id $tgwattachid
sudo ./postgres_replication.sh cloud $6 $1