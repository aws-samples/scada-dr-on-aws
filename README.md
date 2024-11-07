# SCADA Disaster Recovery on AWS for Inductive Automation's Ignition

## Introduction
This sample code demonstrates how to install, configure and execute a disaster recovery on AWS for Ignition SCADA by [Inductive Automation](https://inductiveautomation.com/scada-software/).

This code is part of an AWS Workshop which [you can find here](https://catalog.us-east-1.prod.workshops.aws/workshops/7b8b2c07-b91b-4403-92cc-7d3d65fdb485/en-US). Workshops are hands-on events designed to teach or introduce practical skills, techniques, or concepts which you can use to solve business problems.

It is highly recommended to consult the workshop to understand the industry background and the architectural details of this project.
We also suggest to follow all the steps in the workshop to make sure to execute the configuration correctly and complete the disaster recovery.
In order to start using your own AWS account, you can start from [this section](https://catalog.us-east-1.prod.workshops.aws/workshops/7b8b2c07-b91b-4403-92cc-7d3d65fdb485/en-US/getting-started-aws) "Getting started with your own AWS account".

In this README we will dive deeper only on the explanation of the code, please refer to the workshop for the explanation of the Architecture.

## Architecture

Please navigate to [this page](https://catalog.us-east-1.prod.workshops.aws/workshops/7b8b2c07-b91b-4403-92cc-7d3d65fdb485/en-US/ignition-disaster-recovery-on-aws/architecture) for the detailed explanation

## Code structure
This code is leveraging [AWS Cloud Development Kit](https://aws.amazon.com/cdk/). AWS CDK is a tool which enables developers to create and configure AWS resources in the AWS Cloud. AWS CDK supports many different languages, in this project we are using Typescript.

### CDK typescript code
The main file is the [bin/scada-dr-on-aws.ts](bin/scada-dr-on-aws.ts) where the two different stacks are created. One stack is the cloud stack installed in N.Virginia and the other is the on-premise stack installed in Oregon. There is no strict requirements on the regions, so you can change them in this class using the respective variables.

The definition of the two cloud and on-premise stacks are located respectively in [lib/scada-dr-on-aws-oncloud-stack.ts](lib/scada-dr-on-aws-oncloud-stack.ts) and [lib/scada-dr-on-aws-onprem-stack.ts](lib/scada-dr-on-aws-onprem-stack.ts).

### Scripts

There are different scripts which are required to run the installation of this solution. All script are located in the script folder:
1. [Cloud Primary User Data](script/cloudSCADAUserDataPrimary.sh) This script runs a the start of the cloud SCADA Primary EC2 instance. It mainly runs the [Ignition Installation](script/creation_v2.sh) script after fetching some configuration. The installation script is the same for all servers with different parameters according to the node. The script is sourced from the Ignition SCADA on AWS solution [that you can find here](https://aws.amazon.com/solutions/partners/inductive-automation-ignition/). The script is also responsible to finalize the network configuration accepting the peering connection coming from the on-premise region. Finally it also runs the  [postgres replication](script/postgres_replication.sh) script.
2. [Cloud Backup User Data](script/cloudSCADAUserDataBackup.sh): This script runs at the start of the cloud SCADA Backup EC2 instance. It performs the same tasks happening in the Primary script with a different configuration since this is the backup node. It does not have any other network or database logic in it.
3. [On-Premise Primary User Data](script/onpremSCADAUserDataPimary.sh): This script runs at the start of the on-premise SCADA Primary EC2 instance. It performs the same tasks happening in the cloud with different parameters. Besides installing the Ignition SCADA the scripts also triggers the [postgres replication](script/postgres_replication.sh) script with different parameters compared to the cloud environment.
4. [On-Premise Backup User Data](script/onpremSCADAUserDataBackup.sh): This script runs at the start of the on-premise SCADA Backup EC2 instance. It performs the same tasks happening in the on-premise SCADA Primary script with a different configuration since this is the backup node. It does not have any other network or database logic in it.
5. [Ignition SCADA Installation script](script/creation_v2.sh): This script install and configure the Ignition SCADA according to the configuration and parameters reported in the [AWS Solution](https://aws.amazon.com/solutions/partners/inductive-automation-ignition/). The implementation of this script has been fine-tuned for the implementation of this specific case.
6. [Postgres replication script](script/postgres_replication.sh) This script is used by both primary nodes to configure the database replication. The databases are PostgreSQL servers running on top of [Amazon RDS](https://aws.amazon.com/it/rds/). This script is configuring both server to run logical replication using the PGActive tool. Note that this configuration has already been enabled during the installation on both RDS using a parameter group.
7. [Failover script](script/failover.sh) This script is installed on both cloud EC2s. It fetches the latest backup from the S3 bucket and performs the restore on the Ignition Server. This script is executed by System Manager on both nodes at the same time at recovery time.

### On premise stack

The main [lib/scada-dr-on-aws-onprem-stack.ts](lib/scada-dr-on-aws-onprem-stack.ts) typescript file creates all the on-premise region resources. The main resources created can be found in the reference architecture. To navigate the file you can start from the constructor where each method invocation is describing the specific actions the code is performing:
 1. `createOnPremiseVPC()`
   - Creates a VPC to simulate an on-premises environment for the Ignition SCADA Disaster Recovery solution. The VPC includes a public subnet and a private subnet with egress. VPC Flow Logs are enabled and sent to an S3 bucket for monitoring network traffic.

2. `createEdgeVPC()`
   - Creates a VPC to simulate an on-premises environment for edge devices in the Ignition SCADA Disaster Recovery solution. The VPC includes a public subnet and a private subnet with egress. VPC Flow Logs are enabled and sent to an S3 bucket for monitoring network traffic.

3. `createDBParameters()`
   - Creates a Parameter Group for the RDS (Relational Database Service) instance used in the Ignition SCADA Disaster Recovery solution. The Parameter Group is configured with specific settings, including the PostgreSQL version, enabling PG Active, and custom DNS resolution.

4. `createOnPremDB()`
   - Creates an Amazon RDS (Relational Database Service) instance to simulate an on-premises database for the Ignition SCADA Disaster Recovery solution. The RDS instance is configured with various settings, such as encryption, backup retention period, instance type, security group, and deployment in a private subnet with egress.

5. `createOnPremiseEC2()`
   - Creates two EC2 instances to simulate on-premises SCADA systems for the Ignition SCADA solution. The instances are configured with specific settings, including VPC, subnets, instance names, IAM roles, user data scripts, machine images, security groups, instance types, and encrypted EBS volumes.

6. `createOnEdgeEC2()`
   - Creates an EC2 instance to simulate an edge device for the Ignition SCADA solution. The instance is configured with specific settings, including VPC, subnets, instance name, IAM role, user data script, machine image, security group, instance type, and an encrypted EBS volume.

7. `createTransitGateway()`
   - Creates a Transit Gateway and attaches the on-premises and edge VPCs to it. The Transit Gateway is configured with specific settings, such as Amazon ASN, default route table association and propagation, DNS and multicast support, CIDR blocks, and VPN ECMP support.

8. `adjustRoutingTables()`
   - Adjusts the routing tables of the on-premises and edge VPCs to enable communication through the Transit Gateway. It adds routes to the on-premises private subnets to reach the cloud and edge VPC CIDR blocks via the Transit Gateway, and routes to the edge private subnets to reach the cloud and on-premises VPC CIDR blocks via the Transit Gateway. Additionally, it creates a Transit Gateway peering attachment to connect the on-premises and cloud Transit Gateways across regions.

CDK takes care of the ordering of the creation of the resources according to the configurations and references. The only explicit reference and dependency is the requirement for the EC2s to be created after the Transit Gateways.
Additionally, the code includes suppression rules for CDK Nag, a tool for checking for security and best practice violations in AWS CDK applications.

### Cloud stack

### Method Names and Descriptions
The main [lib/scada-dr-on-aws-oncloud-stack.ts](lib/scada-dr-on-aws-oncloud-stack.ts) typescript file creates all the cloud region resources. The main resources created can be found in the reference architecture. To navigate the file you can start from the constructor where each method invocation is describing the specific actions the code is performing:
1. `uploadScriptToS3()`
   - Creates an S3 bucket for logging and another bucket for storing scripts and binaries. Uploads the contents of the 'script' and 'binaries' directories to the scripts and binaries bucket.

2. `createDRBucket()`
   - Creates an S3 bucket for storing disaster recovery backups, named 'oncloud-dr-backups'.

3. `createOnCloudVPC()`
   - Creates a VPC in the cloud region for hosting the Ignition SCADA disaster recovery environment. Configures the VPC with public and private subnets, VPC Flow Logs, and creates VPC Endpoints for Amazon S3.

4. `createWindowsBastionHost()`
   - Creates a Windows EC2 instance to serve as a bastion host in the cloud environment.

5. `createDBParameters()`
   - Creates a Parameter Group for the RDS (Relational Database Service) instance used in the cloud environment, configured with specific settings like the PostgreSQL version and enabling PG Active.

6. `createOnCloudDB()`
   - Creates an Amazon RDS (Relational Database Service) instance in the cloud environment for disaster recovery, with configurations like encrypted storage, backup retention period, instance type, and deployment in private subnets.

7. `createOnCloudEC2s()`
   - Creates two EC2 instances in the cloud environment to serve as the primary and backup Ignition SCADA servers.

8. `createTransitGateway()`
   - Creates a Transit Gateway in the cloud environment and attaches the cloud VPC to it, with specific configurations like Amazon ASN, default route table association, and CIDR blocks.

9. `adjustRoutingTables()`
   - Adjusts the routing tables of the cloud VPC to enable communication through the Transit Gateway, adding routes to the on-premises and edge VPC CIDR blocks.

10. `defineSSMParams()`
    - Defines a set of AWS Systems Manager (SSM) Parameter Store parameters for various configurations related to the Ignition SCADA solution, such as Gateway certificates, hostnames, IP addresses, and backup bucket name.

## Important considerations
- This is not to be considered a production ready solution, this is meant to be used as a Proof of Concept and foundation over which you can build your own solution
- Some decisions around the security and compliance are based on the fact that this code is designed to be created and destroyed quickly.
- The S3 Buckets are not configured to be read-only and in compliance mode otherwise the deletion would not be possibile. In a real production environment that is something you want to evaluate doing.
- This code is developed simulating an on-premise environment, in a real scenario the connction with the cloud will not be performed using an AWS Transit Gateway but rather a direct connect or a Site to Site VPN
- Please make sure to follow the AWS Workshop for all the guidance on how to use this code and how to clean-up the environment after being used
