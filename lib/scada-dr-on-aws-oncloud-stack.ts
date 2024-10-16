/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import * as cdk from 'aws-cdk-lib';
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as rds from "aws-cdk-lib/aws-rds";
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { NagSuppressions } from 'cdk-nag'


import { readFileSync } from 'fs';
import { Construct } from 'constructs';

export class CloudScadaDrOnAwsStack extends cdk.Stack {

  //Artifacts
  public onCloudVPC: ec2.Vpc;
  public ec2Role: iam.Role;
  public onCloudEC2Primary: ec2.Instance;
  public onCloudEC2Backup: ec2.Instance;
  public onCloudEC2SG: ec2.SecurityGroup;
  public onCloudDBSG: ec2.SecurityGroup;
  public onCloudVPCSG: ec2.SecurityGroup;
  public onCloudBastionEC2SG: ec2.SecurityGroup;
  public cloudEFSSG: ec2.SecurityGroup;
  public transitGateway: ec2.CfnTransitGateway;
  public onCloudTGWAtt: ec2.CfnTransitGatewayAttachment;
  public rdsPMG: rds.IParameterGroup;
  public lambdaRole: iam.Role;
  public backupS3Bucket: s3.Bucket;
  public loggingBucket: s3.Bucket;
  public s3vpce: ec2.InterfaceVpcEndpoint;

  //Parameters
  public OnPremDB: rds.DatabaseInstance;
  public OnCloudDBCluster: rds.DatabaseInstance;
  public onPremDBCredentials: rds.Credentials;
  public onCloudDBCredentials: rds.Credentials;
  public scriptsS3Bucket : s3.Bucket;
  protected ec2Pass : string;
  protected onPremRegion : string;
  protected id: string;

  constructor(scope: Construct, id: string, onPremRegion: string, props?: cdk.StackProps) {
    super(scope, id, props);
    this.onPremRegion=onPremRegion;
    this.id=id;
    
    /**
     * Creates an S3 bucket for logging and another bucket for storing scripts and binaries.
     * The logging bucket is configured with the following settings:
     *   - Object ownership enforced
     *   - Removal policy set to DESTROY (should be RETAIN in production)
     *   - Auto-delete objects enabled (should be disabled in production)
     *   - SSL enforced
     *   - Public access blocked
     *   - Server-side encryption with S3-managed keys
     *   - Versioning enabled
     *   - Object lock disabled (should be enabled in production)
     *   - Server access logs stored in the same bucket with prefix 'logs'
     *
     * The scripts and binaries bucket is created with the name 'oncloud-scripts-and-binaries'.
     *
     * A BucketDeployment resource is created to upload the contents of the 'script' and 'binaries' directories
     * to the scripts and binaries bucket, with a prefix 'script'.
     *
     * Some Nag rules are suppressed for the BucketDeployment resource due to limitations in changing
     * the default configurations created by CDK.
     */
    this.uploadScriptToS3();

    /**
     * Creates an S3 bucket for storing disaster recovery backups.
     * The bucket is named 'oncloud-dr-backups'.
     */
    this.createDRBucket();

    /**
     * Creates a VPC in the cloud region for hosting the Ignition SCADA disaster recovery environment.
     * The VPC is configured with the following settings:
     *   - CIDR block: 10.2.0.0/20
     *   - Maximum of 3 availability zones
     *   - Public and private subnets with a CIDR mask of 24 bits
     *   - VPC Flow Logs enabled and sent to the logging bucket
     *
     * The method also creates the following resources:
     *   - A Gateway VPC Endpoint for Amazon S3
     *   - An Interface VPC Endpoint for Amazon S3, with private DNS enabled and a custom security group
     *   - An IAM policy statement attached to the Interface VPC Endpoint to allow access to the scripts and backups S3 buckets
     *
     * The created VPC instance is assigned to the 'this.onCloudVPC' property.
     */
    this.createOnCloudVPC();

    /**
     * Creates a Windows EC2 instance to serve as a bastion host in the cloud environment.
     * The bastion host is configured with the following settings:
     *   - Deployed in the 'this.onCloudVPC' VPC and public subnets obtained from 'this.getPublicSubnets(2)'
     *   - Instance name: 'oncloud_bastion_host'
     *   - IAM role obtained from 'this.getCloudEC2BastionRole()'
     *   - User data script for Windows
     *   - Key pair named 'admin-keypair-bastion-host' with RSA type
     *   - Machine image obtained from 'this.getWindowsAMI()'
     *   - Security group obtained from 'this.getCloudEC2BastionSG(this.onCloudVPC)'
     *   - Instance type: Burstable2, Large
     *   - 50 GB encrypted EBS volume
     */
    this.createWindowsBastionHost()

    /**
     * Creates a Parameter Group for the RDS (Relational Database Service) instance used in the cloud environment.
     * The Parameter Group is configured with the following settings:
     *   - Database engine: PostgreSQL version 16.1
     *   - Parameter 'rds.enable_pgactive' is set to '1'
     *   - Parameter 'rds.custom_dns_resolution' is set to '1'
     * The created Parameter Group instance is assigned to the 'this.rdsPMG' property.
     * The Parameter Group will be destroyed when the stack is deleted (RemovalPolicy.DESTROY).
     */
    this.createDBParameters();
    
    /**
     * Creates an Amazon RDS (Relational Database Service) instance in the cloud environment for disaster recovery.
     * The RDS instance is configured with the following settings:
     *   - Database engine: PostgreSQL version 16.1
     *   - Storage is encrypted
     *   - Backup retention period: 30 days
     *   - Instance type: Burstable3, Large
     *   - Database credentials are loaded from the 'onCloudDBCredentials' AWS Secrets Manager secret
     *   - Security group obtained from 'this.getCloudDBSG()'
     *   - Parameter group obtained from 'this.rdsPMG'
     *   - Port: 5433
     *   - Multi-AZ deployment enabled
     *   - Deployed in the 'this.onCloudVPC' VPC and private subnets with egress
     *
     * The created RDS instance is assigned to the 'this.OnCloudDBCluster' property.
     */
    this.createOnCloudDB();

    /**
     * Creates two EC2 instances in the cloud environment to serve as the primary and backup Ignition SCADA servers.
     *
     * Primary SCADA Server:
     *   - Instance name: 'scada_oncloud_primary'
     *   - Deployed in the 'this.onCloudVPC' VPC and subnets obtained from 'this.getPrimarySubnets(0)'
     *   - IAM role obtained from 'this.getEC2Role()'
     *   - User data script obtained from 'this.getCloudSCADAUserDataPrimary()'
     *   - Machine image obtained from 'this.getRHELAMI()'
     *   - Security group obtained from 'this.getCloudEC2SG(this.onCloudVPC)'
     *   - Instance type: Burstable2, Large
     *   - Detailed monitoring enabled
     *   - 50 GB encrypted EBS volume
     *
     * Backup SCADA Server:
     *   - Instance name: 'scada_oncloud_backup'
     *   - Deployed in the 'this.onCloudVPC' VPC and subnets obtained from 'this.getPrimarySubnets(1)'
     *   - IAM role obtained from 'this.getEC2Role()'
     *   - User data script obtained from 'this.getCloudSCADAUserDataBackup()'
     *   - Machine image obtained from 'this.getRHELAMI()'
     *   - Security group obtained from 'this.getCloudEC2SG(this.onCloudVPC)'
     *   - Instance type: Burstable2, Large
     *   - Detailed monitoring enabled
     *   - 50 GB encrypted EBS volume
     * The created instances are assigned to the 'this.onCloudEC2Primary' and 'this.onCloudEC2Backup' properties, respectively.
     */
    this.createOnCloudEC2s();

    /**
     * Creates a Transit Gateway in the cloud environment and attaches the cloud VPC to it.
     * The Transit Gateway is configured with the following settings:
     *   - Amazon ASN: 65000
     *   - Auto-accept shared attachments enabled
     *   - Default route table association and propagation enabled
     *   - DNS support enabled
     *   - Multicast support disabled
     *   - CIDR blocks: 10.1.0.0/20, 10.2.0.0/20, 10.3.0.0/20
     *   - VPN ECMP support enabled
     *
     * The cloud VPC ('this.onCloudVPC') is attached to the Transit Gateway.
     * The private subnets of the cloud VPC are associated with the Transit Gateway attachment.
     *
     * The created Transit Gateway instance is assigned to the 'this.transitGateway' property.
     */
    this.createTransitGateway();

    /**
     * Adjusts the routing tables of the cloud VPC to enable communication through the Transit Gateway.
     * The following routes are added:
     *   - Private subnets: Routes to the on-premises and edge VPC CIDR blocks via the Transit Gateway
     *   - Public subnets: Routes to the on-premises VPC CIDR block via the Transit Gateway
     * The routing table entries are made dependent on the Transit Gateway attachment to the cloud VPC.
     */
    this.adjustRoutingTables();

    /**
     * Defines a set of AWS Systems Manager (SSM) Parameter Store parameters for various configurations related to the Ignition SCADA solution.
     * The following parameters are created with an initial value of 'null' (except for '/FailoverFlag' and '/SCADABackupsBucket'):
     * All parameters are set to be deleted when the CloudFormation stack is deleted (RemovalPolicy.DESTROY).
     */
    this.defineSSMParams();

    /**
     * Creates an AWS Lambda function and an Amazon EventBridge rule to check the status of the Ignition SCADA servers.
     *
     * The Lambda function is configured with the following settings:
     *   - Runtime: Node.js 20.x
     *   - Handler: 'index.handler'
     *   - Code source: './lambda/check_ignition_status/src'
     *   - IAM role obtained from 'this.getLambdaRole()'
     *   - Deployed in the 'this.onCloudVPC' VPC
     *   - Timeout: 10 seconds
     *
     * An Amazon EventBridge rule is created to invoke the Lambda function every minute.
     */
    this.createFailoverFunction();

    /** 
     * This method is disabled since in this workshop it is required to use the buckets from the console and also for the CDK automation to create and delete them
     * In real scenarios this can be used but with caution since ANY interaction will need to be performed via the VPC Endpoint also the console will be not be used
     * 
     * Creates bucket policies for the backups and scripts S3 buckets to restrict access only through the S3 VPC Endpoint.
     *
     * The following policies are created and attached to the respective S3 buckets:
     *
     * 1. Deny access to the backups bucket ('this.backupS3Bucket') for requests not originating from the S3 VPC Endpoint ('this.s3vpce').
     *    This policy denies the 's3:PutObject' action for any principal, except when the request is made through the S3 VPC Endpoint.
     *
     * 2. Deny access to the scripts bucket ('this.scriptsS3Bucket') for requests not originating from the S3 VPC Endpoint ('this.s3vpce').
     *    This policy denies the 's3:PutObject' action for any principal, except when the request is made through the S3 VPC Endpoint.
     *
     * These policies ensure that the backups and scripts buckets can only be accessed through the S3 VPC Endpoint,
     * providing an additional layer of security and network isolation.
     */
    //this.createBucketPolicies();
  }

  private createBucketPolicies(){

    const denyAccessToNotVpceBackup = new iam.PolicyStatement({
      actions: ["s3:PutObject"],
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      resources: [          
        "arn:aws:s3:::"+this.backupS3Bucket.bucketName+",",
        "arn:aws:s3:::"+this.backupS3Bucket.bucketName+"/*"],
      conditions: {
        StringNotEquals: {
          "aws:sourceVpce": `${this.s3vpce.vpcEndpointId}`
        }
      }
    });

    const denyAccessToNotVpceScripts = new iam.PolicyStatement({
      actions: ["s3:PutObject"],
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      resources: [
        "arn:aws:s3:::"+this.scriptsS3Bucket.bucketName+",",
        "arn:aws:s3:::"+this.scriptsS3Bucket.bucketName+"/*"],
      conditions: {
        StringNotEquals: {
          "aws:sourceVpce": `${this.s3vpce.vpcEndpointId}`
        }
      }
    });

    this.backupS3Bucket.addToResourcePolicy(
      denyAccessToNotVpceBackup
    );

    this.scriptsS3Bucket.addToResourcePolicy(
      denyAccessToNotVpceScripts
    );
  }

  //S3 for SCADA Backups
  private createDRBucket(){
    
    this.backupS3Bucket = this.createS3Bucket("oncloud-dr-backups")
  }

  //Failover automation
  private createFailoverFunction(){

    //Main Lambda for reading the status
    const check_ignition = new lambda.Function(this, 'check_ignition_status', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('./lambda/check_ignition_status/src'),
      role: this.getLambdaRole(),
      vpc: this.onCloudVPC,
      timeout: cdk.Duration.seconds(10)
    });

    new Rule(this, 'check_ignition_status_rule', {
      schedule: Schedule.cron({ minute: '*' }),
      targets: [new targets.LambdaFunction(check_ignition)],
     });
  }

  private createDBParameters() {

    this.rdsPMG = new rds.ParameterGroup(this, 'MainParameterGroupCloud', {
      engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16_1 }), 
      description: "",
      parameters: {"rds.enable_pgactive":"1", "rds.custom_dns_resolution":"1"}, 
      removalPolicy: cdk.RemovalPolicy.DESTROY});  
  }

  //Define SSM parameters();
  private defineSSMParams(){

    new ssm.StringParameter(this, '/Cloud_Backup_Ignition_Server/gwcert', {parameterName: '/Cloud_Backup_Ignition_Server/gwcert', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/Cloud_Backup_Ignition_Server/gwkey', {parameterName: '/Cloud_Backup_Ignition_Server/gwkey', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/Cloud_Backup_Ignition_Server/gwuuid', {parameterName: '/Cloud_Backup_Ignition_Server/gwuuid', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/OnPremise_Backup_Ignition_Server/gwcert', {parameterName: '/OnPremise_Backup_Ignition_Server/gwcert', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/OnPremise_Backup_Ignition_Server/gwkey', {parameterName: '/OnPremise_Backup_Ignition_Server/gwkey', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/OnPremise_Backup_Ignition_Server/gwuuid', {parameterName: '/OnPremise_Backup_Ignition_Server/gwuuid', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionCloudBackupHostname', {parameterName: '/IgnitionCloudBackupHostname', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionCloudBackupIP', {parameterName: '/IgnitionCloudBackupIP', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionMasterHostname', {parameterName: '/IgnitionMasterHostname', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionMasterIP', {parameterName: '/IgnitionMasterIP', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionOnPremHostname', {parameterName: '/IgnitionOnPremHostname', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionOnPremIP', {parameterName: '/IgnitionOnPremIP', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionOnPremBackupHostname', {parameterName: '/IgnitionOnPremBackupHostname', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/IgnitionOnPremBackupIP', {parameterName: '/IgnitionOnPremBackupIP', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/FailoverFlag', {parameterName: '/FailoverFlag', stringValue: 'true'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/OPCOnPremIP', {parameterName: '/OPCOnPremIP', stringValue: 'null'}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    new ssm.StringParameter(this, '/SCADABackupsBucket', {parameterName: '/SCADABackupsBucket', stringValue: this.backupS3Bucket.bucketName}).applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
  }

  //This method creates a windows bastionhost using an Amazon EC2 AMI
  private createWindowsBastionHost(){
    
    let bootScript = ec2.UserData.forWindows();

    const keyPair = new ec2.KeyPair(this, 'windowsKeyPair', {
      keyPairName: 'admin-keypair-bastion-host',
      type: ec2.KeyPairType.RSA,
    })
    
    let bastion = new ec2.Instance(this, "oncloud_bastion_host", {
      vpc: this.onCloudVPC,
      vpcSubnets: this.getPublicSubnets(2),
      instanceName: "oncloud_bastion_host",
      role: this.getCloudEC2BastionRole(),
      detailedMonitoring: true,
      userData: bootScript,
      keyPair: keyPair,
      machineImage: this.getWindowsAMI(),
      securityGroup: this.getCloudEC2BastionSG(this.onCloudVPC),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.LARGE),
      blockDevices: [
        {
          deviceName: '/dev/sda1',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/oncloud_bastion_host/Resource',
      [
        {
          id: 'AwsSolutions-EC29',
          reason: 'Termination protection is added manually with the L1 construct since the L2 is not'
        }
      ]
    );

   }
  
  //Add necessary routing across TGW
  private adjustRoutingTables(){

    //Enable all the subnets in the cloud to route traffic to the edge and onpremise via TGW
    this.onCloudVPC.privateSubnets.forEach(subnet => {
      (subnet as ec2.Subnet).addRoute('towardsOnpremise1', {    
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.1.0.0/20",
      });
      (subnet as ec2.Subnet).addRoute('towardsEdge1', {    
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.3.0.0/20",
      });
      (subnet as ec2.Subnet).node.findChild("towardsOnpremise1").node.addDependency(this.onCloudTGWAtt);
      (subnet as ec2.Subnet).node.findChild("towardsEdge1").node.addDependency(this.onCloudTGWAtt);
    });

    this.onCloudVPC.publicSubnets.forEach(subnet => {
      (subnet as ec2.Subnet).addRoute('towardsOnpremise', {    
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.1.0.0/20",
      });
      (subnet as ec2.Subnet).node.findChild("towardsOnpremise").node.addDependency(this.onCloudTGWAtt);
    });
  }

  private uploadScriptToS3() {

    this.loggingBucket=new s3.Bucket(this, 'AccessLogsBucket', {
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: cdk.RemovalPolicy.DESTROY, //In prod put RETAIN
      autoDeleteObjects: true, //In prod put false
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, // Block public access to the bucket
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      objectLockEnabled:false, //In prod put TRUE
      serverAccessLogsBucket: this.loggingBucket,
      serverAccessLogsPrefix: 'logs',
    });
    
    this.scriptsS3Bucket = this.createS3Bucket("oncloud-scripts-and-binaries")

    let S3deployment = new s3deploy.BucketDeployment(this, "cloud-upload-install-script", {
      sources: [s3deploy.Source.asset("script"), s3deploy.Source.asset("binaries")],
      destinationBucket: this.scriptsS3Bucket,
      destinationKeyPrefix: "script"
    });

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C/ServiceRole/DefaultPolicy/Resource',
      [
        {
          id: 'AwsSolutions-IAM5',
          reason: 'Created by default by CDK cannot change it'
        },
        {
          id: 'AwsSolutions-EC23',
          reason: 'Created by default by CDK cannot change it'
        },
        {
          id: 'AwsSolutions-IAM1',
          reason: 'Created by default by CDK cannot change it'
        },
      ]
    );

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C/ServiceRole/Resource',
      [
        {
          id: 'AwsSolutions-IAM4',
          reason: 'Created by default by CDK cannot change it'
        }
      ]
    );

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C/Resource',
      [
        {
          id: 'AwsSolutions-L1',
          reason: 'Created by default by CDK cannot change it'
        }
      ]
    );

  }
 
  private createS3Bucket(baseName: string): s3.Bucket {

    const s3Bucket = new s3.Bucket(this, baseName, {
        bucketName: "scada-dr-on-aws-s3-"+baseName+"-"+Date.now(),
        removalPolicy: cdk.RemovalPolicy.DESTROY, //In prod put RETAIN
        autoDeleteObjects: true, //In prod put false
        enforceSSL: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, // Block public access to the bucket
        encryption: s3.BucketEncryption.S3_MANAGED,
        versioned: true,
        objectLockEnabled:false, //In prod put TRUE
        serverAccessLogsBucket: this.loggingBucket,
        serverAccessLogsPrefix: 'logs',
        //objectLockDefaultRetention: s3.ObjectLockRetention.governance(cdk.Duration.days(120)), //remove comment in production
    });

    return s3Bucket;
  }
  
  //Define the central transit gateway for connecting all the VPCs
  private createTransitGateway() {
  
    this.transitGateway = new ec2.CfnTransitGateway(this, 'CloudTransitGateway', /* all optional props */ {

      amazonSideAsn: 65000,
      autoAcceptSharedAttachments: 'enable',
      defaultRouteTableAssociation: 'enable',
      defaultRouteTablePropagation: 'enable',
      description: 'Main transit gateway to interconnect Cloud, Onpremise and Field device networks',
      dnsSupport: 'enable',
      multicastSupport: 'disable',
      transitGatewayCidrBlocks: ['10.1.0.0/20', '10.2.0.0/20', '10.3.0.0/20'],
      vpnEcmpSupport: 'enable',
    });

    this.onCloudTGWAtt=new ec2.CfnTransitGatewayAttachment(this, 'CloudTransitGatewayAttachment', {
      vpcId: this.onCloudVPC.vpcId,
      subnetIds: this.onCloudVPC.privateSubnets.map(subnet => subnet.subnetId),
      transitGatewayId: this.transitGateway.attrId,
    });
  }

  //Create postgres database on cloud VPC
  private createOnCloudDB() {

    let secretName = "onCloudDBCredentials"
    this.onCloudDBCredentials= rds.Credentials.fromUsername("postgres", {secretName: secretName});

    this.OnCloudDBCluster = new rds.DatabaseInstance(this, 'scada_dr_cloud_db', {
      engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16_1 }),
      storageEncrypted: true,
      backupRetention: cdk.Duration.days(30),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
      credentials: this.onCloudDBCredentials,
      securityGroups: [this.getCloudDBSG()],
      parameterGroup: this.rdsPMG,
      port: 5433,
      multiAz: true,
      vpc: this.onCloudVPC,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      }
    });

    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/CloudScadaDrOnAwsStack-us-east-1/scada_dr_cloud_db/Secret/Resource',
      [{
        id: 'AwsSolutions-SMG4',
        reason: 'Ignition SCADA does not support rotating DB Secrets, needs to be rotate manually'
      },
      {
        id: 'AwsSolutions-RDS10',
        reason: 'This database needs to be terminated after the testing'
      }]
    )
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/CloudScadaDrOnAwsStack-us-east-1/scada_dr_cloud_db/Resource',
      [{
        id: 'AwsSolutions-RDS10',
        reason: 'This database needs to be terminated after the testing'
      }]
    )
  }

  private getPrimarySubnets(index: number) {

    /* Subnet selection for the cluster, this statement selects all the private subnets of all AZs in the region */
    let subnet: ec2.SubnetSelection = { subnets: [this.onCloudVPC.privateSubnets[index]] };
    return subnet;
  }

  private getPublicSubnets(index: number) {

    if(index > this.onCloudVPC.publicSubnets.length-1){
      index = this.onCloudVPC.publicSubnets.length-1
    }

    /* Subnet selection for the cluster, this statement selects all the private subnets of all AZs in the region */
    let subnet: ec2.SubnetSelection = { subnets: [this.onCloudVPC.publicSubnets[index]] };
    return subnet;
  }

  private getCloudSCADAUserDataPrimary(){

    let bootScript = ec2.UserData.forLinux();

    bootScript.addCommands("vpcDNS=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "+this.s3vpce.vpcEndpointId+" --query \"VpcEndpoints[0].DnsEntries[0].DnsName\" --output text | cut -c2-)")
    bootScript.addCommands("aws s3 cp s3://"+this.scriptsS3Bucket.bucketName+"/script/ . --recursive --region "+this.region+" --endpoint-url https://bucket$vpcDNS")
    bootScript.addCommands("sudo chmod +x ./*.sh")
    bootScript.addCommands("./cloudSCADAUserDataPrimary.sh "+this.region+" "+this.id+" "+this.OnCloudDBCluster.dbInstanceEndpointAddress+" "+this.OnCloudDBCluster.dbInstanceEndpointPort+" "+this.onCloudDBCredentials.username+" "+this.onPremRegion)
    return bootScript
  }

  private getCloudSCADAUserDataBackup(){

    let bootScript = ec2.UserData.forLinux();
    bootScript.addCommands("vpcDNS=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "+this.s3vpce.vpcEndpointId+" --query \"VpcEndpoints[0].DnsEntries[0].DnsName\" --output text | cut -c2-)")
    bootScript.addCommands("aws s3 cp s3://"+this.scriptsS3Bucket.bucketName+"/script/ . --recursive --region "+this.region+" --endpoint-url https://bucket$vpcDNS")
    bootScript.addCommands("sudo chmod +x ./*.sh")
    bootScript.addCommands("./cloudSCADAUserDataBackup.sh "+this.region+" "+this.id+" "+this.OnCloudDBCluster.dbInstanceEndpointAddress+" "+this.OnCloudDBCluster.dbInstanceEndpointPort+" "+this.onCloudDBCredentials.username)   
    return bootScript
  }

  private createOnCloudEC2s(){

    this.onCloudEC2Primary=new ec2.Instance(this, "scada_oncloud_primary", {
      vpc: this.onCloudVPC,
      vpcSubnets: this.getPrimarySubnets(0),
      instanceName: "scada_oncloud_primary",
      role: this.getEC2Role(),
      userData: this.getCloudSCADAUserDataPrimary(),
      machineImage: this.getRHELAMI(),
      securityGroup: this.getCloudEC2SG(this.onCloudVPC),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.LARGE),
      detailedMonitoring: true,
      
      blockDevices: [
        { 
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/scada_oncloud_primary/Resource',
      [
        {
          id: 'AwsSolutions-EC29',
          reason: 'Termination protection is added manually with the L1 construct since the L2 is not'
        }
      ]
    );

    this.onCloudEC2Backup=new ec2.Instance(this, "scada_oncloud_backup", {
      vpc: this.onCloudVPC,
      vpcSubnets: this.getPrimarySubnets(1),
      instanceName: "scada_oncloud_backup",
      role: this.getEC2Role(),
      userData: this.getCloudSCADAUserDataBackup(),
      detailedMonitoring: true,
      machineImage: this.getRHELAMI(),
      securityGroup: this.getCloudEC2SG(this.onCloudVPC),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.LARGE),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      '/CloudScadaDrOnAwsStack-us-east-1/scada_oncloud_backup/Resource',
      [
        {
          id: 'AwsSolutions-EC29',
          reason: 'Termination protection is added manually with the L1 construct since the L2 is not'
        }
      ]
    );
  }

  private getRHELAMI() {
    
    //Temporary testing with Amazon Linux for semplicity
    return new ec2.AmazonLinuxImage({
      generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023,
    })

    /*
    return new ec2.LookupMachineImage({
      name: "RHEL-9.2.0*x86_64*",
      windows: false
    });
    */
  }

  private getWindowsAMI() {
    
    return new ec2.WindowsImage(ec2.WindowsVersion.WINDOWS_SERVER_2022_ENGLISH_FULL_BASE);

  }

  private getCloudEC2SG(vpc: ec2.Vpc) {

    if(this.onCloudEC2SG){
      return this.onCloudEC2SG;
    } else {
      
      let onCloudEC2SG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "ec2_scada_primary_sg", {
        securityGroupName: "ec2_scada_primary_sg",
        vpc: vpc
      });

      onCloudEC2SG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(5433), "Postgres connection for replica");
      onCloudEC2SG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(8060), "Postgres connection for replica");
      onCloudEC2SG.addIngressRule(this.getCloudEC2BastionSG(vpc), ec2.Port.tcp(443), "Ignition connection");
      onCloudEC2SG.addIngressRule(onCloudEC2SG, ec2.Port.tcp(8060), "Ignition connection for replica");

      this.onCloudEC2SG = onCloudEC2SG;
      return onCloudEC2SG;
    }
  }

  private getCloudEC2BastionSG(vpc: ec2.Vpc) {

    if(this.onCloudBastionEC2SG){
      return this.onCloudBastionEC2SG;
    } else {
      
      let onCloudBastionEC2SG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "ec2_scada_bastion_sg", {
        securityGroupName: "ec2_scada_bastion_sg",
        vpc: vpc
      });

      this.onCloudBastionEC2SG = onCloudBastionEC2SG;
      return onCloudBastionEC2SG;
    }
  }
  
  private getCloudS3VPCEndpointSG(vpc: ec2.Vpc) {
    
    if(this.onCloudVPCSG){
    
      return this.onCloudVPCSG;
    
    } else {
      
      let onCloudVPCSG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "sg_vpce_oncloud", {
        securityGroupName: "sg_vpce_oncloud",
        vpc: vpc
      });

      onCloudVPCSG.addIngressRule(this.getCloudEC2SG(vpc), ec2.Port.tcp(443), "Open connection to S3 from Ignition");
      onCloudVPCSG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(443), "Open connection to S3 from onprem Ignition");

      NagSuppressions.addResourceSuppressionsByPath(this, 
        '/CloudScadaDrOnAwsStack-us-east-1/sg_vpce_oncloud/Resource',
        [{
          id: 'AwsSolutions-EC23',
          reason: 'CdkNagValidationFailure since the configuration is specifying IPs and Ports for VPC Endpoint'
        }]
      )

      this.onCloudVPCSG = onCloudVPCSG;
      return onCloudVPCSG;
    }
  }

  private getCloudDBSG() {

    if(this.onCloudDBSG){

      return this.onCloudDBSG;
    } else {
      
      let onCloudDBSG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "sg_db_scada_oncloud", {
        securityGroupName: "sg_db_scada_oncloud",
        vpc: this.onCloudVPC
      });

      onCloudDBSG.addIngressRule(this.getCloudEC2SG(this.onCloudVPC), ec2.Port.tcp(5433), "Open connection to DB from Ignition");
      onCloudDBSG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(5433), "Open connection to RDS from RDS for replica");

      this.onCloudDBSG = onCloudDBSG;
      return onCloudDBSG;
    }
  }

  private getCloudEC2BastionRole() {

    // Role to be assumed by EC2 instances
    let assumedBy: iam.IPrincipal = new iam.ServicePrincipal("ec2.amazonaws.com");

    // Setting the role for the EC2 that are going to spawn
    let ec2Role: iam.Role = new iam.Role(this, "scada_dr_cluster_ec2_bastion_role", {
      managedPolicies : [
        // This is not working https://docs.aws.amazon.com/systems-manager/latest/userguide/fleet-rdp.html
        iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
      ],
      assumedBy: assumedBy
    });
    
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/CloudScadaDrOnAwsStack-us-east-1/scada_dr_cluster_ec2_bastion_role/Resource',
      [{
        id: 'AwsSolutions-IAM4',
        reason: "Had to fallback to using AmazonSSMManagedInstanceCore because the one stated in the official documentation to enable the EC2 remote RDM connection is not working in workshop studio, https://docs.aws.amazon.com/systems-manager/latest/userguide/fleet-rdp.html"
      }]
    )
  
    return ec2Role;
  }

  private getLambdaRole() {
  
    if(this.lambdaRole){

      return this.lambdaRole;

    } else {
      
      // Role to be assumed by EC2 instances
      let assumedBy: iam.IPrincipal = new iam.ServicePrincipal("lambda.amazonaws.com");
    
      // Setting the role for the EC2 that are going to spawn
      let lambdaRole: iam.Role = new iam.Role(this, "lambda_role", {
        assumedBy: assumedBy
      });

      const ssmStatementCommand = {
        "Effect": "Allow",
        "Action": [
          "ssm:SendCommand"
        ],
        "Resource": [
          "arn:aws:ec2:"+this.region+":"+this.account+":managed-instance/*",
          "arn:aws:ec2:"+this.region+":"+this.account+":instance/*",
          "arn:aws:ssm:"+this.region+"::document/AWS-RunShellScript"
        ]
      };

      const ssmStatementParams = {
        "Effect": "Allow",
        "Action": [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ],
        "Resource": [
          "arn:aws:ssm:"+this.region+":"+this.account+":parameter/*"
        ]
      };

      const cloudWatchLGStatement =  {
        "Effect": "Allow",
        "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource": [
          "arn:aws:logs:"+this.region+":"+this.account+":log-group:*"
        ]
      };

      const ec2Statement = {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeInstances"
        ],
        "Resource": [
          "*"
        ]
      };

      const ec2StatementStar = {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface"
        ],
        "Resource": [
          "*"
        ]
      };

      lambdaRole.addToPolicy(iam.PolicyStatement.fromJson(ssmStatementCommand));
      lambdaRole.addToPolicy(iam.PolicyStatement.fromJson(ssmStatementParams));
      lambdaRole.addToPolicy(iam.PolicyStatement.fromJson(cloudWatchLGStatement));
      lambdaRole.addToPolicy(iam.PolicyStatement.fromJson(ec2Statement));
      lambdaRole.addToPolicy(iam.PolicyStatement.fromJson(ec2StatementStar));

      NagSuppressions.addResourceSuppressionsByPath(
        this,
        '/CloudScadaDrOnAwsStack-us-east-1/lambda_role/DefaultPolicy/Resource',
        [
          {
            id: 'AwsSolutions-IAM5',
            reason: 'Bug https://github.com/aws/aws-cdk/issues/24258'
          }
        ]
      );
    
      this.lambdaRole = lambdaRole;
      return lambdaRole;
    }

  }

  private getEC2Role() {

    if(this.ec2Role){

      return this.ec2Role;

    } else {
      
      // Role to be assumed by EC2 instances
      let assumedBy: iam.IPrincipal = new iam.ServicePrincipal("ec2.amazonaws.com");
    
      // Setting the role for the EC2 that are going to spawn
      let ec2Role: iam.Role = new iam.Role(this, "scada_primary_cluster_ec2_role", {
        managedPolicies : [
          iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
        ],
        assumedBy: assumedBy
      });

      const SecretMStatement = {
        "Effect": "Allow",
        "Action": [
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds"
        ],
        "Resource": [
          "arn:aws:secretsmanager:"+this.region+":"+this.account+":secret:*",
          "arn:aws:secretsmanager:"+this.onPremRegion+":"+this.account+":secret:*"
        ]
      };

      const SSMtatement = {
        "Effect": "Allow",
        "Action": [
          "ssm:PutParameter",
          "ssm:GetParameter"
        ],
        "Resource": [
          "arn:aws:ssm:"+this.region+":"+this.account+":parameter/*"
        ]
      };

      const TGStatementStar = {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateTransitGatewayRoute",
          "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeTransitGatewayRouteTables",
          "ec2:CreateTransitGatewayRouteTable"
        ],
        "Resource": [
          "*"
        ]
      };

      const TGW2Statement = {
        "Effect": "Allow",
        "Action": [
          "ec2:AcceptTransitGatewayPeeringAttachment"
        ],
        "Resource": [
          "arn:aws:ec2:"+this.region+":"+this.account+":transit-gateway-attachment/*"
        ]
      };

      const S3Writestatement = {
        "Effect": "Allow",
        "Action": [
          "s3:ListBucketMultipartUploads",
          "s3:ListMultipartUploadParts",
          "s3:AbortMultipartUpload",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetObject"
        ],
        "Resource": [
          this.scriptsS3Bucket.bucketArn,
          this.scriptsS3Bucket.bucketArn+"/*",
          this.backupS3Bucket.bucketArn,
          this.backupS3Bucket.bucketArn+"/*"
        ]
      };

      const S3WritestatementStar = {
        "Effect": "Allow",
        "Action": [
          "s3:ListBucket"
        ],
        "Resource": [
          "*"
        ]
      };


      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(TGW2Statement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(TGStatementStar));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(S3Writestatement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(S3WritestatementStar));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(SecretMStatement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(SSMtatement));

      NagSuppressions.addResourceSuppressionsByPath(
        this,
        '/CloudScadaDrOnAwsStack-us-east-1/scada_primary_cluster_ec2_role/DefaultPolicy/Resource',
        [
          {
            id: 'AwsSolutions-IAM5',
            reason: 'The role is minimized, the star is required for the VPC Endpoints'
          }
        ]
      );
      NagSuppressions.addResourceSuppressionsByPath(
        this,
        '/CloudScadaDrOnAwsStack-us-east-1/scada_primary_cluster_ec2_role/Resource',
        [
          {
            id: 'AwsSolutions-IAM4',
            reason: 'I cannot manage to get SSM RunCommand to work without the managed service, tried many times unsuccessfully'
          }
        ]
      );

      this.ec2Role = ec2Role;
      return ec2Role;
    }
  }

  private createOnCloudVPC(){

    // Public network group
    let publicSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "scada_on_cloud_public",
      reserved: false, 
      subnetType: ec2.SubnetType.PUBLIC,
    };

    // Private network group
    let privateSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "scada_on_cloud_private",
      reserved: false,
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
    };

    // Configuring networks to add to the VPC
    let subnetConfigs: ec2.SubnetConfiguration[] = [publicSubnet, privateSubnet];

    /* Create VPC with the configured networks */
    let vpc: ec2.Vpc = new ec2.Vpc(this, "scada_on_cloud_vpc", {
      ipAddresses: ec2.IpAddresses.cidr('10.2.0.0/20'),
      maxAzs: 3,
      subnetConfiguration: subnetConfigs,
    });

    vpc.addFlowLog('scada_on_cloud_vpc_FlowLogS3', {
      destination: ec2.FlowLogDestination.toS3(this.loggingBucket)
    });

    let gwend=new ec2.GatewayVpcEndpoint(this, 'S3GWVpce', {
      service:  ec2.GatewayVpcEndpointAwsService.S3,
      vpc,
    });

    this.s3vpce = new ec2.InterfaceVpcEndpoint(this, 'S3InterfaceVpce', {
      vpc,
      service: new ec2.InterfaceVpcEndpointService('com.amazonaws.'+this.region+'.s3', 443),
      subnets: { subnets: vpc.privateSubnets },
      privateDnsEnabled: true,      
      securityGroups: [this.getCloudS3VPCEndpointSG(vpc)]
    });

    let actions = ['*'];
    let resources = ['*'];
    resources = [
      `${this.scriptsS3Bucket.bucketArn}`,
      `${this.scriptsS3Bucket.bucketArn}/*`,
      `${this.backupS3Bucket.bucketArn}`,
      `${this.backupS3Bucket.bucketArn}/*`,
    ]

    const allowAccessToS3 = new iam.PolicyStatement({
      actions,
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      resources,
    });
    // attach the policy statement to the vpce
    this.s3vpce.addToPolicy(allowAccessToS3);

    this.onCloudVPC=vpc;
  }
}