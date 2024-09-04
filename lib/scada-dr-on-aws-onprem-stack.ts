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
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { CloudScadaDrOnAwsStack } from './scada-dr-on-aws-oncloud-stack';
import { NagSuppressions } from 'cdk-nag'

import { readFileSync } from 'fs';
import { Construct } from 'constructs';

export class OnpremScadaDrOnAwsStack extends cdk.Stack {

  //Artifacts
  public onPremVPC: ec2.Vpc;
  public onEdgeVPC: ec2.Vpc;
  public ec2Role: iam.Role;
  public onPremEC2: ec2.Instance;
  public onPremEC2SG: ec2.SecurityGroup;
  public onEdgeEC2SG: ec2.SecurityGroup;
  public onPremDBSG: ec2.SecurityGroup;
  public transitGateway: ec2.CfnTransitGateway;
  public onCloudTransitGateway: ec2.CfnTransitGateway;
  public onEdgeTGWAtt: ec2.CfnTransitGatewayAttachment;
  public onPremTGWAtt: ec2.CfnTransitGatewayAttachment;
  public rdsPMG: rds.IParameterGroup;
  public scriptsS3Bucket: s3.Bucket;
  public backupS3Bucket: s3.Bucket;
  public loggingBucket: s3.Bucket;
  public s3vpce: ec2.GatewayVpcEndpoint;
  
  //Parameters
  public OnPremDB: rds.DatabaseInstance;
  public onPremDBCredentials: rds.Credentials;
  public cloudRegion: string;
  protected id: string;
  protected cloudId: string;

  constructor(scope: Construct, id: string, oncloudId: string, cloudRegion: string, cloud: CloudScadaDrOnAwsStack, props?: cdk.StackProps) {
    super(scope, id, props);
    this.cloudRegion = cloudRegion;
    this.onCloudTransitGateway = cloud.transitGateway;
    this.scriptsS3Bucket = cloud.scriptsS3Bucket;
    this.backupS3Bucket = cloud.backupS3Bucket;
    this.loggingBucket = cloud.loggingBucket;
    this.id=id;
    this.cloudId=oncloudId;
    this.s3vpce=cloud.s3vpce;

    /**
     * Creates a VPC to simulate an on-premises environment for the Ignition SCADA Disaster Recovery solution.
     * The VPC includes a public subnet and a private subnet with egress.
     * VPC Flow Logs are enabled and sent to an S3 bucket for monitoring network traffic.
     * The created VPC instance is assigned to the `this.onPremVPC` property.
     */
    this.createOnPremiseVPC();

    /**
     * Creates a VPC to simulate an on-premises environment for edge devices in the Ignition SCADA Disaster Recovery solution.
     * The VPC includes a public subnet and a private subnet with egress.
     * VPC Flow Logs are enabled and sent to an S3 bucket for monitoring network traffic.
     * The created VPC instance is assigned to the `this.onEdgeVPC` property.
     */
    this.createEdgeVPC();

    /**
     * Creates a Parameter Group for the RDS (Relational Database Service) instance used in the Ignition SCADA Disaster Recovery solution.
     * The Parameter Group is configured with the following settings:
     *   - Database engine: PostgreSQL version 16.1
     *   - Parameter 'rds.enable_pgactive' is set to '1'
     *   - Parameter 'rds.custom_dns_resolution' is set to '1'
     * The created Parameter Group instance is assigned to the `this.rdsPMG` property.
     * The Parameter Group will be destroyed when the stack is deleted (RemovalPolicy.DESTROY).
     */
    this.createDBParameters();

    /**
     * Creates an RDS instance to simulate an on-premises database for the Ignition SCADA solution.
     * The instance is configured with PostgreSQL 16.1, encrypted storage, and a 30-day backup retention.
     * Database credentials, security group, parameter group, VPC, and subnet are obtained from respective properties and methods.
     * The created RDS instance is assigned to the 'this.OnPremDB' property.
     */
    this.createOnPremDB();

    /**
     * Creates two EC2 instances to simulate on-premises SCADA systems for the Ignition SCADA solution.
     * The instances are configured with the following:
     *   - Deployed in the 'this.onPremVPC' VPC and subnets obtained from 'this.getPrimarySubnets()'
     *   - Instance names: 'scada_primary_onpremise' and 'scada_backup_onpremise'
     *   - IAM role obtained from 'this.getEC2Role()'
     *   - User data scripts obtained from 'this.getOnPremiseSCADAUserData()' and 'this.getOnPremSCADAUserDataBackup()'
     *   - Machine image obtained from 'this.getRHELAMI()'
     *   - Security group obtained from 'this.getOnPremiseEC2SG()'
     *   - Instance type: Burstable2, Large
     *   - 50 GB encrypted EBS volume
     * AWS Config rules 'AwsSolutions-EC29' and 'AwsSolutions-EC28' are suppressed for testing disaster recovery scenarios.
     * The created instances are assigned to the 'this.onPremEC2' property.
     */
    this.createOnPremiseEC2();
  
    /**
     * Creates an EC2 instance to simulate an edge device for the Ignition SCADA solution.
     * The instance is configured with the following:
     *   - Deployed in the 'this.onEdgeVPC' VPC and subnets obtained from 'this.getPrimarySubnets()'
     *   - Instance name: 'opc_ua_simulator_edge'
     *   - IAM role obtained from 'this.getEdgeEC2Role()'
     *   - User data script obtained from 'this.getOPCUAUserData()'
     *   - Machine image obtained from 'this.getRHELAMI()'
     *   - Security group obtained from 'this.getOnEdgeEC2SG()'
     *   - Instance type: Burstable2, Medium
     *   - 50 GB encrypted EBS volume
     * AWS Config rule 'AwsSolutions-EC29' is suppressed for testing disaster recovery scenarios.
     * The created instance is assigned to the respective property.
     */
    this.createOnEdgeEC2();

    /**
     * Creates a Transit Gateway and attaches the on-premises and edge VPCs to it.
     * The Transit Gateway is configured with the following settings:
     *   - Amazon ASN: 65000
     *   - Default route table association and propagation enabled
     *   - DNS support enabled
     *   - Multicast support disabled
     *   - CIDR blocks: 10.1.0.0/20, 10.2.0.0/20, 10.3.0.0/20
     *   - VPN ECMP support enabled
     * The on-premises VPC ('this.onPremVPC') and edge VPC ('this.onEdgeVPC') are attached to the Transit Gateway.
     * The Transit Gateway is dependent on the 'this.onCloudTransitGateway' resource.
     */
    this.createTransitGateway();

    /**
     * Adjusts the routing tables of the on-premises and edge VPCs to enable communication through the Transit Gateway.
     * The following routes are added:
     *   - On-premises private subnets: Routes to the cloud and edge VPC CIDR blocks via the Transit Gateway
     *   - Edge private subnets: Routes to the cloud and on-premises VPC CIDR blocks via the Transit Gateway
     * The routing table entries are made dependent on the respective Transit Gateway attachments.
     * Additionally, a Transit Gateway peering attachment is created to connect the on-premises and cloud Transit Gateways across regions.
     */
    this.adjustRoutingTables();
  }

  //Define parameters for DBs
  private createDBParameters() {

    this.rdsPMG = new rds.ParameterGroup(this, 'MainParameterGroup', {
      engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16_1 }), 
      description: "",
      parameters: {"rds.enable_pgactive":"1", "rds.custom_dns_resolution":"1"}, 
      removalPolicy: cdk.RemovalPolicy.DESTROY});  
  }

  //Add necessary routing across TGW
  private adjustRoutingTables(){

    //Enable all the subnets at on premise to route traffic to the cloud and edge via TGW
    this.onPremVPC.privateSubnets.forEach(subnet => {
      (subnet as ec2.Subnet).addRoute('towardsCloud2', {
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.2.0.0/20",
      });
      (subnet as ec2.Subnet).addRoute('towardsEdge2', {
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.3.0.0/20",
      });
      (subnet as ec2.Subnet).node.findChild("towardsCloud2").node.addDependency(this.onPremTGWAtt);
      (subnet as ec2.Subnet).node.findChild("towardsEdge2").node.addDependency(this.onPremTGWAtt);

    });

    //Enable all the subnets in edge to route traffic to the cloud and onpremise via TGW
    this.onEdgeVPC.privateSubnets.forEach(subnet => {
      (subnet as ec2.Subnet).addRoute('towardsCloud3', {
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.2.0.0/20",
      });
      (subnet as ec2.Subnet).addRoute('towardsOnPremise3', {
        routerId: this.transitGateway.attrId,
        routerType: ec2.RouterType.TRANSIT_GATEWAY,
        destinationCidrBlock: "10.1.0.0/20",
      });
      (subnet as ec2.Subnet).node.findChild("towardsCloud3").node.addDependency(this.onEdgeTGWAtt);
      (subnet as ec2.Subnet).node.findChild("towardsOnPremise3").node.addDependency(this.onEdgeTGWAtt);
    });

    //Create a peering attachment to connect the two regions, this can also be done wo the TGW via peerings
    const cfnTransitGatewayPeeringAttachment = new ec2.CfnTransitGatewayPeeringAttachment(this, 'towardsCloudPeeringAttachment', {
      peerAccountId: this.account,
      peerRegion: this.cloudRegion,
      peerTransitGatewayId: this.onCloudTransitGateway.attrId,
      transitGatewayId: this.transitGateway.attrId
    });

  }

  //Define the central transit gateway for connecting all the VPCs
  private createTransitGateway() {
  
    this.transitGateway = new ec2.CfnTransitGateway(this, 'OnPremTransitGateway', /* all optional props */ {

      amazonSideAsn: 65000,
      associationDefaultRouteTableId: 'associationDefaultRouteTableId',
      autoAcceptSharedAttachments: 'enable',
      defaultRouteTableAssociation: 'enable',
      defaultRouteTablePropagation: 'enable',
      description: 'Main transit gateway to interconnect Cloud, Onpremise and Field device networks',
      dnsSupport: 'enable',
      multicastSupport: 'disable',
      propagationDefaultRouteTableId: 'propagationRouteTable',
      transitGatewayCidrBlocks: ['10.1.0.0/20', '10.2.0.0/20', '10.3.0.0/20'],
      vpnEcmpSupport: 'enable',
    });

    this.onPremTGWAtt=new ec2.CfnTransitGatewayAttachment(this, 'OnPremTransitGatewayAttachment', {
      vpcId: this.onPremVPC.vpcId,
      subnetIds: this.onPremVPC.privateSubnets.map(subnet => subnet.subnetId),
      transitGatewayId: this.transitGateway.attrId,
    });

    this.onEdgeTGWAtt=new ec2.CfnTransitGatewayAttachment(this, 'EdgeTransitGatewayAttachment', {
      vpcId: this.onEdgeVPC.vpcId,
      subnetIds: this.onEdgeVPC.privateSubnets.map(subnet => subnet.subnetId),
      transitGatewayId: this.transitGateway.attrId,
    });

    this.transitGateway.addDependency(this.onCloudTransitGateway)

  }

  private createOnPremDB() {

    this.onPremDBCredentials = rds.Credentials.fromUsername("postgres", {secretName: "onPremDBCredentials"});

    this.OnPremDB = new rds.DatabaseInstance(this, 'scada_primary_onpremise_db', {
      engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16_1 }),
      storageEncrypted: true,
      backupRetention: cdk.Duration.days(30),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
      credentials: this.onPremDBCredentials,
      securityGroups: [this.getOnPremiseDBSG()],
      parameterGroup: this.rdsPMG,
      vpc: this.onPremVPC,
      port: 5433,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      }
    });
    
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_onpremise_db/Secret/Resource',
      [{
        id: 'AwsSolutions-SMG4',
        reason: 'Ignition SCADA does not support rotating DB Secrets, needs to be rotate manually'
      }]
    )
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_onpremise_db/Resource',
      [{
        id: 'AwsSolutions-RDS3',
        reason: 'This is single instance by design to make it fail'
      }]
    )
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_onpremise_db/Resource',
      [{
        id: 'AwsSolutions-RDS3',
        reason: 'This database should be terminated and be terminated to test the disaster recovery'
      }]
    )
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_onpremise_db/Resource',
      [{
        id: 'AwsSolutions-RDS10',
        reason: 'This database should be terminated and be terminated to test the disaster recovery'
      }]
    )

  }

  private getPrimarySubnets() {

    /* Subnet selection for the cluster, this statement selects all the private subnets of all AZs in the region */
    let privateSubnets: ec2.SubnetSelection = { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS };
    return privateSubnets;
  }

  private getPublicSubnets() {

    /* Subnet selection for the cluster, this statement selects all the private subnets of all AZs in the region */
    let publicSubnets: ec2.SubnetSelection = { subnetType: ec2.SubnetType.PUBLIC };
    return publicSubnets;
  }
  
  private getOnPremiseSCADAUserData(){

    let bootScript = ec2.UserData.forLinux();

    bootScript.addCommands("vpcDNS=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "+this.s3vpce.vpcEndpointId+" --query \"VpcEndpoints[0].DnsEntries[0].DnsName\" --output text --region "+ this.cloudRegion +" | cut -c2-)")
    bootScript.addCommands("aws s3 cp s3://"+this.scriptsS3Bucket.bucketName+"/script/ . --recursive --region "+this.cloudRegion)
    bootScript.addCommands("sudo chmod +x ./*.sh")
    bootScript.addCommands("./onpremSCADAUserDataPrimary.sh "+this.cloudRegion+" "+this.region+" "+this.id + " " + this.OnPremDB.dbInstanceEndpointAddress + " "+this.OnPremDB.dbInstanceEndpointPort + " " + this.onPremDBCredentials.username + " s3://" + this.backupS3Bucket.bucketName + " $vpcDNS")
    return bootScript
  }

  private getOnPremSCADAUserDataBackup(){

    let bootScript = ec2.UserData.forLinux();

    bootScript.addCommands("vpcDNS=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "+this.s3vpce.vpcEndpointId+" --query \"VpcEndpoints[0].DnsEntries[0].DnsName\" --output text --region "+ this.cloudRegion +" | cut -c2-)")
    bootScript.addCommands("aws s3 cp s3://"+this.scriptsS3Bucket.bucketName+"/script/ . --recursive --region "+this.cloudRegion)
    bootScript.addCommands("sudo chmod +x ./*.sh")
    bootScript.addCommands("./onpremSCADAUserDataBackup.sh "+this.cloudRegion+" "+this.region+" "+this.id + " " + this.OnPremDB.dbInstanceEndpointAddress + " "+this.OnPremDB.dbInstanceEndpointPort + " " + this.onPremDBCredentials.username + " s3://" + this.backupS3Bucket.bucketName + " $vpcDNS")
    return bootScript
  }

  private getOPCUAUserData(){

    let bootScript = ec2.UserData.forLinux();
    bootScript.addCommands("sudo yum update -y");
    bootScript.addCommands("sudo yum install python3 -y");
    bootScript.addCommands("sudo yum install pip -y");
    bootScript.addCommands("python3 -m pip install opcua");
    bootScript.addCommands("aws s3 cp s3://"+this.scriptsS3Bucket.bucketName+"/script/opcua_server.py . --region "+this.cloudRegion)
    bootScript.addCommands("sudo chmod +x ./opcua_server.py")
    bootScript.addCommands("nohup python3 opcua_server.py &");
    bootScript.addCommands("aws ssm put-parameter --region '"+this.cloudRegion+"' --name 'OPCOnPremIP' --value $(hostname -I) --type String --overwrite")
    return bootScript;
  }

  private createOnEdgeEC2(){

    new ec2.Instance(this, "opc_ua_simulator_edge", {
      vpc: this.onEdgeVPC,
      vpcSubnets: this.getPrimarySubnets(),
      instanceName: "opc_ua_simulator_edge",
      role: this.getEdgeEC2Role(),
      userData: this.getOPCUAUserData(),
      machineImage: this.getRHELAMI(),
      securityGroup: this.getOnEdgeEC2SG(),
      detailedMonitoring: true,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MEDIUM),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/opc_ua_simulator_edge/Resource',
      [{
        id: 'AwsSolutions-EC29',
        reason: 'This instance should be terminated and be terminated to test the disaster recovery'
      }]
    )
  }

  private createOnPremiseEC2(){

    let userData= this.getOnPremiseSCADAUserData();

    this.onPremEC2= new ec2.Instance(this, "scada_primary_onpremise", {
      vpc: this.onPremVPC,
      vpcSubnets: this.getPrimarySubnets(),
      instanceName: "scada_primary_onpremise",
      role: this.getEC2Role(),
      userData: userData,
      machineImage: this.getRHELAMI(),
      securityGroup: this.getOnPremiseEC2SG(),
      detailedMonitoring: true,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.LARGE),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_onpremise/Resource',
      [{
        id: 'AwsSolutions-EC29',
        reason: 'This instance should be terminated and be terminated to test the disaster recovery'
      }]
    )

    let userDataBackup= this.getOnPremSCADAUserDataBackup();

    this.onPremEC2= new ec2.Instance(this, "scada_backup_onpremise", {
      vpc: this.onPremVPC,
      vpcSubnets: this.getPrimarySubnets(),
      instanceName: "scada_backup_onpremise",
      role: this.getEC2Role(),
      userData: userDataBackup,
      machineImage: this.getRHELAMI(),
      securityGroup: this.getOnPremiseEC2SG(),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.LARGE),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {encrypted: true}),
        }
      ]
    });
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_backup_onpremise/Resource',
      [{
        id: 'AwsSolutions-EC28',
        reason: 'This instance should be terminated and be terminated to test the disaster recovery'
      }]
    )
    NagSuppressions.addResourceSuppressionsByPath(this, 
      '/OnpremScadaDrOnAwsStack-us-west-2/scada_backup_onpremise/Resource',
      [{
        id: 'AwsSolutions-EC29',
        reason: 'This instance should be terminated and be terminated to test the disaster recovery'
      }]
    )
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
    
    //Temporary testing with Amazon Linux for semplicity
    return new ec2.WindowsImage(ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE);

  }

  private getOnPremiseEC2SG() {

    if(this.onPremEC2SG){
      return this.onPremEC2SG;
    } else {
      
      let onPremEC2SG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "sg_ec2_scada_sg", {
        securityGroupName: "ec2_scada_dr_sg",
        vpc: this.onPremVPC
      });

      onPremEC2SG.addIngressRule(ec2.Peer.ipv4('10.2.0.0/20'), ec2.Port.tcp(5433), "Postgres connection for replica");
      onPremEC2SG.addIngressRule(ec2.Peer.ipv4('10.2.0.0/20'), ec2.Port.tcp(443), "Bastion connection for admin");
      onPremEC2SG.addIngressRule(ec2.Peer.ipv4('10.2.0.0/20'), ec2.Port.tcp(8060), "Connection for ignition");
      onPremEC2SG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(8060), "Connection for ignition");
      onPremEC2SG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(443), "Connection for healthcheck");

      this.onPremEC2SG = onPremEC2SG;
      return onPremEC2SG;
    }
  }

  private getOnEdgeEC2SG() {

    if(this.onEdgeEC2SG){
      return this.onEdgeEC2SG;
    } else {
      
      let onEdgeEC2SG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "sg_ec2_opc_simulator", {
        securityGroupName: "ec2_opc_simulator",
        vpc: this.onEdgeVPC
      });

      onEdgeEC2SG.addIngressRule(ec2.Peer.ipv4('10.2.0.0/20'), ec2.Port.tcp(4840), "Open connection to OPC-UA Simulator from Ignition");
      onEdgeEC2SG.addIngressRule(ec2.Peer.ipv4('10.1.0.0/20'), ec2.Port.tcp(4840), "Open connection to OPC-UA Simulator from Ignition");  

      this.onEdgeEC2SG = onEdgeEC2SG;
      return onEdgeEC2SG;
    }
  }

  private getOnPremiseDBSG() {

    if(this.onPremDBSG){
      return this.onPremDBSG;
    } else {
      
      let onPremDBSG: ec2.SecurityGroup = new ec2.SecurityGroup(this, "sg_db_scada_onprem", {
        securityGroupName: "sg_db_scada_onprem",
        vpc: this.onPremVPC
      });

      onPremDBSG.addIngressRule(this.getOnPremiseEC2SG(), ec2.Port.tcp(5433), "Open connection to DB from Ignition");
      onPremDBSG.addIngressRule(ec2.Peer.ipv4('10.2.0.0/20'), ec2.Port.tcp(5433), "Open connection to RDS from RDS for replica");

      this.onPremDBSG = onPremDBSG;
      return onPremDBSG;
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
          "arn:aws:secretsmanager:"+this.cloudRegion+":"+this.account+":secret:*"
        ]
      };
      
      const SSMtatement = {
        "Effect": "Allow",
        "Action": [
          "ssm:PutParameter",
          "ssm:GetParameter"
        ],
        "Resource": [
          "arn:aws:ssm:"+this.cloudRegion+":"+this.account+":parameter/*"
        ]
      };

      const EC2Statement = {
        "Effect": "Allow",
        "Action": [
          "ec2:AcceptTransitGatewayPeeringAttachment"
        ],
        "Resource": [
          "arn:aws:ec2:"+this.region+":"+this.account+":transit-gateway-attachment/*"
        ]
      };

      const TGStatementStar = {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateTransitGatewayRoute",
          "ec2:CreateTransitGatewayRouteTable",
          "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeTransitGatewayRouteTables"
        ],
        "Resource": [
          "*"
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

      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(S3Writestatement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(TGStatementStar));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(EC2Statement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(SecretMStatement));
      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(SSMtatement));

      NagSuppressions.addResourceSuppressionsByPath(
        this,
        '/OnpremScadaDrOnAwsStack-us-west-2/scada_primary_cluster_ec2_role/DefaultPolicy/Resource',
        [
          {
            id: 'AwsSolutions-IAM5',
            reason: 'The role is minimized, the star is required for the VPC Endpoint'
          }
        ]
      );

      this.ec2Role = ec2Role;
      return ec2Role;
    }
  }

  private getEdgeEC2Role() {

    if(this.ec2Role){

      return this.ec2Role;

    } else {

      // Role to be assumed by EC2 instances
      let assumedBy: iam.IPrincipal = new iam.ServicePrincipal("ec2.amazonaws.com");
    
      // Setting the role for the EC2 that are going to spawn
      let ec2Role: iam.Role = new iam.Role(this, "opc_ua_ec2_role", {
        assumedBy: assumedBy
      });

      const statement = {
        "Effect": "Allow",
        "Action": [
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds"
        ],
        "Resource": [
          "arn:aws:secretsmanager:"+this.region+":"+this.account+":secret:*"
        ]
      };

      ec2Role.addToPolicy(iam.PolicyStatement.fromJson(statement));

      this.ec2Role = ec2Role;
      return ec2Role;
    }
  }

  private createOnPremiseVPC(){

    // Public network group
    let publicSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "scada_on_premise_public",
      reserved: false, 
      subnetType: ec2.SubnetType.PUBLIC
    };

    // Private network group
    let privateSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "scada_on_premise_private",
      reserved: false,
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
    };

    // Configuring networks to add to the VPC
    let subnetConfigs: ec2.SubnetConfiguration[] = [publicSubnet, privateSubnet];

    /* Create VPC with the configured networks */
    let vpc: ec2.Vpc = new ec2.Vpc(this, "scada_on_premise_vpc", {
      ipAddresses: ec2.IpAddresses.cidr('10.1.0.0/20'),
      availabilityZones : [this.region+'b',this.region+'a'],
      subnetConfiguration: subnetConfigs
    });

    vpc.addFlowLog('scada_on_cloud_vpc_FlowLogS3', {
      destination: ec2.FlowLogDestination.toS3(this.loggingBucket)
    });

    this.onPremVPC=vpc;
  }
 
  private createEdgeVPC(){

    // Public network group
    let publicSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "devices_on_premise_public",
      reserved: false, 
      subnetType: ec2.SubnetType.PUBLIC
    };

    // Private network group
    let privateSubnet: ec2.SubnetConfiguration = {
      cidrMask: 24,
      name: "devices_on_premise_private",
      reserved: false,
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
    };

    // Configuring networks to add to the VPC
    let subnetConfigs: ec2.SubnetConfiguration[] = [publicSubnet, privateSubnet];

    /* Create VPC with the configured networks */
    let vpc: ec2.Vpc = new ec2.Vpc(this, "devices_on_premise_vpc", {
      ipAddresses: ec2.IpAddresses.cidr('10.3.0.0/20'),
      availabilityZones : [this.region+'c'],
      subnetConfiguration: subnetConfigs
    });

    vpc.addFlowLog('scada_on_cloud_vpc_FlowLogS3', {
      destination: ec2.FlowLogDestination.toS3(this.loggingBucket)
    });

    this.onEdgeVPC=vpc;
  }
}