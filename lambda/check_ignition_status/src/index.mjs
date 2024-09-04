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

import https from 'https';
import { SSMClient, SendCommandCommand, PutParameterCommand, GetParameterCommand } from "@aws-sdk/client-ssm"; // ES Modules import
import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2"; // ES Modules import


let IgnitionOnPremHostname=""; 
let IgnitionOnPremBackupHostname="";

let IgnitionCloudId="";
let IgnitionCloudackupId="";

export const handler = async (event) => {
  
    const ssmClient = new SSMClient();
    const ec2Client = new EC2Client();
    
    const getStatus = { Name: "FailoverFlag" };
    let command = new GetParameterCommand(getStatus);
    let failoverStatus = await ssmClient.send(command);
    
    if(failoverStatus.Parameter.Value!="true") {
        
        await getHostnames();
    
        await getInstanceIDs();
      
        const primary = {
            hostname: IgnitionOnPremHostname,
            port: 443,
            path: '/',
            method: 'get',
            rejectUnauthorized: false,
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 500
        };
    
        const backup = {
            hostname: IgnitionOnPremBackupHostname,
            port: 443,
            path: '/',
            method: 'get',
            rejectUnauthorized: false,
            headers: {  
                'Content-Type': 'application/json'
            },
            timeout: 500
        };
    
        console.log("Testing availability of the primary node: ", IgnitionOnPremHostname);
        const primaryStatus = await doRequest(primary);
        console.log("Testing availability of the backup node ", IgnitionOnPremBackupHostname);
        const backupStatus = await doRequest(backup);
    
        if(primaryStatus=="true" || backupStatus=="true") {
    
            console.log("Primary site is currently up and running");
        } else {
            
            console.log(IgnitionCloudId);
            console.log(IgnitionCloudackupId);
    
           const input = {
                "DocumentName": "AWS-RunShellScript",
                "InstanceIds":[IgnitionCloudId,IgnitionCloudackupId],
                "Parameters": {
                    "commands": [
                        "/failover.sh"
                    ]
                }
            };
            console.log("Primary site is currently down, failing over to DR");
            let command = new SendCommandCommand(input);
            await ssmClient.send(command);
            
            const failover = {
              Name: "FailoverFlag",
              Value: "true",
              Type: "String",
              Overwrite: true
            };
            command = new PutParameterCommand(failover);
            await ssmClient.send(command);
        }
    }

    async function getInstanceIDs() {
        
        let output = "";
        let command ="";
        let primaryCloudInput = {Filters: [{ Name: "tag:Name", Values: [ "scada_oncloud_primary" ] }, { Name: "instance-state-name", Values: [ "running"] } ] };
        let backupCloudInput = {Filters: [{ Name: "tag:Name", Values: [ "scada_oncloud_backup" ] }, { Name: "instance-state-name", Values: [ "running"] } ] };

        if(!IgnitionCloudId){   
            
            command = new DescribeInstancesCommand(primaryCloudInput);
            output = await ec2Client.send(command);
            IgnitionCloudId = output.Reservations[0].Instances[0].InstanceId;
        }

        if(!IgnitionCloudackupId){
            
            command = new DescribeInstancesCommand(backupCloudInput);
            output = await ec2Client.send(command);
            IgnitionCloudackupId = output.Reservations[0].Instances[0].InstanceId;
        }
    }

    async function getHostnames() {

        const primaryOnPremInput = { Name: "IgnitionOnPremIP" };
        const backupOnPremInput = { Name: "IgnitionOnPremBackupIP" };

        let command ="";

        //GET Hostnames
        if (!IgnitionOnPremHostname) {
            command = new GetParameterCommand(primaryOnPremInput);
            let primaryOnPremOutput = await ssmClient.send(command);
            IgnitionOnPremHostname = primaryOnPremOutput.Parameter.Value;
        } 

        if (!IgnitionOnPremBackupHostname) {
            command = new GetParameterCommand(backupOnPremInput);
            const backupOnPremOutput = await ssmClient.send(command);
            IgnitionOnPremBackupHostname = backupOnPremOutput.Parameter.Value;
        }
    }
};

function doRequest(options) {
    let OK = "true";
    let KO = "false";
    return new Promise((resolve, reject) => {
        var req = https.request(options, function (res) {

            res.on('data', function (chunk) { console.log("check") });                                                                                                                                                                
            res.on('end', function () {
                if (res.statusCode === 200 || res.statusCode === 302 ) { resolve(OK) }
                else { console.log("error: ", res.statusCode)}
            });
        }).setTimeout(500);
        req.on('error', function (err) { reject(err) }); 
        req.on('timeout', () => { resolve(KO)});
        req.end();
    });
}