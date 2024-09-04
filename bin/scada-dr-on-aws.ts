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

import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CloudScadaDrOnAwsStack } from '../lib/scada-dr-on-aws-oncloud-stack';
import { OnpremScadaDrOnAwsStack } from '../lib/scada-dr-on-aws-onprem-stack';
import { AwsSolutionsChecks } from 'cdk-nag'
import { Aspects } from 'aws-cdk-lib';
import { NagSuppressions } from 'cdk-nag'

const app = new cdk.App();

const cloudRegion = 'us-east-1' 
const onPremRegion = 'us-west-2' 

const cloudStackName = 'CloudScadaDrOnAwsStack-'+cloudRegion;
const onPremStackName = 'OnpremScadaDrOnAwsStack-'+onPremRegion;

// Create the stack for the North Virginia (us-east-1) region
let cloud = new CloudScadaDrOnAwsStack(app, cloudStackName, onPremRegion, {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: cloudRegion }, crossRegionReferences: true,
});

// Create the stack for the Oregon (us-west-2) region
let onprem = new OnpremScadaDrOnAwsStack(app, onPremStackName, cloudStackName, cloudRegion, cloud, {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: onPremRegion } , crossRegionReferences: true});

Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }))

cdk.Tags.of(cloud).add("owner", "scada-dr-on-aws-cdk");
cdk.Tags.of(onprem).add("owner", "scada-dr-on-aws-cdk");