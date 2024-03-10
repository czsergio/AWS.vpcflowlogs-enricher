# AWS VPC Flow Log enriching with Security Groups details
Amazon VPC Flow log enricher to complement log records with instance details such as assigned Security Groups and Inbound/Outbound rules.

# Overview

Activating and analysing VPC Flow Logs for an Amazon VPC, allows to understand better the network traffic flows - from and to every network interface of its compute instances. However, sometimes it's not that easy to understand some of the allowed or rejected traffic flows without taking into consideration the settings of inbound and outbound rules of the Security Groups assigned to the end instances of that flow. Also, most of the log analysis tools or SIEMs do not support to join distinct sources of data into a unified view. Thus, it is required to enrich the VPC Flow Log records with additional information of the Security Group settings for the source instance (of the Egress traffic flow) or target instance (of the Ingress traffic flow).

For example, consider the following settings for Security Groups assigned to an EC2 instance.

![Ec2-sg](/images/EC2-sg.png)

So, for an Ingress log record with that EC2 instance as a target, it should be added the following attribute list:

![EC2-sg-list-to-enrich-vpc-flow-log](/images/EC2-sg-list-vpcfl.png)

That is implemented by the [AWS Lambda](https://aws.amazon.com/lambda/) function [vpcfl-securitygroups](/functions/vpcfl-securitygroups.py), using the [boto3](https://pypi.org/project/boto3/) AWS SDK for [Python](https://www.python.org/downloads/).


The high-level architecture will look like this:

![HLDarchitecture](/images/HLDarchitecture.png "High-Level Architecture")

# Deployment

### 1. Create the Amazon S3 bucket
It will be set as the target of the Amazon Data Firehose delivery stream.

### 2. Create the enriching AWS Lambda Function

i) Create a function, selecting the **Author from scratch** option.

ii) Choose the last Python version for *Runtime* and x86_64 for *Architecture*.

iii) Select to **Create a new role with basic Lambda permissions** for its execution role.

iv) Import this [/functions/vpcfl-securitygroups.py](/functions/vpcfl-securitygroups.py) code and deploy it.

v) Create an IAM policy with this [/deploy/iam-policy-Ec2ServicePolicy-Describe-SecurityGroups.json](/deploy/iam-policy-Ec2ServicePolicy-Describe-SecurityGroups.json) code and attach it to the AWS Lambda execution IAM role generated in the previous step.

### 3. Set the Amazon Data Firehose delivery stream

i) Create a Firehose stream with **Direct PUT** as *Source* and **Amazon S3** as *Destination*.

ii) **Turn on data transformation** selecting the AWS Lambda function created previously.

iii) Customise or keep defaults for *Buffer size* and *Buffer interval*. They can be customised later as per the Operational Excellence considerations below.

iv) Customise or keep the default record format depending on the tools to be used for analysing the VPC Flow Logs.

v) Browse the Amazon *S3 bucket* created previously as the destination.

vi) A *New line delimiter* can be **Enabled** between stream records.

vii) For S3 *Buffer size* and *Buffer interval* defaults can be kept for a first setup but depending on the amount of traffic to analyse and the capability of the analysis tools to process, they can be set until the allowed maximum values for optimizing data archival and save processing cost.

viii) It is recommended to set **GZIP** as *Compression for data records* for saving data storage.

### 4. Create the Amazon VPC Flow Log

i) In the intended Amazon VPC, choose to **Create flow log**.

ii) *Filter* the type of traffic to be captured (**Accept**, **Reject**, or **All**).

iii) Select **1 minute** for *Maximum aggregation interval* if analysis to be performed near-realtime, or ** 10 minutes** otherwise.

iv) Select to **Send to Amazon Data Firehose in the same account** (or **Send to Amazon Data Firehose in a different account**) and choose the Amazon Firehose stream set previously.

v) For the *log record format* select **Custom format** and then **Select all** attributes for this enriching AWS Lambda function to be used *as-is*.

> In case it is only required just a few attributes for analysis, this enriching AWS Lambda function code can be easily adapted when setting the **record_dict** Python dictionary from the **flow_log_record** list that is assigned with the VPC Flow Log record.


# Well-architected considerations

## 1. Operational Excellence

Enabling Data transformation in the delivery stream when associating to this enriching Lambda function ensures the entire VPC Flow Log payload is processed without any complexity neither operational overhead. 

Considering the VPC Flow log target will be an Amazon S3 bucket, it will be a pretty scalable solution because there won't be space limits for files store.

For the Lambda function, the execution timeout might not be relevant for the maximum payload a delivery stream can incurr to but it is relevant to monitor in Cloudwatch Logs the trends of memory usage to avoid overspending with the Amazon Lambda service as well as the limit of AWS API invocations for getting the details to enrich the VPC Flow Log.

Cloudwatch Logs should be used for monitoring the generation and buffering of the delivery stream of the Data Firehose as well as the execution of the enriching Lambda function. Thresholds for buffer size (number of records the delivery stream will buffer before it flushes it to Amazon S3) and buffer interval (number of seconds the delivery stream will buffer the incoming VPC Flow Log's records) can be set in CloudWatch Alarms for optimizing their settings as long as the network traffic increases.

As long as the number of instances and security groups' rules will increase, Amazon ElastiCache can be leveraged for keeping a track record of their updated configuration, if it is not subject to be modified quite often. In that case, the Lambda function should be then adapted for retrieving that information from ElastiCache, instead of retrieving it as long as new instance id or security group show up for processing.

## 2. Security

All the Amazon Web Services running and interoperating in this architecture are executed under IAM roles with stricted permissions specified in their policies according to the least privileged principle.

This enriching Lambda function's execution role is assigned an IAM **describe-sg-policy** with the following permission for a very limited set of actions over Amazon EC2 instances.

![ec2-describe-policy](/images/IAMec2-describe-policy.png "EC2 describe policy to add to the Lambda execution role")

The same least privileged principle should apply for the execution IAM role generated when setting the Amazon Data Firehose stream.

Security best practices should also be implemented such as for securing the target S3 bucket or any further ingestion to external tools, leveraging as much as possible Secrets Manager encryption keys and HTTPS communication for data transfer, or even VPC gateway endpoint if running withing the AWS cloud.

## 3. Reliability

This is a full serverless solution leveraging Amazon Web Services with built-in reliability.

## 4. Performance Efficiency

There are two important limits to consider that might hit, depending on the applicable scenario:
1. **The number of AWS API invocations and frequency** for getting the data about the resources with the boto3 Python library.

Every security group's details and its inbound and outbound rules settings are retrieved only once during each Lambda execution as long as there is a new instance id in the log payload being processed. They and cached in memory in the form of Python dictionaries data structures that are natively optimized for local runtime processing of transitory and finite space of data.

2. **The limits of the Amazon Data Firehose**

It is recommended to take a look to the quota consideration for the service in the [Amazon Data Firehose developer guide](https://docs.aws.amazon.com/firehose/latest/dev/limits.html).

## 5. Cost Optimization

It is recommended to reduce the payload for the Data Firehose stream, selecting only the relevant fields from the VPC Flow log according to the analysis at scope. This will save the amount of data being handled and stored so it will reduce significantly the charges for data stored as well as data transfer to external SIEM to where the data streams are being ingested.

In this architecture, it was relevant to enrich the VPC Flow Log in real time with the security groups' rules for the origin and target instances for every shard being generated. In other cases with more relaxed processing requirements - less traffic and on-demand/off-line analysis only, this processing lambda function can be adapted to be called only at the preparation of that analysis to process VPC Flow logs files that should be stored in the S3 bucket as pending for enrichment.

Cost-wise, if this solution will be implemented to be continuously running, it is critical to handle data throught a [VPC gateway endpoint for S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html) whenever the analysis is performed with non-AWS native tools. Otherwise, data transfer will be a weight charge in the TCO for this solution.

For data archival, it can also be select S3 Intelligent-tiering storage class or S3 Standard - Infrequent Access storage class since the need for reprocessing is barely none, mainly if the environment is auto-scaled often. If that is the case, bare in mind that at the time of processing an "old" VPC flow log it might happen that the enriching lambda function will not find at that moment a particular instance id recorded in the flow log because it has already been terminated when scaling in the Workload's autoscaling group of nodes.

## 6. Sustainability

Implementing this VPC flow logs enricher according to the best practices described and recommended above leveraging those AWS serverless services, the carbon footprint will be minimal provided that services will run, and amount of data will be processed and stored, in the same proportion of the network traffic being generated within the VPC at scope.

If the analysis over the VPC Flow Logs is not required to be in real time, the proposed architecture can be modified to discard the Amazon Data Firehose stream with data transformation built-in, and use the Lambda function to process pending VPC Flow Log files set to be put directly in the Amazon S3 bucket. Thus, Amazon Data Firehose won't be required and the enriching Lambda function will run fewer times, only as part of a pre-analysis setup phase to process all pending files at once.

Moreover, the Python code in this enriching Lambda function has leveraged optimized data structures and development best practices recommended by the Green Software Foundation. However, since it was not the purpose of this implementation to apply VPC Flow Log enrichment continuously but only for investigation, it is recommended a careful study of those GSF recommended best practices for further improvement.