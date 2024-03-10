# Copyright Matrix IT CloudZone Ltd. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import boto3
import io
from collections import OrderedDict


ec2_client = boto3.client('ec2')
ec2 = boto3.resource('ec2')

def lambda_handler(event, context):
    """
    This function processes vpc flow log records buffered by Amazon Kinesis Data Firehose. Each record is enriched with additional metadata 
    like resource tags for source & destination IP address. VPC ID, Region, Subnet ID, Interface ID etc. for destination IP address.
    """
    output = []
    instance_id=None
    flow_direction=None
    src_tag_prefix='src-tag-'
    dst_tag_prefix='dst-tag-'
    dst_prefix='dst-'

    instancesecuritygroup_dict = {}
    securitygrouprule_dict = {}
    
    
    vpc_fl_header = "account-id action az-id bytes dstaddr dstport end flow-direction instance-id interface-id log-status packets pkt-dst-aws-service pkt-dstaddr pkt-src-aws-service pkt-srcaddr protocol region srcaddr srcport start sublocation-id sublocation-type subnet-id tcp-flags traffic-path type version vpc-id"

    for record in event['records']:
        # Decode the payload with utf-8 to read the values from the record and enrich it
        payload = base64.b64decode(record['data']).decode('utf-8')

        # Custom processing to enrich the payload
        try:
            json_payload=json.loads(payload)
            
            # Original record from VPC Flow Logs is separated by space delimiter
            flow_log_record=json_payload["message"].split(" ")

            record_dict=OrderedDict({"account-id": flow_log_record[0], "action": flow_log_record[1], "az-id": flow_log_record[2], "bytes": flow_log_record[3], "dstaddr": flow_log_record[4], "dstport": flow_log_record[5], \
            "end": flow_log_record[6], "flow-direction": flow_log_record[7], "instance-id": flow_log_record[8], "interface-id": flow_log_record[9], "log-status": flow_log_record[10], \
            "packets": flow_log_record[11], "pkt-dst-aws-service": flow_log_record[12], "pkt-dstaddr": flow_log_record[13], "pkt-src-aws-service": flow_log_record[14], \
            "pkt-srcaddr": flow_log_record[15], "protocol": flow_log_record[16], "region": flow_log_record[17], "srcaddr": flow_log_record[18], "srcport": flow_log_record[19], \
            "start": flow_log_record[20], "sublocation-id": flow_log_record[21], "sublocation-type": flow_log_record[22], "subnet-id": flow_log_record[23], "tcp-flags": flow_log_record[24], \
            "traffic-path": flow_log_record[25], "type": flow_log_record[26], "version": flow_log_record[27], "vpc-id": flow_log_record[28]})
            
            record_dict['security-groups']="||||no-security-groups"

            instance_id = record_dict['instance-id']
            flow_direction = record_dict['flow-direction']
            
            # Get the resource security groups for instance id from the log record, in case it hadn't gotten them yet for that same instance id in previous records.
            if instance_id:
                if len(instance_id) > 0 and instance_id.strip() != "-" and instancesecuritygroup_dict.get(instance_id) == None:
                    instancesecuritygroup_dict[instance_id] = get_resource_securitygroups(instance_id)
                if instancesecuritygroup_dict[instance_id]:
                    record_dict['security-groups']=""
                    for securitygroup in instancesecuritygroup_dict[instance_id]:
                        # Get the inbound and outbound rules for the security group in case it hadn't gotten them yet for that same security group id in previous records. 
                        if securitygrouprule_dict.get(securitygroup["GroupId"] + "-" + flow_direction) == None:
                            securitygrouprules = get_securitygroup_rules(securitygroup["GroupId"])
                            securitygrouprule_dict[securitygroup["GroupId"] + "-egress"] = securitygrouprules[securitygroup["GroupId"] + "-egress"] 
                            securitygrouprule_dict[securitygroup["GroupId"] + "-ingress"] = securitygrouprules[securitygroup["GroupId"] + "-ingress"]
                        
                        if record_dict['security-groups'] != "":
                            record_dict['security-groups'] = record_dict['security-groups'] + ";"
                        record_dict['security-groups'] = record_dict['security-groups'] + securitygrouprule_dict[securitygroup["GroupId"] + "-" + flow_direction]

            # Finally modify the payload with enriched record
            payload=json.dumps(record_dict) + "\n"
        except Exception as ex:
            print('Could not process record, Exception: ', ex)
            output_record = {
                'recordId': record['recordId'],
                'result': 'ProcessingFailed',
                'data': base64.b64encode(payload.encode('utf-8')).decode('utf-8')
            }
        else:
            # Assign the enriched record to the output_record for Kinesis to process it further
            output_record = {
                'recordId': record['recordId'],
                'result': 'Ok',
                'data': base64.b64encode(payload.encode('utf-8')).decode('utf-8')
            }
            
        output.append(output_record)

    print('Security Groups described for {} distinct instances.'.format(len(instancesecuritygroup_dict.keys())))
    print('Successfully processed {} records.'.format(len(event['records'])))

    return {'records': output}
    
def get_resource_securitygroups(resource_id):
    
    # This function fetches resource security groups for resource_id parameter using boto3
    
    resource_securitygroups=None
    try:
        ec2 = boto3.resource('ec2')
        ec2instance = ec2.Instance(resource_id)
        resource_securitygroups=ec2instance.security_groups
    except Exception as ex:
        print('Exception get_resource_securitygroups: ', ex)
        
    return resource_securitygroups

def get_securitygroup_rules(securitygroup_id):
    
    # This function using boto3 fetches security group rules for the securitygroup_id parameter, returning always dictionary with two keys: 
    # "securitygroup_id-ingress", with a string of concatenated security group's inbound rules (if Not IsEgress) separated by ";", each rule a concatenated string of "SecurityGroupRuleId|IpProtocol|FromPort-ToPort|CidrIpv4|securitygroup_id"
    # "securitygroup_id-egress", with a string of concatenated security group's outbound rules (if IsEgress) separated by ";", each rule a concatenated string of "SecurityGroupRuleId|IpProtocol|FromPort-ToPort|CidrIpv4|securitygroup_id"
    
    securitygrouprules = {securitygroup_id + "-egress" : "", securitygroup_id + "-ingress" : ""}
    #print(securitygrouprules)

    describe_sg_rules=None
    sg_rules=None

    protocol=""
    portRange = ""
    ruleDetail = ""

    
    try:
        ec2_client = boto3.client('ec2')
        
        describe_sg_rules=ec2_client.describe_security_group_rules(Filters=[{'Name':'group-id','Values':[securitygroup_id]}])
        sg_rules=describe_sg_rules["SecurityGroupRules"]
        
        if sg_rules:
            for rule in sg_rules:
                portRange = str(rule["FromPort"])
                if portRange != str(rule["ToPort"]):
                    portRange = portRange + "-" + str(rule["ToPort"])
                
                protocol = rule["IpProtocol"]
                if protocol =="-1":
                    protocol="All protocols"
                if portRange=="-1":
                    portRange="All ports"

                ruleDetail=rule["SecurityGroupRuleId"] + "|" + protocol + "|" + portRange + "|" + rule["CidrIpv4"] + "|" + securitygroup_id
                
                if rule["IsEgress"]:
                    if securitygrouprules[securitygroup_id + "-egress"] == "":
                        securitygrouprules[securitygroup_id + "-egress"]=ruleDetail
                    else:
                        securitygrouprules[securitygroup_id + "-egress"]=securitygrouprules[securitygroup_id + "-egress"] + ";" + ruleDetail
                if not(rule["IsEgress"]):
                    if securitygrouprules[securitygroup_id + "-ingress"] == "":
                        securitygrouprules[securitygroup_id + "-ingress"]=ruleDetail
                    else:
                        securitygrouprules[securitygroup_id + "-ingress"]=securitygrouprules[securitygroup_id + "-ingress"] + ";" + ruleDetail
        
        # if at the end, there weren't any outbound rules, it still returns outbound rule record with 'no-outbound-rules'.
        if securitygrouprules[securitygroup_id + "-egress"] == "":
            securitygrouprules[securitygroup_id + "-egress"] = "no-outbound-rules||||" + securitygroup_id
        # if at the end, there weren't any inbound rules, it still returns inbound rule record with 'no-inbound-rules'.
        if securitygrouprules[securitygroup_id + "-ingress"] == "":
            securitygrouprules[securitygroup_id + "-ingress"] = "no-inbound-rules||||" + securitygroup_id
 
    except Exception as ex:
        print('Exception get_securitygroup_rules: ', ex)
    return securitygrouprules
