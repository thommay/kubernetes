/*
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws_cloud

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"code.google.com/p/gcfg"
	"github.com/golang/glog"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
	"github.com/mitchellh/goamz/elb"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/cloudprovider"
)

type EC2 interface {
	AuthorizeSecurityGroup(group ec2.SecurityGroup, perms []ec2.IPPerm) (resp *ec2.SimpleResp, err error)
	CreateSecurityGroup(group ec2.SecurityGroup) (resp *ec2.CreateSecurityGroupResp, err error)
	DescribeSubnets(subnetIds []string, filter *ec2.Filter) (resp *ec2.SubnetsResp, err error)
	DescribeVpcs(vpcIds []string, filter *ec2.Filter) (resp *ec2.VpcsResp, err error)
	Instances(instIds []string, filter *ec2.Filter) (resp *ec2.InstancesResp, err error)
	SecurityGroups(groups []ec2.SecurityGroup, filter *ec2.Filter) (resp *ec2.SecurityGroupsResp, err error)
}

type AwsMetadata interface {
	GetInstanceAz() (string, error)
}

// AWSCloud is an implementation of Interface, TCPLoadBalancer and Instances for Amazon Web Services.
type AWSCloud struct {
	auth             aws.Auth
	availabilityZone string
	cfg              *AWSCloudConfig
	ec2              EC2
	metadata         AwsMetadata
	region           *aws.Region
}

type AWSCloudConfig struct {
	Global struct {
		VpcName string `gcfg:"vpc-name"`
		Region  string
	}
}

type AuthFunc func() (auth aws.Auth, err error)

func init() {
	cloudprovider.RegisterCloudProvider("aws", func(config io.Reader) (cloudprovider.Interface, error) {
		return newAWSCloud(config, &instanceMetadata{}, getAuth)
	})
}

func getAuth() (auth aws.Auth, err error) {
	return aws.GetAuth("", "")
}

// readAWSCloudConfig reads an instance of AWSCloudConfig from config reader.
func readAWSCloudConfig(config io.Reader) (*AWSCloudConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("no AWS cloud provider config file given")
	}

	var cfg AWSCloudConfig
	err := gcfg.ReadInto(&cfg, config)
	if err != nil {
		return nil, err
	}

	if cfg.Global.Region == "" {
		return nil, fmt.Errorf("no region specified in configuration file")
	}

	return &cfg, nil
}

// newAWSCloud creates a new instance of AWSCloud.
func newAWSCloud(config io.Reader, metadata AwsMetadata, authFunc AuthFunc) (*AWSCloud, error) {
	cfg, err := readAWSCloudConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to read AWS cloud provider config file: %v", err)
	}

	auth, err := authFunc()
	if err != nil {
		return nil, err
	}

	availabilityZone, err := metadata.GetInstanceAz()
	if err != nil {
		return nil, err
	}

	var reg string
	if availabilityZone != "" {
		// the region is the AZ minus the last character
		reg = availabilityZone[:len(availabilityZone)-1]
	} else {
		reg = cfg.Global.Region
	}
	region, ok := aws.Regions[reg]
	if !ok {
		return nil, fmt.Errorf("not a valid AWS region: %s", reg)
	}

	ec2 := ec2.New(auth, region)
	return &AWSCloud{
		auth:             auth,
		availabilityZone: availabilityZone,
		cfg:              cfg,
		ec2:              ec2,
		metadata:         &instanceMetadata{},
		region:           &region,
	}, nil
}

func (aws *AWSCloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// TCPLoadBalancer returns an implementation of TCPLoadBalancer for Amazon Web Services.
func (aws *AWSCloud) TCPLoadBalancer() (cloudprovider.TCPLoadBalancer, bool) {
	return aws, true
}

// Instances returns an implementation of Instances for Amazon Web Services.
func (aws *AWSCloud) Instances() (cloudprovider.Instances, bool) {
	return aws, true
}

// Zones returns an implementation of Zones for Amazon Web Services.
func (aws *AWSCloud) Zones() (cloudprovider.Zones, bool) {
	return aws, true
}

// IPAddress is an implementation of Instances.IPAddress.
func (aws *AWSCloud) IPAddress(name string) (net.IP, error) {
	f := ec2.NewFilter()
	f.Add("private-dns-name", name)
	instance, err := aws.getInstanceByFilter(name, f)
	if err != nil {
		return nil, err
	}

	ipAddress := instance.PrivateIpAddress
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid network IP: %s", ipAddress)
	}
	return ip, nil
}

func (aws *AWSCloud) getInstanceByFilter(name string, f *ec2.Filter) (*ec2.Instance, error) {
	resp, err := aws.ec2.Instances(nil, f)
	if err != nil {
		return nil, err
	}
	if len(resp.Reservations) == 0 {
		return nil, fmt.Errorf("no reservations found for host: %s", name)
	}
	if len(resp.Reservations) > 1 {
		return nil, fmt.Errorf("multiple reservations found for host: %s", name)
	}
	if len(resp.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("no instances found for host: %s", name)
	}
	if len(resp.Reservations[0].Instances) > 1 {
		return nil, fmt.Errorf("multiple instances found for host: %s", name)
	}

	return &resp.Reservations[0].Instances[0], nil
}

// Return a list of instances matching regex string.
func (aws *AWSCloud) getInstancesByRegex(regex string) ([]string, error) {
	resp, err := aws.ec2.Instances(nil, nil)
	if err != nil {
		return []string{}, err
	}
	if resp == nil {
		return []string{}, fmt.Errorf("no InstanceResp returned")
	}

	re, err := regexp.Compile(regex)
	if err != nil {
		return []string{}, err
	}

	instances := []string{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			for _, tag := range instance.Tags {
				if tag.Key == "Name" && re.MatchString(tag.Value) {
					instances = append(instances, instance.PrivateDNSName)
					break
				}
			}
		}
	}
	return instances, nil
}

// List is an implementation of Instances.List.
func (aws *AWSCloud) List(filter string) ([]string, error) {
	// TODO: Should really use tag query. No need to go regexp.
	return aws.getInstancesByRegex(filter)
}

func (self *AWSCloud) findInstance(name string) (*ec2.Instance, error) {
	f := ec2.NewFilter()
	// we might receive a straight up IP, or a hostname.
	ip := net.ParseIP(name)
	if ip == nil {
		f.Add("private-dns-name", name)
	} else {
		f.Add("private-ip-address", name)
	}
	return self.getInstanceByFilter(name, f)
}

func (self *AWSCloud) findVpc() (*ec2.VPC, error) {
	f := ec2.NewFilter()
	f.Add("tag:Name", self.cfg.Global.VpcName)

	ids := []string{}
	resp, err := self.ec2.DescribeVpcs(ids, f)
	if err != nil {
		glog.Error("error listing VPCs ", err)
		return nil, err
	}

	vpcs := resp.VPCs
	if len(vpcs) == 0 {
		return nil, nil
	}

	if len(vpcs) > 1 {
		glog.Warning("Found multiple VPCs; picking arbitrarily", vpcs)
		return &vpcs[0], nil
	}

	return &vpcs[0], nil
}

func (v *AWSCloud) GetNodeResources(name string) (*api.NodeResources, error) {
	return nil, nil
}

func (aws *AWSCloud) GetZone() (cloudprovider.Zone, error) {
	return cloudprovider.Zone{
		FailureDomain: aws.availabilityZone,
		Region:        aws.region.Name,
	}, nil
}

func (self *AWSCloud) getElbClient(regionName string) (*elb.ELB, error) {
	region, ok := aws.Regions[regionName]
	if !ok {
		return nil, fmt.Errorf("not a valid AWS region: %s", regionName)
	}
	return elb.New(self.auth, region), nil
}

func (self *AWSCloud) describeLoadBalancer(client *elb.ELB, name string) (*elb.LoadBalancer, error) {
	request := &elb.DescribeLoadBalancer{}
	request.Names = []string{name}
	response, err := client.DescribeLoadBalancers(request)
	if err != nil {
		elbError, ok := err.(*elb.Error)
		if ok && elbError.Code == "LoadBalancerNotFound" {
			return nil, nil
		}
		glog.Error("error describing load balancer: ", err)
		return nil, err
	}

	var ret *elb.LoadBalancer
	for _, loadBalancer := range response.LoadBalancers {
		ret = &loadBalancer
	}
	return ret, nil
}

func (self *AWSCloud) TCPLoadBalancerExists(name, region string) (bool, error) {
	client, err := self.getElbClient(region)
	if err != nil {
		return false, err
	}

	lb, err := self.describeLoadBalancer(client, name)
	if err != nil {
		return false, err
	}

	if lb != nil {
		return true, nil
	}

	return false, nil
}

func (self *AWSCloud) hostsToInstances(hosts []string) ([]*ec2.Instance, error) {
	instances := []*ec2.Instance{}
	for _, host := range hosts {
		instance, err := self.findInstance(host)
		if err != nil {
			return nil, err
		}
		if instance == nil {
			return nil, fmt.Errorf("unable to find instance " + host)
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

func mapToInstanceIds(instances []*ec2.Instance) []string {
	ids := []string{}
	for _, instance := range instances {
		ids = append(ids, instance.InstanceId)
	}
	return ids
}

func (self *AWSCloud) describeSubnets(subnetIds []string, filter *ec2.Filter) (*ec2.SubnetsResp, error) {
	subnets, err := self.ec2.DescribeSubnets(subnetIds, filter)
	if err != nil {
		glog.Error("error listing subnets", err)
		return nil, err
	}

	return subnets, nil
}

func (self *AWSCloud) findSecurityGroups(filter *ec2.Filter) ([]ec2.SecurityGroupInfo, error) {
	response, err := self.ec2.SecurityGroups([]ec2.SecurityGroup{}, filter)
	if err != nil {
		return nil, err
	}

	return response.Groups, nil
}

func (self *AWSCloud) createSecurityGroup(vpcId, name, description string) (string, error) {
	request := ec2.SecurityGroup{}
	request.VpcId = vpcId
	request.Name = name
	request.Description = description
	response, err := self.ec2.CreateSecurityGroup(request)
	if err != nil {
		return "", err
	}

	return response.Id, nil
}

func (self *AWSCloud) ensureSecurityGroupIngress(securityGroupId string, sourceIp string, protocol string, fromPort, toPort int) (bool, error) {
	groupSpec := ec2.SecurityGroup{Id: securityGroupId}
	findGroups := []ec2.SecurityGroup{groupSpec}
	response, err := self.ec2.SecurityGroups(findGroups, nil)
	if err != nil {
		glog.Warning("error retrieving security group", err)
		return false, err
	}

	if len(response.Groups) == 0 {
		return false, fmt.Errorf("security group not found")
	}
	group := response.Groups[0]

	for _, permission := range group.IPPerms {
		if permission.FromPort != fromPort {
			continue
		}
		if permission.ToPort != toPort {
			continue
		}
		if len(permission.SourceIPs) != 1 {
			continue
		}
		if permission.SourceIPs[0] != sourceIp {
			continue
		}
		return false, nil
	}
	newPermission := ec2.IPPerm{}
	newPermission.FromPort = fromPort
	newPermission.ToPort = toPort
	newPermission.Protocol = protocol
	newPermission.SourceIPs = []string{sourceIp}

	newPermissions := []ec2.IPPerm{newPermission}
	_, err = self.ec2.AuthorizeSecurityGroup(groupSpec, newPermissions)
	if err != nil {
		glog.Warning("error authorizing security group ingress", err)
		return false, err
	}

	return true, nil
}

// CreateTCPLoadBalancer is an implementation of TCPLoadBalancer.CreateTCPLoadBalancer.
func (self *AWSCloud) CreateTCPLoadBalancer(name, region string, externalIP net.IP, port int, hosts []string, affinityType api.AffinityType) (*cloudprovider.LoadBalancerInfo, error) {
	instances, err := self.hostsToInstances(hosts)
	if err != nil {
		return nil, err
	}

	client, err := self.getElbClient(region)
	if err != nil {
		return nil, err
	}

	vpc, err := self.findVpc()
	if err != nil {
		return nil, err
	}

	if vpc == nil {
		return nil, fmt.Errorf("Unable to find VPC")
	}

	subnetIds := []string{}
	{
		f := ec2.NewFilter()
		f.Add("vpc-id", vpc.VpcId)
		subnets, err := self.describeSubnets(nil, f)
		if err != nil {
			glog.Error("error listing subnets", err)
			return nil, err
		}

		for _, subnet := range subnets.Subnets {
			subnetIds = append(subnetIds, subnet.SubnetId)
			if !strings.HasPrefix(subnet.AvailabilityZone, region) {
				glog.Error("found AZ that did not match region", subnet.AvailabilityZone, "vs", region)
				return nil, fmt.Errorf("invalid AZ for region")
			}
		}
	}

	var loadBalancerName, dnsName string
	{
		loadBalancer, err := self.describeLoadBalancer(client, name)

		if err != nil {
			return nil, err
		}

		if loadBalancer == nil {
			createRequest := &elb.CreateLoadBalancer{}
			createRequest.LoadBalancerName = name

			listener := elb.Listener{}
			listener.InstancePort = int64(port)
			listener.LoadBalancerPort = int64(port)
			listener.Protocol = "tcp"
			listener.InstanceProtocol = "tcp"
			createRequest.Listeners = []elb.Listener{listener}
			createRequest.Subnets = subnetIds

			sgName := "k8s-elb-" + name
			sgDescription := "Security group for Kubernetes ELB " + name

			{
				f := ec2.NewFilter()
				f.Add("vpc-id", vpc.VpcId)
				f.Add("group-name", sgName)

				securityGroups, err := self.findSecurityGroups(f)
				if err != nil {
					return nil, err
				}

				var securityGroupId string
				for _, securityGroup := range securityGroups {
					securityGroupId = securityGroup.Id
				}
				if securityGroupId == "" {
					securityGroupId, err = self.createSecurityGroup(vpc.VpcId, sgName, sgDescription)
					if err != nil {
						return nil, err
					}
				}

				_, err = self.ensureSecurityGroupIngress(securityGroupId, "0.0.0.0/0", "tcp", port, port)

				if err != nil {
					return nil, err
				}
				createRequest.SecurityGroups = []string{securityGroupId}
			}

			if len(externalIP) > 0 {
				return nil, fmt.Errorf("External IP cannot be specified for AWS ELB")
			}
			createResponse, err := client.CreateLoadBalancer(createRequest)
			if err != nil {
				return nil, err
			}

			dnsName = createResponse.DNSName
			loadBalancerName = name
		} else {
			loadBalancerName = loadBalancer.LoadBalancerName
			dnsName = loadBalancer.DNSName
		}

		registerRequest := &elb.RegisterInstancesWithLoadBalancer{}
		registerRequest.LoadBalancerName = loadBalancerName
		registerRequest.Instances = mapToInstanceIds(instances)

		registerResponse, err := client.RegisterInstancesWithLoadBalancer(registerRequest)
		if err != nil {
			return nil, err
		}

		glog.V(1).Info("Updated instances registered with load-balancer", name, registerResponse.Instances)

		loadBalancerInfo := &cloudprovider.LoadBalancerInfo{}
		loadBalancerInfo.ExternalDnsName = dnsName
		return loadBalancerInfo, nil
	}
}

func (self *AWSCloud) UpdateTCPLoadBalancer(name, region string, hosts []string) error {
	instances, err := self.hostsToInstances(hosts)
	if err != nil {
		return err
	}

	client, err := self.getElbClient(region)
	if err != nil {
		return err
	}

	lb, err := self.describeLoadBalancer(client, name)
	if err != nil {
		return err
	}

	if lb == nil {
		return fmt.Errorf("Load balancer not found")
	}

	existingInstances := map[string]*elb.Instance{}
	for _, instance := range lb.Instances {
		existingInstances[instance.InstanceId] = &instance
	}

	wantInstances := map[string]*ec2.Instance{}
	for _, instance := range instances {
		wantInstances[instance.InstanceId] = instance
	}

	addInstances := []string{}
	for key := range wantInstances {
		_, found := wantInstances[key]
		if !found {
			addInstances = append(addInstances, key)
		}
	}

	removeInstances := []string{}
	for key := range existingInstances {
		_, found := wantInstances[key]
		if !found {
			removeInstances = append(removeInstances, key)
		}
	}

	if len(addInstances) > 0 {
		registerRequest := &elb.RegisterInstancesWithLoadBalancer{}
		registerRequest.Instances = addInstances
		registerRequest.LoadBalancerName = lb.LoadBalancerName
		_, err = client.RegisterInstancesWithLoadBalancer(registerRequest)
		if err != nil {
			return err
		}
	}

	if len(removeInstances) > 0 {
		deregisterRequest := &elb.DeregisterInstancesFromLoadBalancer{}
		deregisterRequest.Instances = removeInstances
		deregisterRequest.LoadBalancerName = lb.LoadBalancerName
		_, err = client.DeregisterInstancesFromLoadBalancer(deregisterRequest)
		if err != nil {
			return err
		}
	}

	return nil
}

func (self *AWSCloud) DeleteTCPLoadBalancer(name, region string) error {
	client, err := self.getElbClient(region)
	if err != nil {
		return err
	}

	request := &elb.DeleteLoadBalancer{}
	request.LoadBalancerName = name
	_, err = client.DeleteLoadBalancer(request)
	if err != nil {
		return err
	}

	return nil
}

type instanceMetadata struct{}

func (*instanceMetadata) GetInstanceAz() (az string, err error) {
	path := "placement/availability-zone"

	data, err := aws.GetMetaData(path)
	if err != nil {
		glog.Error("unable to fetch az from EC2 metadata", err)
		return "", err
	}
	return string(data), nil
}
