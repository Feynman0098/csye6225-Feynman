package myproject;

import com.pulumi.Context;
import com.pulumi.Pulumi;
import com.pulumi.asset.FileArchive;
import com.pulumi.aws.AwsFunctions;
import com.pulumi.aws.acm.Certificate;
import com.pulumi.aws.acm.CertificateArgs;
import com.pulumi.aws.autoscaling.Group;
import com.pulumi.aws.autoscaling.GroupArgs;
import com.pulumi.aws.autoscaling.inputs.GroupLaunchTemplateArgs;
import com.pulumi.aws.autoscaling.inputs.GroupTagArgs;
import com.pulumi.aws.cloudwatch.LogGroup;
import com.pulumi.aws.cloudwatch.LogGroupArgs;
import com.pulumi.aws.cloudwatch.MetricAlarm;
import com.pulumi.aws.cloudwatch.MetricAlarmArgs;
import com.pulumi.aws.dynamodb.Table;
import com.pulumi.aws.dynamodb.TableArgs;
import com.pulumi.aws.dynamodb.inputs.TableAttributeArgs;
import com.pulumi.aws.ec2.*;
import com.pulumi.aws.ec2.inputs.LaunchTemplateIamInstanceProfileArgs;
import com.pulumi.aws.ec2.inputs.LaunchTemplateNetworkInterfaceArgs;
import com.pulumi.aws.iam.*;
import com.pulumi.aws.lambda.*;
import com.pulumi.aws.lambda.inputs.FunctionEnvironmentArgs;
import com.pulumi.aws.lb.*;
import com.pulumi.aws.lb.inputs.ListenerDefaultActionArgs;
import com.pulumi.aws.lb.inputs.TargetGroupHealthCheckArgs;
import com.pulumi.aws.rds.ParameterGroup;
import com.pulumi.aws.rds.ParameterGroupArgs;
import com.pulumi.aws.rds.SubnetGroup;
import com.pulumi.aws.rds.SubnetGroupArgs;
import com.pulumi.aws.rds.inputs.ParameterGroupParameterArgs;
import com.pulumi.aws.route53.RecordArgs;
import com.pulumi.aws.route53.inputs.RecordAliasArgs;
import com.pulumi.aws.sns.Topic;
import com.pulumi.aws.sns.TopicArgs;
import com.pulumi.aws.sns.TopicSubscription;
import com.pulumi.aws.sns.TopicSubscriptionArgs;
import com.pulumi.core.Output;
import com.pulumi.gcp.serviceaccount.Account;
import com.pulumi.gcp.serviceaccount.AccountArgs;
import com.pulumi.gcp.serviceaccount.Key;
import com.pulumi.gcp.serviceaccount.KeyArgs;
import com.pulumi.gcp.storage.Bucket;
import com.pulumi.gcp.storage.inputs.BucketState;
import com.pulumi.resources.CustomResourceOptions;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.DoubleStream;

import static com.pulumi.codegen.internal.Serialization.*;

public class App {
    public static void main(String[] args) {
        Pulumi.run(App::stack);
    }

    public static void stack(Context ctx) {
        final var current = AwsFunctions.getRegion();
        var config = ctx.config();
        // Create Google Bucket
        String bucketId = config.require("bucketName");
        Output<String> myOutputString = Output.of(bucketId);
        var existingBucket = Bucket.get("my-bucket", myOutputString, BucketState.Empty, CustomResourceOptions.Empty);
        var serviceAccount = new Account("serviceAccount", AccountArgs.builder()
                .accountId("service-account-id")
                .displayName("Service Account")
                .build());

        // Create SNS
        var snsTopic = new Topic("snsTopic", TopicArgs.builder()
                .build());

        serviceAccount.email().apply(email -> {
            var iamMember = new com.pulumi.gcp.projects.IAMMember("my-service-account-iam", com.pulumi.gcp.projects.IAMMemberArgs.builder()
                    .member("serviceAccount:"+email)
                    .role("roles/storage.objectUser")
                    .project(config.require("projectName"))
                    .build());

            var serviceAccountKey = new Key("my-service-account-key", KeyArgs.builder()
                    .serviceAccountId(serviceAccount.accountId())
                    .privateKeyType("TYPE_GOOGLE_CREDENTIALS_FILE")
                    .build());

            // Create IAM
            var lambdaRole = new Role("lambdaRole", RoleArgs.builder()
                    .assumeRolePolicy(serializeJson(
                            jsonObject(
                                    jsonProperty("Version", "2012-10-17"),
                                    jsonProperty("Statement", jsonArray(jsonObject(
                                            jsonProperty("Action", "sts:AssumeRole"),
                                            jsonProperty("Effect", "Allow"),
                                            jsonProperty("Sid", ""),
                                            jsonProperty("Principal", jsonObject(
                                                    jsonProperty("Service", "lambda.amazonaws.com")
                                            ))
                                    )))
                            )))
                    .tags(Map.of("role-name", "lambda-role"))
                    .build());

            var dynamoDbPolicyAttachment = new RolePolicyAttachment("myDynamoDbPolicyAttachment",
                    RolePolicyAttachmentArgs.builder()
                            .role(lambdaRole.name())
                            .policyArn("arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess")
                            .build());

            var sesPolicyAttachment = new RolePolicyAttachment("mySesPolicyAttachment",
                    RolePolicyAttachmentArgs.builder()
                            .role(lambdaRole.name())
                            .policyArn("arn:aws:iam::aws:policy/AmazonSESFullAccess")
                            .build());
            var lambdaPolicyAttachment = new RolePolicyAttachment("myLambdaPolicyAttachment",
                    RolePolicyAttachmentArgs.builder()
                            .role(lambdaRole.name())
                            .policyArn("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
                            .build());

            var lambdaRoleProfile = new InstanceProfile("lambdaRoleProfile", InstanceProfileArgs.builder()
                    .role(lambdaRole.name())
                    .build());
            // Create DB
            var emailRecordTable = new Table("EmailRecordTable", TableArgs.builder()
                    .attributes(TableAttributeArgs.builder()
                            .name("Id")
                            .type("S")
                            .build())
                    .hashKey("Id")
                    .billingMode("PAY_PER_REQUEST")
                    .build());
            // Create Lambda
            emailRecordTable.name().apply(tableName -> {
                serviceAccountKey.privateKey().apply(key -> {
                    byte[] decodedBytes = Base64.getDecoder().decode(key);
                    String privateKeyString = new String(decodedBytes, StandardCharsets.UTF_8);
                    var lambdaFunction = new Function("lambdaFunction", FunctionArgs.builder()
                            .handler("index.handler")
                            .runtime("nodejs18.x")
                            .code(new FileArchive(config.require("codePath")))
                            .role(lambdaRole.arn())
                            .timeout(10)
                            .environment(FunctionEnvironmentArgs.builder()
                                    .variables(Map.of(
                                            "BUCKET_NAME", config.require("bucketName"),
                                            "EMAIL_SUBJECT", config.require("emailSubject"),
                                            "EMAIL_TEXT_FAIL", config.require("emailTextFail"),
                                            "EMAIL_TEXT_SUCCESS", config.require("emailTextSuccess"),
                                            "JSON_STRING", privateKeyString,
                                            "TABLE_NAME", tableName,
                                            "SOURCE_EMAIL", config.require("sourceEmail")
                                    ))
                                    .build())
                            .build());

                    // trigger
                    var snsLambdaSubscription = new TopicSubscription("snsLambdaSubscription", TopicSubscriptionArgs.builder()
                            .protocol("lambda")
                            .topic(snsTopic.arn())
                            .endpoint(lambdaFunction.arn())
                            .build());
                    new Permission("allowSNSPermission", PermissionArgs.builder()
                            .action("lambda:InvokeFunction")
                            .function(lambdaFunction.arn())
                            .principal("sns.amazonaws.com")
                            .sourceArn(snsTopic.arn())
                            .build());
                    return Output.ofNullable("");
                });
                return Output.ofNullable("");
            });
            return Output.ofNullable("");
        });
        // Create AWS VPC
        var myvpc = new Vpc(config.require("vpcName"), VpcArgs.builder()
                .cidrBlock(config.require("vpcCidr"))
                .build());

        // create subnets
        String[] availabilityZones = {config.require("region") + "a", config.require("region") + "b", config.require("region") + "b"};
        Subnet[] publicSubNets = new Subnet[availabilityZones.length];
        Subnet[] privateSubNets = new Subnet[availabilityZones.length];
        for (int i = 0; i < availabilityZones.length; i++) {
            publicSubNets[i] = new Subnet("publicSubnet" + i, SubnetArgs.builder()
                    .vpcId(myvpc.id())
                    .cidrBlock(config.require("public1") + i + config.require("public2"))
                    .availabilityZone(availabilityZones[i])
                    .mapPublicIpOnLaunch(true)
                    .build());

            privateSubNets[i] = new Subnet("privateSubnet" + i, SubnetArgs.builder()
                    .vpcId(myvpc.id())
                    .cidrBlock(config.require("private1") + (i+availabilityZones.length) + config.require("private2"))
                    .availabilityZone(availabilityZones[i])
                    .build());
        }
        // create gateway
        InternetGateway myInternetGateway = new InternetGateway("myInternetGateway",
                InternetGatewayArgs.builder().vpcId(myvpc.id()).build());

        // create public route table
        RouteTable publicRouteTable = new RouteTable("publicRouteTable", RouteTableArgs.builder()
                .vpcId(myvpc.id())
                .build());
        Route publicRoute = new Route("publicRoute", RouteArgs.builder()
                .routeTableId(publicRouteTable.id())
                .destinationCidrBlock("0.0.0.0/0")
                .gatewayId(myInternetGateway.id())
                .build());
        for (int i = 0; i < availabilityZones.length; i++) {
            RouteTableAssociation publicSubnetAssociation = new RouteTableAssociation("publicSubnetAssociation" + i,
                    RouteTableAssociationArgs.builder()
                            .subnetId(publicSubNets[i].id())
                            .routeTableId(publicRouteTable.id())
                            .build());
        }
        // create private route table
        RouteTable privateRouteTable = new RouteTable("privateRouteTable", RouteTableArgs.builder()
                .vpcId(myvpc.id())
                .build());
        for (int i = 0; i < availabilityZones.length; i++) {
            RouteTableAssociation privateSubnetAssociation = new RouteTableAssociation("privateSubnetAssociation" + i,
                    RouteTableAssociationArgs.builder()
                            .subnetId(privateSubNets[i].id())
                            .routeTableId(privateRouteTable.id())
                            .build());
        }
        // create security group
        ProfileCredentialsProvider profileCredentialsProvider = ProfileCredentialsProvider.builder()
                .profileName(config.require("profile"))
                .build();
        Region region = Region.of(config.require("region"));
        Ec2Client ec2 = Ec2Client.builder()
                .region(region)
                .credentialsProvider(profileCredentialsProvider)
                .build();

        String groupName = "MySecurityGroup";
        String description = "My security group";
        // create load balance security group
        var lbSecurityGroup = new SecurityGroup("lb-security-group", SecurityGroupArgs.builder()
                .vpcId(myvpc.id())
                .build());
        SecurityGroupRule httpApplication = new SecurityGroupRule("http-rule", SecurityGroupRuleArgs.builder()
                .type("ingress")
                .fromPort(80)
                .toPort(80)
                .protocol("tcp")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(lbSecurityGroup.id())
                .build());
        SecurityGroupRule httpsApplication = new SecurityGroupRule("https-rule", SecurityGroupRuleArgs.builder()
                .type("ingress")
                .fromPort(443)
                .toPort(443)
                .protocol("tcp")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(lbSecurityGroup.id())
                .build());
        SecurityGroupRule lbOutRule = new SecurityGroupRule("lb-out-rule", SecurityGroupRuleArgs.builder()
                .type("egress")
                .fromPort(0)
                .toPort(65535)
                .protocol("all")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(lbSecurityGroup.id())
                .build());
        // app security group
        var appSecurityGroup = new SecurityGroup("app-security-group", SecurityGroupArgs.builder()
                .vpcId(myvpc.id())
                .build());
        SecurityGroupRule sshRule = new SecurityGroupRule("ssh-rule", SecurityGroupRuleArgs.builder()
                .type("ingress")
                .fromPort(22)
                .toPort(22)
                .protocol("tcp")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(appSecurityGroup.id())
                .build());
        SecurityGroupRule ruleApplication = new SecurityGroupRule("rule-rule", SecurityGroupRuleArgs.builder()
                .type("ingress")
                .fromPort(8080)
                .toPort(8080)
                .protocol("tcp")
                .securityGroupId(appSecurityGroup.id())
                .sourceSecurityGroupId(lbSecurityGroup.id())
                .build());
        SecurityGroupRule outApplication = new SecurityGroupRule("app-out-rule", SecurityGroupRuleArgs.builder()
                .type("egress")
                .fromPort(0)
                .toPort(65535)
                .protocol("all")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(appSecurityGroup.id())
                .build());
        // db security group
        var dbSecurityGroup = new SecurityGroup("db-security-group", SecurityGroupArgs.builder()
                .vpcId(myvpc.id())
                .build());
        SecurityGroupRule dbRule = new SecurityGroupRule("db-rule", SecurityGroupRuleArgs.builder()
                .type("ingress")
                .fromPort(3306)
                .toPort(3306)
                .protocol("tcp")
                .securityGroupId(dbSecurityGroup.id())
                .sourceSecurityGroupId(appSecurityGroup.id())
                .build());
        SecurityGroupRule dbOutRule = new SecurityGroupRule("db-out-rule", SecurityGroupRuleArgs.builder()
                .type("egress")
                .fromPort(0)
                .toPort(65535)
                .protocol("all")
                .cidrBlocks("0.0.0.0/0")
                .securityGroupId(dbSecurityGroup.id())
                .build());


        // RDS parameter group
        var myGroup = new ParameterGroup(config.require("parameterGroupName"), ParameterGroupArgs.builder()
                .family("mysql8.0")
                .parameters(
                        ParameterGroupParameterArgs.builder()
                                .name("character_set_server")
                                .value("utf8")
                                .build(),
                        ParameterGroupParameterArgs.builder()
                                .name("character_set_client")
                                .value("utf8")
                                .build())
                .build());
        // Create IAM
        var role = new Role("myCloudWatchRole", RoleArgs.builder()
                .assumeRolePolicy(serializeJson(
                        jsonObject(
                                jsonProperty("Version", "2012-10-17"),
                                jsonProperty("Statement", jsonArray(jsonObject(
                                        jsonProperty("Action", "sts:AssumeRole"),
                                        jsonProperty("Effect", "Allow"),
                                        jsonProperty("Sid", ""),
                                        jsonProperty("Principal", jsonObject(
                                                jsonProperty("Service", "ec2.amazonaws.com")
                                        ))
                                )))
                        )))
                .tags(Map.of("role-name", "cloud-watch-role"))
                .build());

        var policyAttachment = new RolePolicyAttachment("myPolicyAttachment",
                RolePolicyAttachmentArgs.builder()
                        .role(role.name())
                        .policyArn("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")
                        .build());
        var snsAttachment = new RolePolicyAttachment("mySnsAttachment",
                RolePolicyAttachmentArgs.builder()
                        .role(role.name())
                        .policyArn("arn:aws:iam::aws:policy/AmazonSNSFullAccess")
                        .build());

        var roleProfile = new InstanceProfile("roleProfile", InstanceProfileArgs.builder()
                .role(role.name())
                .build());

        // Create RDS instance
        Output<String> output1 = privateSubNets[0].id();
        Output<String> output2 = privateSubNets[1].id();
        Output<String> output3 = dbSecurityGroup.id();
        Output<String> output4 = publicSubNets[0].id();
        Output<String> output5 = appSecurityGroup.id();
        Output<String> output6 = roleProfile.name();
        Output<String> output7 = lbSecurityGroup.id();
        Output<String> output8 = publicSubNets[1].id();
        Output<String> output9 = snsTopic.arn();
        Output.all(output1, output2, output3, output4, output5, output6, output7, output8, output9).apply(tuple -> {
            String str1 = tuple.get(0);
            String str2 = tuple.get(1);
            String str3 = tuple.get(2);
            String str4 = tuple.get(3);
            String str5 = tuple.get(4);
            String str6 = tuple.get(5);
            String str7 = tuple.get(6);
            String str8 = tuple.get(7);
            String str9 = tuple.get(8);
            // create load balancer
            var appLoadBalancer = new LoadBalancer("appLoadBalancer", LoadBalancerArgs.builder()
                    .loadBalancerType("application")
                    .securityGroups(str7)
                    .tags(Map.of("Name", "webapp-lb"))
                    .subnets(List.of(str4, str8))
                    .ipAddressType("ipv4")
                    .build());

            var rdsSubnet = new SubnetGroup("rds-subnet", SubnetGroupArgs.builder()
                    .subnetIds(Arrays.asList(str1, str2))
                    .build());

            var rdsInstance = new com.pulumi.aws.rds.Instance(config.require("dbInstanceName"), new com.pulumi.aws.rds.InstanceArgs.Builder()
                    .dbName(config.require("dbName"))
                    .engine("mysql")
                    .engineVersion("8.0")
                    .dbSubnetGroupName(rdsSubnet.name())
                    .instanceClass(config.require("instanceClass"))
                    .parameterGroupName(myGroup.name())
                    .password(config.require("password"))
                    .skipFinalSnapshot(true)
                    .username(config.require("username"))
                    .publiclyAccessible(Boolean.FALSE)
                    .multiAz(Boolean.FALSE)
                    .vpcSecurityGroupIds(str3)
                    .allocatedStorage(20)
                    .build());

            var launchTemplateProfile = new LaunchTemplateIamInstanceProfileArgs.Builder();
            launchTemplateProfile.name(str6);

            Output<String> dbEndpoint = rdsInstance.endpoint();
            Output<String> dbName = rdsInstance.dbName();
            dbEndpoint.apply(var1 -> {
                dbName.apply(var2 -> {
                    // user data
                    Map<String, String> tags = new HashMap<>();
                    Map<String, String> properties = new HashMap<>();
                    properties.put("spring.datasource.url", "jdbc:mysql://" + var1  + "/"+ var2 +"?serverTimezone=UTC");
                    properties.put("spring.datasource.username", config.require("username"));
                    properties.put("spring.datasource.password", config.require("password"));
                    properties.put("spring.datasource.driver-class-name", "com.mysql.cj.jdbc.Driver");
                    properties.put("spring.jpa.properties.hibernate.dialect", "org.hibernate.dialect.MySQL8Dialect");
                    properties.put("spring.jpa.hibernate.ddl-auto", "update");
                    properties.put("spring.datasource.hikari.connection-timeout", "1000");
                    properties.put("logging.level.org.hibernate.SQL", "debug");
                    properties.put("logging.level.org.hibernate.type.descriptor.sql.BasicBinder", "trace");
                    properties.put("logging.file.name", "/var/log/csye6225.log");
                    properties.put("sns.topicArn", str9);
                    properties.put("sns.region", config.require("region"));
                    StringBuilder userDataBuilder = new StringBuilder();
                    userDataBuilder.append("#!/bin/bash\n");
                    userDataBuilder.append("ENV_FILE=\"/opt/application.properties\"\n");
                    for (Map.Entry<String, String> entry : properties.entrySet()) {
                        userDataBuilder.append(String.format("echo \"%s=%s\" | sudo tee -a ${ENV_FILE}\n", entry.getKey(), entry.getValue()));
                    }
                    userDataBuilder.append("chown csye6225:csye6225 ${ENV_FILE}\n");
                    userDataBuilder.append("chmod 644 ${ENV_FILE}\n");
                    userDataBuilder.append("sudo systemctl start csye6225\n");
                    userDataBuilder.append("sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \\\n" +
                            "    -a fetch-config \\\n" +
                            "    -m ec2 \\\n" +
                            "    -c file:/opt/csye6225/cloudwatch-config.json \\\n" +
                            "    -s");
                    String userData = userDataBuilder.toString();
                    String encodedUserData = Base64.getEncoder().encodeToString(userData.getBytes());

                    // create target group
                    var targetGroup = new TargetGroup("targetGroup", TargetGroupArgs.builder()
                            .port(8080)
                            .protocol("HTTP")
                            .vpcId(myvpc.id())
                            .healthCheck(TargetGroupHealthCheckArgs.builder()
                                    .path("/healthz")
                                    .protocol("HTTP")
                                    .port("traffic-port")
                                    .build())
                            .build());

                    // create ALB listener
                    var httpListener = new Listener("httpListener", ListenerArgs.builder()
                            .loadBalancerArn(appLoadBalancer.arn())
                            .port(443)
                            .protocol("HTTPS")
                            .sslPolicy("ELBSecurityPolicy-2016-08")
                            .certificateArn(config.require("sslCertificateId"))
                            .defaultActions(ListenerDefaultActionArgs.builder()
                                    .type("forward")
                                    .targetGroupArn(targetGroup.arn())
                                    .build())
                            .build());

                    // create Launch Templates
                    tags.put("Name", "csye6225_asg");
                    var launchTemplate = new LaunchTemplate("launch-template", LaunchTemplateArgs.builder()
                            .name("launch-template")
                            .iamInstanceProfile(launchTemplateProfile.build())
                            .imageId(config.require("amiId"))
                            .instanceType(config.require("instanceType"))
                            .keyName(config.require("keyPair"))
                            .userData(encodedUserData)
                            .networkInterfaces(LaunchTemplateNetworkInterfaceArgs.builder()
                                    .associatePublicIpAddress("true")
                                    .securityGroups(str5)
                                    .build())
                            .tags(tags)
                            .build());
                    // create auto scaling groups
                    Output<String> targetGroupArn = targetGroup.arn();
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                    targetGroupArn.apply(arn -> {
                        var autoScalingGroup = new Group("autoScalingGroup", GroupArgs.builder()
                                .name("autoScalingGroup")
                                .maxSize(3)
                                .minSize(1)
                                .healthCheckGracePeriod(300)
                                .launchTemplate(GroupLaunchTemplateArgs.builder()
                                        .id(launchTemplate.id())
                                        .build())
                                .tags(
                                        GroupTagArgs.builder()
                                                .key("Name")
                                                .value("my-instance" + "-" + LocalDateTime.now().format(formatter))
                                                .propagateAtLaunch(true)
                                                .build()
                                )
                                .defaultCooldown(60)
                                .desiredCapacity(1)
                                .targetGroupArns(arn)
                                .vpcZoneIdentifiers(str4, str8)
                                .build());

                        // create scale up policy
                        var scaleUpPolicy = new com.pulumi.aws.autoscaling.Policy("scaleUpPolicy", com.pulumi.aws.autoscaling.PolicyArgs.builder()
                                .autoscalingGroupName(autoScalingGroup.name())
                                .scalingAdjustment(1)
                                .adjustmentType("ChangeInCapacity")
                                .cooldown(60)
                                .autoscalingGroupName(autoScalingGroup.name())
                                .build());
                        Output<String> scaleUpArn = scaleUpPolicy.arn();
                        Output<String> asgName = autoScalingGroup.name();
                        scaleUpArn.apply(var -> {
                            asgName.apply(asgNameVar -> {
                                new MetricAlarm("scaleUpAlarm", MetricAlarmArgs.builder()
                                        .comparisonOperator("GreaterThanOrEqualToThreshold")
                                        .evaluationPeriods(2)
                                        .metricName("CPUUtilization")
                                        .namespace("AWS/EC2")
                                        .period(60)
                                        .statistic("Average")
                                        .threshold(5.0)
                                        .alarmActions(var)
                                        .dimensions(Map.of("AutoScalingGroupName", asgNameVar))
                                        .build());
                                return Output.ofNullable("");
                            });
                            return Output.ofNullable("");
                        });

                        // create scale down policy
                        var scaleDownPolicy = new com.pulumi.aws.autoscaling.Policy("scaleDownPolicy", com.pulumi.aws.autoscaling.PolicyArgs.builder()
                                .autoscalingGroupName(autoScalingGroup.name())
                                .scalingAdjustment(-1)
                                .adjustmentType("ChangeInCapacity")
                                .cooldown(60)
                                .autoscalingGroupName(autoScalingGroup.name())
                                .build());
                        Output<String> scaleDownArn = scaleDownPolicy.arn();
                        scaleDownArn.apply(var -> {
                            asgName.apply(asgNameVar -> {
                                new MetricAlarm("scaleDownAlarm", MetricAlarmArgs.builder()
                                        .comparisonOperator("LessThanOrEqualToThreshold")
                                        .evaluationPeriods(2)
                                        .metricName("CPUUtilization")
                                        .namespace("AWS/EC2")
                                        .period(60)
                                        .statistic("Average")
                                        .threshold(3.0)
                                        .alarmActions(var)
                                        .dimensions(Map.of("AutoScalingGroupName", asgNameVar))
                                        .build());
                                return Output.ofNullable("");
                            });
                            return Output.ofNullable("");
                        });
                        // create new record
                        Output<String> aName = autoScalingGroup.name();
                        Output<String> dnsName = appLoadBalancer.dnsName();
                        Output<String> zoneId = appLoadBalancer.zoneId();
                        dnsName.apply(dns -> {
                            zoneId.apply(id -> {
                                aName.apply(var -> {
                                    new com.pulumi.aws.route53.Record("my-record", RecordArgs.builder()
                                            .zoneId(config.require("zoneId"))
                                            .name(config.require("recordName"))
                                            .type("A")
                                            .aliases(RecordAliasArgs.builder()
                                                    .name(dns)
                                                    .zoneId(id)
                                                    .evaluateTargetHealth(true)
                                                    .build()
                                            )
                                            .build());
                                    return Output.ofNullable("");
                                });
                                return Output.ofNullable("");
                            });
                            return Output.ofNullable("");
                        });
                        return Output.ofNullable("");
                    });
                    return Output.ofNullable("");
                });
                return Output.ofNullable("");
            });
            return Output.ofNullable("");
        });
    }
}
