#!/usr/bin/env ruby

require 'aws-sdk'
require 'pp'
require_relative 'cornell_saml_x509'

# How old can an IAM access key be before warning about rotation.
IAM_ACCESS_KEY_WARNING_AGE_DAYS = 90
VERBOSE = false

## Expects AWS credntials set up in ~/.aws/config OR in evironment variables
## See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
## See also https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs
Aws.config.update({
   region: 'us-east-1'
#   credentials: Aws::SharedCredentials.new()
})

################################
# IAM
#
# - root user
#   - alerts if access key configured
#   - alerts if MFA is not enabled
# - SAML identity providers
#   - alerts if exactly one identity provider is not configured
#   - alerts if public key in IDP SAML metadata does not match Cornell IDP SAML
#   - alerts if Cornell IDP is not found
# - IAM user passwords
#   - alerts if password is configured for any IAM user
################################
def check_iam

  puts "Checking IAM"

  @iam = Aws::IAM::Client.new

  puts "Checking IAM account alias"
  resp = @iam.list_account_aliases
  if resp.account_aliases.length != 1
    puts "\tNo account alias is configured."
    contact_cloud_support
  else
    puts "\tAlias is '#{resp.account_aliases[0]}'."
  end

  resp = @iam.get_account_summary()
  iam_summary_map = resp.summary_map

  puts "Checking IAM root user"
  if iam_summary_map["AccountAccessKeysPresent"] != 0 then
    puts "\tAccess key is configured for root user"
    puts "\t\tPlease remove access keys for the root user."
    puts "\t\tAccess keys should be associated only with accounts assigned to specific individuals."
  end
  if iam_summary_map["AccountMFAEnabled"] != 1 then
    puts "\tMFA is NOT enabled for root user."
    puts "\t\tPlease enable MFA for the root user and secure the MFA device."
    puts "\t\tIf you need an MFA device contact cloud-support@cornell.edu."
  end

  puts "Checking IAM identity provider configuration"

  resp = @iam.list_saml_providers

  cornell_saml = false
  resp.saml_provider_list.each do | provider |
    puts "\t...#{provider.arn}" if VERBOSE
    resp = @iam.get_saml_provider(saml_provider_arn: provider.arn)
    # puts "#{resp.saml_metadata_document}"
    if resp.saml_metadata_document.include? CornellSamlX509.public_key
      cornell_saml = true
    else
      puts "\tUnknown SAML identity provider #{provider.arn}"
      contact_cloud_support
    end
  end

  if !cornell_saml then
    puts "\tCornell SAML identity provider is not configured."
    contact_cloud_support
  end

  if iam_summary_map["Providers"] == 0
    puts "\tNo identity providers are configured"
    contact_cloud_support
  end
  if iam_summary_map["Providers"] > 1
    puts "\tMultiple identity providers are configured"
    contact_cloud_support
  end

  puts "Checking IAM user passwords..."
  resp = @iam.list_users()
  users = resp.users
  users.each do |user|
    puts "\t...#{user.user_name}" if VERBOSE
    begin
      resp = @iam.get_login_profile(user_name: user.user_name)
      puts "\tPassword is configured for IAM user '#{user.user_name}'."
      puts "\t\tAll AWS access should be accomplished through Shibboleth and Cornell netID credentials."
      puts "\t\tPlease delete the password for this user."
    rescue Aws::IAM::Errors::NoSuchEntity
      # no password is configured
    end
  end

  puts "Checking IAM access keys"
  users.each do |user|
    puts "\t...#{user.user_name}" if VERBOSE
    resp = @iam.list_access_keys({user_name: user.user_name})
    resp.access_key_metadata.each do | ak |
      expire_date = ak.create_date + (60*60*24*IAM_ACCESS_KEY_WARNING_AGE_DAYS)
      expired = ((expire_date <=> Time.now) < 0 && ak.status == 'Active')
      if (expired || VERBOSE) then
        puts "\tuser: #{ak.user_name}\tkey: #{ak.access_key_id}"
      end
      if expired then
        puts "\tWARNING: Active key is over #{IAM_ACCESS_KEY_WARNING_AGE_DAYS} days old and should be rotated!"
      end
      if (expired || VERBOSE) then
        puts "\t\tstatus: #{ak.status}"
        puts "\t\tcreated: #{ak.create_date}"
        resp = @iam.get_access_key_last_used({access_key_id: ak.access_key_id})
        puts "\t\tlast_used: #{resp.access_key_last_used.last_used_date}"
        puts "\t\tfor service: #{resp.access_key_last_used.service_name}"
        puts "\t\tin region: #{resp.access_key_last_used.region}"
      end
    end
  end


end # check_iam

################################
# AWS Config
#
# - CLOUD_TRAIL_ENABLED rule
#   - alerts if frequency is not 24 hours
#   - alerts if rule is not ACTIVE
#   - alerts if rule is not present in us-east-1
#   - alerts if rule has not been evaluated in past 24 hours
#   - alerts if rule is not compliant
################################
def check_config

  puts "Checking AWS Config Service..."

  # ec2  = Aws::EC2::Client.new
  # regions = ec2.describe_regions({})

  # List of regions where Config rules can check resource configurations
  # http://docs.aws.amazon.com/general/latest/gr/rande.html#awsconfig_region
  # As of 4/22/2016
  regions = ["us-east-1", "us-west-2", "eu-west-1",
              "eu-central-1", "ap-northeast-1"]

  regions.each do |region|
    puts "...#{region}"
    client = Aws::ConfigService::Client.new(region: region)
    resp = client.describe_config_rules
    check_config_cloud_trail(client, region, resp.config_rules)
  end


end

def check_config_cloud_trail(client, region, config_rules)
  cloud_trail_rule_present = false
  config_rules.each do | rule |
    if rule.source.source_identifier == "CLOUD_TRAIL_ENABLED" && rule.source.owner == "AWS" then
       cloud_trail_rule_present = true
       if rule.maximum_execution_frequency != "TwentyFour_Hours" && rule.maximum_execution_frequency != "One_Hour" then
         puts "\tConfig rule to check that CloudTrail is enabled has frequency of #{rule.maximum_execution_frequency}. Should be 1 hour or 24 hours frequency."
         contact_cloud_support
       end
       if rule.config_rule_state != "ACTIVE" then
         puts "\tConfig rule to check that CloudTrail is enabled is itself present but not enabled"
         contact_cloud_support
      end
      response = client.describe_config_rule_evaluation_status({
        config_rule_names: [rule.config_rule_name]
        })
      eval_status = response.config_rules_evaluation_status.first
      yesterday = Time.now - (60 * 60 * 24)
      if ((yesterday <=> eval_status.last_successful_invocation_time) > 0 ) then
         puts "\tConfig rule to check that CloudTrail is enabled has not been executed within past 24 hours. It was last executed at: #{eval_status.last_successful_invocation_time}"
         contact_cloud_support
      end

      response = client.get_compliance_details_by_config_rule({
          config_rule_name: rule.config_rule_name
        })
      if (response.evaluation_results.first.compliance_type != "COMPLIANT") then
        puts "\tConfig rule to check that CloudTrail is enabled indicates that CloudTrail is NOT enabled. Rule compliance: #{response.evaluation_results.first.compliance_type} evaluated at #{response.evaluation_results.first.config_rule_invoked_time}"
        contact_cloud_support
      end
    else
      # not a cloud trail rule
    end
  end
  if !cloud_trail_rule_present && region == "us-east-1" then
    puts "\t[#{region}] Config rule to check that CloudTrail is enabled is missing."
    contact_cloud_support
  end
end

################################
# AWS CloudTrail
#
# - ITSO trail
#   - alerts if ITSO trail is not present
#   - alerts if ITSO trail is not logging
#   - alerts if ITSO trail is not enabled for global events and multi-regions
#   - alerts if ITSO trail has not delivered results within the last 12 hours
# - Main trail
#   - alerts if Main trail is not present
#   - alerts if Main trail is not logging
#   - alerts if Main trail is not enabled for global events and multi-regions
#   - alerts if Main trail has not delivered results within the last 12 hours
################################
def check_cloudtrail

  puts "Checking AWS CloudTrail..."
  itso_trails = []
  global_trails = []
  ec2  = Aws::EC2::Client.new
  resp = ec2.describe_regions({})

  resp.regions.each do | region |
    puts "...#{region.region_name}"
    client = Aws::CloudTrail::Client.new(region: region.region_name)
    resp = client.describe_trails(include_shadow_trails: false)

    resp.trail_list.each do | trail |

      if cloudtrail_is_itso_trail?(trail) then
        itso_trails << trail
      elsif cloudtrail_is_global_trail?(trail) then
        global_trails << trail
      end
    end
  end

  itso_trail_valid = false
  errors_summary = []

  if itso_trails.empty? then
    puts "\tITSO CloudTrail for logging all API access is missing."
    contact_cloud_support
  else

    itso_trails.each do | trail |
      errors = cloudtrail_is_active_trail? (trail)
      itso_trail_valid = itso_trail_valid || errors.empty?
      errors_summary.concat(errors)
    end
    if !itso_trail_valid then
      puts "\tAn ITSO CloudTrail is present but appears does not appear to be configured properly."
      contact_cloud_support
    end
    errors_summary.each { | msg | puts msg }
  end

  global_trail_valid = false
  errors_summary = []

  if global_trails.empty? then
    puts "\tNo trail is configured to log events in all regions. This account may need to transition to the 'multi-region' trail configuration where a single trail can log events in all regions."
    contact_cloud_support
  else
    global_trails.each do | trail |
      errors = cloudtrail_is_active_trail? (trail)
      global_trail_valid = global_trail_valid || errors.empty?
      errors_summary.concat(errors)
    end
    if !global_trail_valid then
      # puts "\tA multi-region trail is present but does not appear to be configured properly."
    end
    errors_summary.each { | msg | puts msg }
  end
end

def cloudtrail_is_itso_trail? (trail)
  (trail.trail_arn =~ /arn:aws:cloudtrail:us-east-1:.*:trail\/.*[Ii][Tt][Ss][Oo].*/)
end

def cloudtrail_is_global_trail? (trail)
  trail.include_global_service_events && trail.is_multi_region_trail
end

# Returns empty array if the trail passes tests.
# Returns array of error messages if not.
def cloudtrail_is_active_trail? (trail)
  client = Aws::CloudTrail::Client.new(region: trail.home_region)
  resp = client.get_trail_status(name: trail.name)

  errors = []
  if resp.is_logging then
    # 60*60*12 = # of seconds in 12 hours
    if resp.latest_delivery_time + (60*60*12) < Time.now then
      isvalid = false
      errors << "\tTrail has not delivered logs for more than 12 hours (#{trail.trail_arn}). Last successful delivery was #{resp.latest_delivery_time}"
    end
    # Any other invalid states?
  else
    errors << "\tTrail is not logging (#{trail.trail_arn})."
  end
  return errors
end

def check_vpc
  check_nacls
  check_flow_logs
end

def check_flow_logs
  puts "Checking VPC Flow Logs"

  client = Aws::EC2::Client.new
  resp = client.describe_flow_logs({})
  if resp.flow_logs.empty?
    puts "\tNo flow logs are enabled. If your account requires flow logs for auditing or troubleshooting, contact cloud-support@cornell.edu."
  end

  # resp.flow_logs.each do | log |
  #     puts log.inspect
  # end

end

################################
# AWS NACLS
#
# - alerts if there are missing NACL rules
#
################################
def check_nacls

  puts "Checking default NACLS in each region..."

  ec2  = Aws::EC2::Client.new

  regions = ec2.describe_regions({})

  regions.regions.each do |region|
    puts "...#{region.region_name}"

    Aws.config[:region] = region.region_name
    ec2 = Aws::EC2::Client.new

    nacls = ec2.describe_network_acls({})

    nacls.network_acls.each do |acl|

      rule_map = [
        {cidr: "10.0.0.0/8", egress: true, matched: 0},
        {cidr: "10.0.0.0/8", egress: false,  matched: 0},
        {cidr: "128.84.0.0/16", egress: true, matched: 0},
        {cidr: "128.84.0.0/16", egress: false,  matched: 0},
        {cidr: "128.253.0.0/16", egress: true, matched: 0},
        {cidr: "128.253.0.0/16", egress: false,  matched: 0},
        {cidr: "132.236.0.0/16", egress: true, matched: 0},
        {cidr: "132.236.0.0/16", egress: false,  matched: 0},
        {cidr: "192.35.82.0/24", egress: true, matched: 0},
        {cidr: "192.35.82.0/24", egress: false,  matched: 0},
        {cidr: "192.122.235.0/24", egress: true, matched: 0},
        {cidr: "192.122.235.0/24", egress: false,  matched: 0},
        {cidr: "192.122.236.0/24", egress: true, matched: 0},
        {cidr: "192.122.236.0/24", egress: false,  matched: 0},
        {cidr: "0.0.0.0/0", egress: true, from: 80, to: 80, matched: 0},
        {cidr: "0.0.0.0/0", egress: false, from: 80, to: 80, matched: 0},
        {cidr: "0.0.0.0/0", egress: true, from: 443, to: 443, matched: 0},
        {cidr: "0.0.0.0/0", egress: false, from: 443, to: 443, matched: 0},
        {cidr: "0.0.0.0/0", egress: true, from: 1024, to: 65535, matched: 0},
        {cidr: "0.0.0.0/0", egress: false, from: 1024, to: 65535, matched: 0},
      ]

      acl.entries.each do |entry|
        if acl.is_default
          if entry.rule_number < 32767
            if entry.port_range.nil?
              rule = rule_map.find {|rule| rule[:cidr] == entry.cidr_block and rule[:egress] == entry.egress}
              rule[:matched] = 1 if rule
            else
              rule = rule_map.find {|rule| rule[:cidr] == entry.cidr_block and rule[:egress] == entry.egress and rule[:to] == entry.port_range.to and rule[:from] == entry.port_range.from}
              rule[:matched] = 1 if rule
            end
          end
        end
      end
      unmatched = rule_map.find_all {|rule| rule[:matched] == 0}
      if unmatched.length > 0
        puts "\tUnmatched rule(s) in #{acl.network_acl_id} in VPC #{acl.vpc_id}"
        unmatched.each do |rule|
          puts "\t\t" + rule.to_s
        end
        contact_cloud_support
      end
    end
  end

end

def contact_cloud_support
  puts "\t\tPlease contact cloud-support@cornell.edu about this issue."
end

check_iam
check_config
check_cloudtrail
check_vpc
