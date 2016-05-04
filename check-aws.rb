#!/usr/bin/env ruby

require 'aws-sdk'
require 'pp'
require_relative 'cornell_saml_x509'

## Expects AWS credntials set up in ~/.aws/config OR in evironment variables
## See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
Aws.config.update({
  region: 'us-east-1',
  credentials: Aws::SharedCredentials.new(profile_name: "default")
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

  resp = @iam.get_account_summary()
  iam_summary_map = resp.summary_map

  puts "Checking IAM root user"
  puts "\tAccess key is configured for root user" if iam_summary_map["AccountAccessKeysPresent"] != 1
  puts "\tMFA is NOT enabled for root user" if iam_summary_map["AccountMFAEnabled"] != 1

  puts "Checking IAM identity provider configuration"
  puts "\tNo identity providers are configured" if iam_summary_map["Providers"] == 0
  puts "\tMultiple identity providers are configured" if iam_summary_map["Providers"] > 1

  resp = @iam.list_saml_providers

  cornell_saml = false
  resp.saml_provider_list.each do | provider |
    resp = @iam.get_saml_provider(saml_provider_arn: provider.arn)
    # puts "#{resp.saml_metadata_document}"
    if resp.saml_metadata_document.include? CornellSamlX509.public_key
      cornell_saml = true
    else
      puts "\tUnknown SAML identity provider #{provider.arn}"
    end
  end
  puts "\tCornell SAML identity provider is not configured" if !cornell_saml

  puts "Checking IAM user passwords"
  resp = @iam.list_users()
  resp.users.each do |user|
    # puts "#{user}"
    begin
      resp = @iam.get_login_profile(user_name: user.user_name)
      puts "\tPassword is configured for IAM user '#{user.user_name}'"
    rescue Aws::IAM::Errors::NoSuchEntity
      # no password is configured
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
    check_config_cloud_trail(region, resp.config_rules)
  end


end

def check_config_cloud_trail(region, config_rules)
  cloud_trail_rule_present = false
  config_rules.each do | rule |
    if rule.source.source_identifier == "CLOUD_TRAIL_ENABLED" && rule.source.owner == "AWS" then
       cloud_trail_rule_present = true
       if rule.maximum_execution_frequency != "TwentyFour_Hours" then
         puts "\tConfig rule to check that CloudTrail is enabled has frequency of #{rule.maximum_execution_frequency}. Should be 24 hours frequency."
       end
       if rule.config_rule_state != "ACTIVE" then
         puts "\tConfig rule to check that CloudTrail is enabled is itself present but not enabled"
      end
    else
      # not a cloud trail rule
    end
  end
  if !cloud_trail_rule_present && region == "us-east-1" then
    puts "\t[#{region}] Config rule to check that CloudTrail is enabled is missing."
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
#
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
  else

    itso_trails.each do | trail |
      errors = cloudtrail_is_active_trail? (trail)
      itso_trail_valid = itso_trail_valid || errors.empty?
      errors_summary.concat(errors)
    end
    if !itso_trail_valid then
      puts "\tAn ITSO CloudTrail is present but appears does not appear to be configured properly."
    end
    errors_summary.each { | msg | puts msg }
  end

  global_trail_valid = false
  errors_summary = []

  if global_trails.empty? then
    puts "\tNo trail is configured to log events in all regions. This account may need to transition to the 'multi-region' trail configuration where a single trail can log events in all regions."
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
  (trail.trail_arn =~ /arn:aws:cloudtrail:us-east-1:.*:trail\/itso/)
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

check_iam
check_config
check_cloudtrail