# README #

The repo contains simple Ruby scripts to check an AWS account against configuration required by Cornell policy.

### Configuration Checks ###

The baseline Cornell policy for organizational use of AWS are outlined in [Cloudification Service Details](https://blogs.cornell.edu/cloudification/cloudification-service/).

This code checks for the following:

* IAM
  *  Check that exactly one account alias is configured. Show the alias.
  * root user
    * alerts if access key configured
    * alerts if MFA is not enabled
  * SAML identity providers
    * alerts if exactly one identity provider is not configured
    * alerts if public key in IDP SAML metadata does not match Cornell IDP SAML
    * alerts if Cornell IDP is not found
  * IAM user passwords
    * alerts if password is configured for any IAM user
  * IAM password policy
    * alerts if the IAM password policy parameters are weak. Cornell recommendations for a password policy:
      * require symbols in passwords
      * require numbers in passwords
      * require lowercase characters in passwords
      * require uppercase characters in passwords
      * allow users to change their own passwords
      * allow users set new password after expiration
      * require minimum password length of 14 characters
      * require maximum password age of 90 days or less
      * require at least 3 new, different passwords before a password is reused
  * IAM access keys
    * alerts if an active key is more than 90 days old
      * [How to rotate IAM access keys](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey)
* AWS Config
  * CLOUD_TRAIL_ENABLED rule
    * alerts if frequency is not 24 hours
    * alerts if rule is not ACTIVE
    * alerts if rule is not present in us-east-1
    * alerts if rule hasn't been run in the past 24 hours
    * alerts if last evaluation of rule result in NONCOMPLIANT result
* AWS CloudTrail
  * ITSO auditing trail
    * alerts if ITSO trail is not present
    * alerts if ITSO trail is not logging
    * alerts if ITSO trail is not enabled for global events and multi-regions
    * alerts if ITSO trail has not delivered results within the last 12 hours
  * main trail
    * alerts if main trail is not present
    * alerts if main trail is not logging
    * alerts if main trail is not enabled for global events and multi-regions
    * alerts if main trail has not delivered results within the last 12 hours
    * warns that account may need to have multi-region trail added if no global and multi-region trail is found
* VPC
  * Network ACLs
    * checks that [baseline network ACL](https://confluence.cornell.edu/display/CLOUD/Baseline+AWS+Network+ACL) is present in all regions
  * Flow logs
    * Since there is not yet a Cornell standard flow log configuration deployed, simple identify any existing flow logs, or state that there are none.

Add your ideas for additional checks as issues to this repo.

### Notes ###

The check-aws.rb script will alert on CloudTrail configs that uses one trail for each region. We are transitioning to the multi-region style of trail, and not all accounts are transitioned yet.

## How do I run it? ##

#### Prerequisites ####

* AWS credentials should be setup for AWS CLI and scripts as described as in  http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html. As written, the code will use the credentials under your "default" profile.
* You need Ruby installed on your system. This script was developed using Ruby 2.3.0p0.
* You need the following Gems on your system:
  * aws-sdk (2.2.32)
  * aws-sdk-core (2.2.32)
  * aws-sdk-resources (2.2.32)
  * To install these execute `$ gem install aws-sdk`

#### Running the code ####

```
$ ./check-aws.rb
```

### Who do I talk to about this project? ###

* Contributions and improvements from the Cornell community are welcome.
* Contact the [Cornell Cloudification Services Team](mailto:cloudification-l@cornell.edu) for more information.
