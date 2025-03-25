---
title: ThunderDome - Flag 2 - Pulled From the Sky
parent: ThunderDome CTF
nav_order: 2
---

# ThunderDome - Flag 2 - Pulled From the Sky
{: .no_toc }

## Table of Contents
1. TOC
{:toc}

---

# Flag 2 - Pulled From the Sky

## Recap

This walkthrough follows on from flag 1 - **Emerge Through the Breach. Let’s recap what we did to capture flag 1:**

![img]({{ '/assets/images/flag2/Untitled.png' | relative_url }}){: .center-image }

## AWS assets from flag 1

In the writeup for flag 1, I gave a little hint of what to expect for flag 2:

> Make a note of the above, it's a snapshot (ahem) of what you'll need for the next flag!
> 

If you didn’t guess, we will be grabbing the snapshot `arn:aws:ec2:us-east-1:211125382880:snapshot/snap-0c241b0d00d234853` which was discovered by our CloudFox enumeration and examining it locally. Here is the CloudFox inventory again to remind you:

```bash
arn:aws:iam::211125382880:user/detective-user
arn:aws:iam::211125382880:user/haru@massive-pharma.com
arn:aws:iam::211125382880:user/nacer@massive-pharma.com
arn:aws:iam::211125382880:user/nina@massive-pharma.com
arn:aws:iam::211125382880:user/sven@massive-pharma.com
arn:aws:ec2:us-east-1:211125382880:image/ami-00568b27b974ba617
arn:aws:ec2:us-east-1:211125382880:snapshot/snap-0c241b0d00d234853
arn:aws:ec2:us-east-1:211125382880:instance/i-0874ad63d9693239c
arn:aws:ec2:us-east-1:211125382880:instance/i-0d67cb27d5cc12605
arn:aws:ec2:us-east-1:211125382880:volume/vol-05ada6051c8801cad
arn:aws:ec2:us-east-1:211125382880:volume/vol-06ca35e92e87b4aac
arn:aws:secretsmanager:us-east-1:211125382880:secret:flag-6LBCtw
arn:aws:secretsmanager:us-east-1:211125382880:secret:aws/haru-yQP4Jm
```

When I was going through the inventory it wasn’t obvious that the next step to finding flag 2 would be the snapshot (although I had a strong suspicion). Let’s have a look at what CloudFox collected in the `loot` directory:

CloudFox suggested some steps which could be taken to attempt Remote Code Execution on the EC2 instances that were discovered - `instance/i-0874ad63d9693239c` and `instance/i-0d67cb27d5cc12605`. Let’s `cat instances-ec2InstanceConnectCommands.txt` and see what it says:

![img]({{ '/assets/images/flag2/Untitled 1.png' | relative_url }}){: .center-image }

The first instance listed is `admin/i-0874ad63d9693239c`. We’ll ignore that as it’s out-of-scope, and look at `web-prod/i-0d67cb27d5cc12605`. Note what the requirements are to connect to `web-prod` :

```bash
You'll need to change the --instance-os-user and --ssh-public-key parameters to match your own setup.
```

At the moment we don’t know the OS user (this varies whether it’s an Amazon Linux box, Ubuntu, Debian, CentOS, etc.) but let’s go with `ec2-user` hoping CloudFox has a funky way of figuring this out.

```bash
└─# ls -l /root/.cloudfox/cloudfox-output/aws/haru-211125382880/loot/                                                                                                               
total 40
-rw-r--r-- 1 root root   27 May 18 15:08 elastic-network-interfaces-PrivateIPs.txt
-rw-r--r-- 1 root root   29 May 18 15:08 elastic-network-interfaces-PublicIPs.txt
-rw-r--r-- 1 root root 1111 May 18 15:07 instances-ec2InstanceConnectCommands.txt
-rw-r--r-- 1 root root   27 May 18 15:07 instances-ec2PrivateIPs.txt
-rw-r--r-- 1 root root   29 May 18 15:07 instances-ec2PublicIPs.txt
-rw-r--r-- 1 root root 2073 May 18 15:07 instances-ssmCommands.txt
-rw-r--r-- 1 root root  787 May 18 15:07 inventory.txt
-rw-r--r-- 1 root root  329 May 16 17:41 network-ports-private-ipv4.txt
-rw-r--r-- 1 root root  331 May 16 17:41 network-ports-public-ipv4.txt
-rw-r--r-- 1 root root  529 May 18 15:08 pull-secrets-commands.txt

```

We see an AWS CLI command leveraging `ec2-instance-connect` - more information here - [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-eic.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-eic.html). This is a simplified way to connect to EC2 instances without having to distribute `ssh` keys. It temporarily pushes your `ssh` public key to an EC2 instance, allowing you establish an `ssh` session. The user trying to do this needs to have the relevant permissions and the EC2 instance needs an appropriate attached role. Here’s the command CloudFox says we should run:

```bash
aws --profile $profile --region us-east-1 ec2-instance-connect send-ssh-public-key --instance-id i-0874ad63d9693239c --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub
```

We’ll run it, substituting `$profile` with `haru` and ensuring we have our `ssh` public key at `~/.ssh/id_rsa.pub`:

![img]({{ '/assets/images/flag2/Untitled 2.png' | relative_url }}){: .center-image }

That didn't work; Haru don’t have permissions to connect this way. Let’s `cat instances-ssmCommands.txt` and what that has to offer:

![img]({{ '/assets/images/flag2/Untitled 3.png' | relative_url }}){: .center-image }

These look like steps leveraging AWS Systems Manager to connect to an EC2 instance. Again, we’ll ignore the steps for `admin/i-0874ad63d9693239c` as it’s out-of-scope. There are two methods mentioned above:

1. Using `ssm start-session` to start an interactive session with an EC2 instance
2. Using `ssm send-command` to send a command to an EC2 instance and `ssm get-command-invocation` to get the output of the previously sent command

<aside>
💡 A quick note on the difference between `ssm start-session` and `ssm send-command` / `ssm get-command-invocation:`

- `ssm start-session` - good for real-time interactive administration
- `ssm send-command` / `ssm get-command-invocation` - good for automation and scripted command execution
</aside>

If we want to use `ssm start-session` we’ll need the AWS CLI session manager plugin - [https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html). The other option is to try and send a command to `web-prod` :

```bash
aws --profile $profile --region us-east-1 ssm send-command --instance-ids i-0d67cb27d5cc12605 --document-name AWS-RunShellScript --parameters commands="aws sts get-caller-identity"
```

Let’s give it a go:

```bash
└─# aws --profile haru --region us-east-1 ssm send-command --instance-ids i-0d67cb27d5cc12605 --document-name AWS-RunShellScript --parameters commands="aws sts get-caller-identity"

An error occurred (AccessDeniedException) when calling the SendCommand operation: User: arn:aws:iam::211125382880:user/haru@massive-pharma.com is not authorized to perform: ssm:SendCommand on resource: arn:aws:ec2:us-east-1:211125382880:instance/i-0d67cb27d5cc12605 because no identity-based policy allows the ssm:SendCommand action
```

![img]({{ '/assets/images/flag2/Untitled 4.png' | relative_url }}){: .center-image }

That didn't work either; Haru doesn’t have permissions to perform `ssm send-command`. Turning our attention to the public IPs, let’s `cat` the `instances-ec2PublicIPs.txt` file:

![img]({{ '/assets/images/flag2/Untitled 5.png' | relative_url }}){: .center-image }

The first IP address is the out-of-scope `admin` box and the second - `web-prod` - is `44.208.228.94` , which is our starting point. We don’t need to go back to that right now. There is an image - `image/ami-00568b27b974ba617` - which I was not able to do anything with, so it looks like that’s not the path we should be going down. 

## Snapshot

It’s probably a good time to turn our attention to the snapshot - `snap-0c241b0d00d234853`. Reading a snapshot typically involves creating a volume from the snapshot and attaching it to an EC2 instance. You can also make it public or share it with an AWS account you own/control. There’s another method which is downloading the snapshot locally. This is what we will focus on.

### Pacu

You can fire up `pacu` (we used it during the flag 1 walkthrough if you remember) and check out these two modules - `ebs__enum_volumes_snapshots` and `ebs__download_snapshots`. Run the former first then the latter. The output path for enumeration finding is `~/.local/share/pacu/flag1/downloads`:

`ebs__enum_volumes_snapshots`

![img]({{ '/assets/images/flag2/Untitled 6.png' | relative_url }}){: .center-image }

![img]({{ '/assets/images/flag2/Untitled 7.png' | relative_url }}){: .center-image }

`ebs__download_snapshots` (has some bugs but fixed in release 1.5.3)

![img]({{ '/assets/images/flag2/Untitled 8.png' | relative_url }}){: .center-image }

### Dsnap

Instead of `pacu` `ebs__download_snapshots` you can also use `dsnap` (a library used by the `ebs__download_snapshots` module). You can find more information about it here - [https://github.com/RhinoSecurityLabs/dsnap](https://github.com/RhinoSecurityLabs/dsnap). Why would you use one over the other? Well, according the docs:

> [https://github.com/RhinoSecurityLabs/dsnap?tab=readme-ov-file#pacu-integration](https://github.com/RhinoSecurityLabs/dsnap?tab=readme-ov-file#pacu-integration)
> 
> 
> *This project is used by [Pacu](https://github.com/RhinoSecurityLabs/pacu) in the [ebs__download_snapshots](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details#ebs__download_snapshots) module. The primary benefit of using the Pacu module is to reduce unnecessary API call's, as a tradeoff it doesn't have some niceties that are included with dsnap.*
> 
> *For example the Pacu module reuses snapshots gathered from [ebs__enum_volumes_snapshots](https://github.com/RhinoSecurityLabs/pacu/wiki/Module-Details#ebs__enum_volumes_snapshots), this prevents looking up snapshots more often then needed. At the moment it does not support some dsnap features like creating temporary snapshots or searching for snapshots by instance ID, this however may change in the future.*
> 

If you are conducting a penetration test or taking part in a CTF, you’re probably not too concerned about noise (unnecessary API calls) so `dsnap` would be a simpler choice. After installing `dsnap` as per the instructions in the aforementioned link, we can list and download the snapshot.

Set AWS credentials and list the snapshot with `dsnap list` :

![img]({{ '/assets/images/flag2/Untitled 9.png' | relative_url }}){: .center-image }

Download the snapshot with `dsnap get` :

![img]({{ '/assets/images/flag2/Untitled 10.png' | relative_url }}){: .center-image }

You should now have the snapshot downloaded to your current working directory:

![img]({{ '/assets/images/flag2/Untitled 11.png' | relative_url }}){: .center-image }

### Build docker container

We will be mounting the snapshot on a docker container so follow the instructions in this link to build the docker container we will be using to mount the snapshot - [https://github.com/RhinoSecurityLabs/dsnap?tab=readme-ov-file#mounting-with-docker](https://github.com/RhinoSecurityLabs/dsnap?tab=readme-ov-file#mounting-with-docker):

```bash
git clone https://github.com/RhinoSecurityLabs/dsnap.git
cd dsnap
make docker/build
```

### Run docker container and mount snapshot

```bash
docker run -it -v "/root/thunderdome/flag2/snap-0c241b0d00d234853.img:/disks/snap-0c241b0d00d234853.img" -w /disks dsnap-mount --ro -a "snap-0c241b0d00d234853.img" -m /dev/sda1:/
```

![img]({{ '/assets/images/flag2/Untitled 12.png' | relative_url }}){: .center-image }

### A word on `guestfish` from the Interwebs:

> `Guestfish` is a command-line shell and scripting tool used to access and manipulate virtual machine disk images and filesystems. It is part of the **`libguestfs`** suite, which provides a set of tools for accessing and modifying virtual machine (VM) disk images without the need to boot the VM
> 

For the most part, typical `Linux` commands work but there are some nuances, e.g.:

![img]({{ '/assets/images/flag2/Untitled 13.png' | relative_url }}){: .center-image }

So if you were to `ls` a user’s home directory, hidden files are returned by default (on a typical `Linux` box you’d run something like `ls -la` ):

![img]({{ '/assets/images/flag2/Untitled 14.png' | relative_url }}){: .center-image }

Also, as per the `help ls` output above, there is no current working directory, so a `pwd` would return an error:

![img]({{ '/assets/images/flag2/Untitled 15.png' | relative_url }}){: .center-image }

So you can’t `cd` to a directory but you can `ls` it:

![img]({{ '/assets/images/flag2/Untitled 16.png' | relative_url }}){: .center-image }

Let’s note the hostname

![img]({{ '/assets/images/flag2/Untitled 17.png' | relative_url }}){: .center-image }

We’ve seen this IP address before, it’s an internal DNS hostname for an EC2 instance - we saw it during out `nmap` output for flag1:

```json
Service Info: Host: ip-172-31-90-229.ec2.internal
```

This is the private IP address for `web-prod` , the box that hosts the Massive Pharma website. We know that the public IP address for `web-prod`was `44.208.228.94`, so to double check we can run this command using Haru’s credentials we collected for flag 1. We have already gathered the AWS region is us-east-1 from various sources (the console and the EC2 RCE scripts discussed above):

```bash
aws ec2 describe-instances --region us-east-1 --profile haru --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name'].Value|[0],PublicIpAddress:PublicIpAddress,PrivateIpAddress:PrivateIpAddress}" --output table
```
![img]({{ '/assets/images/flag2/Untitled 18.png' | relative_url }}){: .center-image }

As we can see the IP address in the `cat /etc/hostname` output matches the name and public IP address for `web-prod` . We can conclude that we are browsing a snapshot of the `web-prod` instance.

## Looking for loot in the snapshot

There are a number of key files and directories we want to look at. Here’s a quick list (certainly not definitive) of some that would be of particular interest to us in finding the flag and information that would help us with the next flag(s). I’ve limited the commands to `ls` and `cat` due to a restricted shell:

```bash
ls /root
ls /root/.ssh
cat /root/.ssh/id_rsa
cat /root/.ssh/authorized_keys
ls /home
ls /home/<user>/.aws
cat /home/<user>/.aws/credentials
ls /home/<user>/.azure
ls /home/<user>/.config/gcloud/
cat /home/<user>/.config/gcloud/credentials.db
cat /home/<user>/.ssh/id_rsa
cat /home/<user>/.ssh/authorized_keys
cat /home/<user>/.ssh/known_hosts
cat /etc/environment
cat /home/<user>/.bash_history
cat /etc/passwd
cat /etc/group
cat /etc/crontab
ls /var/log
ls /var/spool/cron/crontabs
cat /etc/hosts
```

### Let’s have a look around

The root file system:

![img]({{ '/assets/images/flag2/Untitled 19.png' | relative_url }}){: .center-image }

List the contents of `/root` :

![img]({{ '/assets/images/flag2/Untitled 20.png' | relative_url }}){: .center-image }

AWS credentials belonging to `root`:

![img]({{ '/assets/images/flag2/Untitled 21.png' | relative_url }}){: .center-image }

```bash
aws_access_key_id = AKIATCKANV3QM4E6RKFP
aws_secret_access_key = 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
```

![img]({{ '/assets/images/flag2/Untitled 22.png' | relative_url }}){: .center-image }

We have AWS credentials for Haru from the previous flag. I browsed through the `haru` and the `ubuntu` directories but didn’t find anything interesting. In `nacer` ’s directory, however, we find AWS access keys. These could prove useful so we’ll add them to our loot stash.

![img]({{ '/assets/images/flag2/Untitled 23.png' | relative_url }}){: .center-image }

![img]({{ '/assets/images/flag2/Untitled 24.png' | relative_url }}){: .center-image }

```bash
aws_access_key_id = AKIATCKANV3QAD7S2SGU
aws_secret_access_key = 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
```

Speaking of AWS access keys, looking at root’s `crontab` it seems they are rotated periodically for user `nacer` on the host. This is information that might be useful later: 

![img]({{ '/assets/images/flag2/Untitled 25.png' | relative_url }}){: .center-image }

We also have Nacer’s `ssh` key which we’ll try out a bit later:

![img]({{ '/assets/images/flag2/Untitled 26.png' | relative_url }}){: .center-image }

We have Nacer’s  Azure environment configuration. The following shows the tenant ID and a subscription ID:

![img]({{ '/assets/images/flag2/Untitled 27.png' | relative_url }}){: .center-image }

In `/home/nacer/.azure/msal_token_cache.json`we discover Nacer’s Azure credentials - this is a significant find. It will help us move laterally within the organisation, gather and exfiltrate sensitive data and transition to another Cloud provider. We may be able to leverage the refresh token to obtain an access token which will not only allow access to Azure resources, but also M365 resources such Teams chats and Outlook emails. For more information on the differences between access tokens and refresh tokens, checkout this lab - [https://pwnedlabs.io/labs/phished-for-initial-access](https://pwnedlabs.io/labs/phished-for-initial-access).

![img]({{ '/assets/images/flag2/Untitled 28.png' | relative_url }}){: .center-image }

## Checkout what we can do with the ssh key

<aside>
💡 Remember to `chmod 600` the ssh key before using it.

</aside>

At this point you would normally try to gain situational awareness and look for ways to escalate privileges using a combination of manual exploration (see the “*Looking for loot in the snapshot”* section above) and tools. To check what tools exist on the box that we may be able to leverage you can run the following one-liner (taken from here - [https://book.hacktricks.xyz/linux-hardening/privilege-escalation#useful-software](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#useful-software)):

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

![img]({{ '/assets/images/flag2/Untitled 29.png' | relative_url }}){: .center-image }

![img]({{ '/assets/images/flag2/Untitled 30.png' | relative_url }}){: .center-image }

We can see a few tools above that would definitely come in handy. Depending on permissions and egress restrictions, you could pull software on to the host via `curl` or `wget`, or use `netcat` to run a port scan, exfiltrate data, and a lot more. 

We’re not going to spend too much time on the box, but  let’s look around some more and check for `ssh` keys. Something to note about running `ls` with a wildcard `*`against directories belonging to other users is that it doesn’t return an output for directories to which you don’t permissions, even if the path exists:

```bash
ls -alh /home/*/.ssh/
```

![img]({{ '/assets/images/flag2/Untitled 31.png' | relative_url }}){: .center-image }

We see keys for `nacer` but we already have this key, so let’s move on and look for Cloud credentials in the default locations:

```bash
ls -alh /home/*/.aws/
ls -alh /home/*/.azure
ls -alh /home/*/.config/gcloud/
```

![img]({{ '/assets/images/flag2/Untitled 32.png' | relative_url }}){: .center-image }

The above shows we’ve found AWS credentials and Azure credentials for `nacer` . Let’s have a closer look:

![img]({{ '/assets/images/flag2/Untitled 33.png' | relative_url }}){: .center-image }

Let’s see if any AWS credentials are currently active on the box:

![img]({{ '/assets/images/flag2/Untitled 34.png' | relative_url }}){: .center-image }

From the above output we have the following AWS information:

- Username `nacer@massive-pharma.com`
- AWS account ID `211125382880`

Remember banner when we logged into the box via `ssh` ?

![img]({{ '/assets/images/flag2/Untitled 35.png' | relative_url }}){: .center-image }

We saw that this was done via a `cron` job (refer to the output of `cat /var/spool/cron/crontabs/root` in the snapshot above). This means that although we can use the above AWS credentials and enumerate from our attacker machine, we need to be aware  the credentials are time-bound (rotated daily). Also, there may be ABAC (Attribute Based Access Control) `Condition` definitions applied to resource policies (such as `aws:SourceVpc` or `aws:SourceIp`) which could prevent our enumeration attempts outside of the host (these would have been fundamental in limiting the blast radius of the Capital One breach, but that’s another story). With that said, let's use the AWS credentials on our local machine and come back to `web-prod` if need be. 

Let’s configure Nacer’s credentials locally and see if we can list S3 buckets:

![img]({{ '/assets/images/flag2/Untitled 36.png' | relative_url }}){: .center-image }

![img]({{ '/assets/images/flag2/Untitled 37.png' | relative_url }}){: .center-image }

We get an `AccessDenied`. Let’s see if this has anything to do with IAM Condition definitions we were talking about earlier (such as `aws:SourceVpc` or `aws:SourceIp`) and run the same command on `web-prod` :

![img]({{ '/assets/images/flag2/Untitled 38.png' | relative_url }}){: .center-image }

We still get an `AccessDenied` so it may be related to Nacer’s permissions. I tried various `aws cli` commands to view permissions, and also tried `iam simulate-principal-policy` but no joy (looks like Nacer is lacking permissions like `iam:ListUserPolicies` and `iam:ListAttachedUserPolicies`). We’ll have to do some manual enumeration. Since listing S3 buckets is not allowed, how about listing a particular S3 bucket? We’ll need a bucket in the account to try this with… remember the one we gathered from one of the Bitbucket commits in flag 1? It was `mp-clinical-trial-data` . Let’s try the command again but this time we’ll mention this bucket specifically:

![img]({{ '/assets/images/flag2/Untitled 39.png' | relative_url }}){: .center-image }

Success. But wait, why weren’t we able to execute `aws s3 ls` but were able to execute `aws s3 ls mp-clinical-trial-data` ? This may be because Nacer does not have **`s3:ListAllMyBuckets` permissions but he does have `s3:ListBucket` permissions for** `mp-clinical-trial-data` specifically. 

Let’s download all the content in `mp-clinical-trial-data` to our local machine. We can do this by running `aws s3 sync s3://mp-clinical-trial-data . --profile nacer`. Something to note is that `aws s3 sync` works recursively by default. We should now see the following:

![img]({{ '/assets/images/flag2/Untitled 40.png' | relative_url }}){: .center-image }

Okay, if we check the contents of those directories we see:

![img]({{ '/assets/images/flag2/Untitled 41.png' | relative_url }}){: .center-image }

There’s the second flag! But we're never done with just the flag, we need something that will help us move deeper within Massive Pharma. Grab the flag, submit it, and have a look at the `.csv` file:

![img]({{ '/assets/images/flag2/Untitled 42.png' | relative_url }}){: .center-image }

The file looks like it’s a list of clinical trial candidates and their medical information. Not information which should be readily available, but of no use to us at the moment. Let’s turn our attention to `admin-temp`. We see a file called `openemr-5.0.2.tar.gz`. We’ll extract this see what we can find:

![img]({{ '/assets/images/flag2/Untitled 43.png' | relative_url }}){: .center-image }

Ok, so what’s `OpenEMR`? Apparently it’s “*a Free and Open Source electronic health records and medical practice management application”*. I had a look around various files and directories but didn’t find anything interesting. I ran `TruffleHog` against the directory but nothing particularly helpful was flagged -  `./trufflehog filesystem <path>/mp-clinical-trial-data/admin-temp/openemr-5.0.2/`. It did, however, report `Detector Type: SQLServer` entries so that’s something we should probably note:

![img]({{ '/assets/images/flag2/Untitled 44.png' | relative_url }}){: .center-image }

## What about the Azure credentials we found?

Heading back to `web-prod` we can also check if any Azure credentials are currently active on the box:

![img]({{ '/assets/images/flag2/Untitled 45.png' | relative_url }}){: .center-image }

From the above output we have the following Azure information:

- User `nacer@massive-pharma.com`
- Tenant `2522da8b-d801-40c4-88bf-1944eae9d237`
- Subscription `41b63b94-5bb3-41b2-a2ad-2b411979dc26`

### What can we do with the active credentials on the box?

Trying to pull the active access token via `az account get-access-token` failed, likely due to permissions issues on the `msal_token_cache.json` file. We can, however, `cat` the file. Let’s grab the output and keep it on our local machine. If you remember we found Azure credentials in the snapshot as well, so we’ll keep both in our loot. Let’s move on from `web-prod` for now and see what we can do with the Azure credentials we’ve found  - we’ll do this in the walk-through for flag3, see you then!
