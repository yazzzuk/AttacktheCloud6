---
title: ThunderDome -  Flag 3 - An Absent Defense
parent: ThunderDome CTF
nav_order: 3
---

# ThunderDome -  Flag 3 - An Absent Defense
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Recap

Right, so let’s continue from where we left off in the flag 2 walkthrough. We found the second flag in an S3 bucket - `mp-clinical-trial-data`. We also found Nacer’s Azure credentials in the snapshot we pulled from the AWS account as well as on the `web-prod` host. Let’s try the tokens we found in the snapshot first and see how we get on. 

## Refresh token

From the `msal_token_cache.json` file, we can pull out the refresh token and exchange it for an access token . Refer to this lab for a refresher on refresh and access tokens: [https://pwnedlabs.io/labs/phished-for-initial-access](https://pwnedlabs.io/labs/phished-for-initial-access):

![img]({{ '/assets/images/flag3/Untitled.png' | relative_url }}){: .center-image }

> You might be wondering - “*surely the refresh token has expired by now*?” Well, Microsoft 365/Azure AD refresh tokens typically have a default lifetime of 90 days. Within this period you can use the refresh token to obtain a new access token. If the refresh token is used continuously (before the 90 day expiry), the default lifetime is extended by 90 days with the `Sliding Window` mechanism. Technically, you can keep using the refresh token until it expires or is revoked. For more information checkout these links:
> 

https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens

https://learn.microsoft.com/en-us/microsoft-365/enterprise/session-timeouts?view=o365-worldwide

https://learn.microsoft.com/en-us/answers/questions/873977/is-there-a-concept-of-refresh-token-sliding-window

## Exchange refresh token for an access token

As discussed, we need to try and exchange this refresh token for an access token. The access token contains a *scope* which defines the level and breadth of access for the user the token belongs to. To get started, we’ll need TokenTacticsV2, which you’ll find here: [https://github.com/f-bader/TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2). We’ll be using PowerShell which you can run on a Windows box or Linux (I ran it on my Kali instance):

```bash
git clone https://github.com/f-bader/TokenTacticsV2
cd TokenTacticsV2/
pwsh # PowerShell on Linux
Import-Module ./TokenTactics.psm1
```

![img]({{ '/assets/images/flag3/Untitled 1.png' | relative_url }}){: .center-image }

We then run the `Invoke-RefreshToMSGraphToken` command to exchange Nacer’s refresh token for a token we can use with `MSGraph` (Microsoft Graph). `MSGraph` is an API which leverages OAuth 2.0. It allows people (both legit and dodgy) to access Microsoft 365 data and services. The complete command is as follows (note the `-domain massive-pharma.com`):

```powershell
Invoke-RefreshToMSGraphToken -domain massive-pharma.com -refreshToken "<token>"
```

Now this is interesting. We get an error which states the refresh token has expired due to inactivity and because it was `inactive for 90.00:00:00` (remember I said that typically the default lifetime is 90 days):

![img]({{ '/assets/images/flag3/Untitled 2.png' | relative_url }}){: .center-image }

This refresh token may have expired, but we have another option - remember the Azure credentials we found in Nacer’s home directory when we `ssh`-ed to `web-prod` for flag 2? We can use the refresh token from the `msal_token_cache.json` file we found or just jump back onto `web-prod` again and grab the latest credentials. We have an `ssh` key which gives us persistence as Nacer:

![img]({{ '/assets/images/flag3/Untitled 3.png' | relative_url }}){: .center-image }

Grab the `refresh_token` and run the command again:

![img]({{ '/assets/images/flag3/Untitled 4.png' | relative_url }}){: .center-image }

Looking at the scope above, some key resources stand out:

- Mail
    - `https://graph.microsoft.com/Mail.ReadWrite`
    - `https://graph.microsoft.com/Mail.Send`
- Teams
    - `https://graph.microsoft.com/TeamMember.ReadWrite.All`
    - `https://graph.microsoft.com/TeamsTab.ReadWriteForChat`
- Users
    - `https://graph.microsoft.com/User.Read.All`
    - `https://graph.microsoft.com/User.ReadBasic.All`
    - `https://graph.microsoft.com/User.ReadWrite`
    - `https://graph.microsoft.com/Users.Read`
    - `https://graph.microsoft.com/.default`

We now need to grab the `access_token` token. Lets’s do that by running `$MSGraphToken.access_token`: 

![img]({{ '/assets/images/flag3/Untitled 5.png' | relative_url }}){: .center-image }

We’ll leave the PowerShell terminal tab running and open a new terminal tab. Before we do that, let’s copy the access token so we can store it in an environment variable, e.g.,  `NACER_AZ_TOKEN`:

![img]({{ '/assets/images/flag3/Untitled 6.png' | relative_url }}){: .center-image }

Let’s test the access token by `cURL`-ing the `MSGraph` endpoint referencing the `NACER_AZ_TOKEN` variable (I have `jq` installed):

```bash
curl -s -H "Authorization: Bearer $NT" -H "Content-Type: application/json" https://graph.microsoft.com/v1.0/me | jq
```

![img]({{ '/assets/images/flag3/Untitled 7.png' | relative_url }}){: .center-image }

Success. We know the access token works. Instead of using my favourite `cURL` all the things approach, let’s look at some tools we can use to interact with the `MSGraph` API.

## M365 pillaging

When looking for tools to leverage, we need to consider things such as what loot we currently have. For example, we don't have Nacer’s login credentials at present, but we have an MSGraph access token, so we need a tool that supports access tokens. A very useful post-exploitation tool we can use to quickly pillage some M365 loot is GraphRunner - [https://github.com/dafthack/GraphRunner](https://github.com/dafthack/GraphRunner). We’ll download it and run the GraphRunner GUI (`firefox GraphRunner/GraphRunnerGUI.html`).

In the first field `Access Token` paste the access token you saved in the `NACER_AZ_TOKEN` variable and hit `Parse Token`:

![img]({{ '/assets/images/flag3/Untitled 8.png' | relative_url }}){: .center-image }

We can confirm the access token is an MSGraph token, the scope (our permissions) and the Tenant ID.

Scroll a little further down to `Directory - Users` and click `List Users`:

![img]({{ '/assets/images/flag3/Untitled 9.png' | relative_url }}){: .center-image }

From the above we know Nacer has permissions to list users in the Tenant Directory. Add the users to your loot stash and save them in a file called `flag3_users.txt`.

Under `Directory - Groups` , click `List Groups`:

![img]({{ '/assets/images/flag3/Untitled 10.png' | relative_url }}){: .center-image }

We observe from the above that besides the `General` group, Nacer is a member of the `IT-Admins` and `Engineering-Managers` groups. We’ll make a note of that and add that information to our loot stash as well.

Next, we get to something very interesting - Nacer’s emails. Under `Email Viewer (Current User)` click on `Fetch Emails`:

![img]({{ '/assets/images/flag3/Untitled 11.png' | relative_url }}){: .center-image }

We have Nacer’s emails! There’s something about an AWS/Azure DR plan - this is interesting information as it confirms the multi-cloud footprint we’ve discovered and suggests further integration to explore. Scanning through the emails, something important stands out:

![img]({{ '/assets/images/flag3/Untitled 12.png' | relative_url }}){: .center-image }

It looks like there’s an application called `PHARSIGHT` and the password for “*the user*” is `$MPappdev1`. We’ll add that information to our loot stash. Let’s come back to the other GraphRunner functions later, we have enough to move forward for now. 

To recap, we have the following loot:

- Nacer’s user/email address - [`nacer@massive-pharma.com`](mailto:nacer@massive-pharma.com)
- Nacer’s MSGraph access token
- A list of users/email addresses in the Azure Tenant `2522da8b-d801-40c4-88bf-1944eae9d237`
- A password - `$MPappdev1`

## Password spraying

Since we have a password and a bunch of usernames, it makes sense to try password spraying (using one or a few passwords against a larger number of usernames). With a password spray attack (well it’s not an attack per se, it’s a technique which is a means to an attack) there is less chance of locking out an account but it can still be picked up by security tools.

Let’s carry out our password spray using the `flag3_users.txt` file we created earlier and a tool called `MSOLSpray` - [https://github.com/dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray). Once you’ve downloaded it, import the module and start the password spray:

```powershell
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList ./flag3_users.txt -Password '$MPappdev1'
```

![img]({{ '/assets/images/flag3/Untitled 13.png' | relative_url }}){: .center-image }

We get a hit for `yuki`! Let’s see if we can log into the Azure portal with the credentials we’ve found:

- [`yuki@massive-pharma.com`](mailto:yuki@massive-pharma.com)
- `$MPappdev1`

Success! We can log into the portal:

![img]({{ '/assets/images/flag3/Untitled 14.png' | relative_url }}){: .center-image }

Looking at the at recent services visited under `Resources`, a couple of resources standout:

- Storage account - `mpprod`
- Function App - `pharsight-dev`

## Azure Storage Account

Let’s have a look at the storage account. An Azure storage account is a unique namespace (similar concept to AWS S3) which is used for the purpose of storing data. In a storage account you’ll find “*containers*” which contain (funnily enough) files and objects called “*blobs*”.  

![img]({{ '/assets/images/flag3/Untitled 15.png' | relative_url }}){: .center-image }

The `$logs` container above was empty, `portal-storage` contained a blob called `export-users.sh`:

![img]({{ '/assets/images/flag3/Untitled 16.png' | relative_url }}){: .center-image }

Let’s download this file and see what’s in it:

```bash
#!/bin/bash

DB_NAME="portal"
TABLE_NAME="users"
EXPORT_FILE="users_export_$(date +%Y%m%d).csv"
CONTAINER_NAME="portal-storage"
STORAGE_ACCOUNT="mpprod"
RESOURCE_GROUP="MP-PROD1"
CONNECTION_STRING=$(az storage account show-connection-string --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query connectionString --output tsv)

PGPASSWORD=<password> pg_dump -h your_host -U nacer -d $DB_NAME -t $TABLE_NAME --csv > $EXPORT_FILE

if [ ! -f $EXPORT_FILE ]; then
    echo "Export failed."
    exit 1
fi

az storage blob upload --connection-string $CONNECTION_STRING --container-name $CONTAINER_NAME --file $EXPORT_FILE --name $EXPORT_FILE

rm $EXPORT_FILE

```

The above script exports the `users` table from the `portal` database to a `csv` file, uploads the file to the `mpprod` storage account, under the `portal-storage` container. 

In the screenshot of the `portal-storage` container above, there was a toggle switch to show deleted blobs. Let’s turn this on to see if anything interesting pops up:

![img]({{ '/assets/images/flag3/Untitled 17.png' | relative_url }}){: .center-image }

It looks like blob versioning has been enabled under “Data protection” because a previously deleted blob appears. Let’s download that and check out the contents. Click on the blob `users_export_20240202.csv`, click on the “*Versions*” tab and then “*Download*”.

![img]({{ '/assets/images/flag3/Untitled 18.png' | relative_url }}){: .center-image }

## Hashcat

Looks like we found more credentials! The file appears to be users, usernames and (potentially) hashed passwords. Let’s get cracking - dump the hashes to a file:

```bash
awk -F, '{print $4}' users_export_20240202.csv | sed '1d' > flag3_hashes.txt
```

The above prints the 4th comma separated item, removes the first line (column heading) and redirects what’s left to a file called `flag3_hashes.txt`. Run `hashid` against one of the hashes:

![img]({{ '/assets/images/flag3/Untitled 19.png' | relative_url }}){: .center-image }

Looks like a 256-bit hash. We’re going to use `hashcat` to crack the hashes so we’ll use the `-m 1400` flag to denote a 256-bit hash and `-a 0` to specify a standard dictionary attack. For more information check out `Hash modes` and `Attack Modes` with `hashcat --help`:

```bash
hashcat -m 1400 -a 0 flag3_hashes.txt /<path to>/rockyou.txt
```

I used the `rockyou.txt` wordlist which has been around for a while now. There are other newer (and more specific) wordlists available for security research but for CTFs `rockyou.txt` does the job. When `hashcat` finishes we see the following:

```bash
75587e5e2c48b2be2ff1db3f279bf106943fbc0e1e1e7ed9228c5d8741302846:biotch#1

```

The password for hash `75587e5e2c48b2be2ff1db3f279bf106943fbc0e1e1e7ed9228c5d8741302846` is `biotch#1`. To check what user this hash is for, `grep` the hash against the `users_export_20240202.csv` file:

![img]({{ '/assets/images/flag3/Untitled 20.png' | relative_url }}){: .center-image }

The password is for the Test Acc user - [`testacc@massive-pharma.com`](mailto:testacc@massive-pharma.com). We’ll add this username and password to our loot.

## Azure Function App

Let’s turn our attention to the Function App `pharsight-dev`.

![img]({{ '/assets/images/flag3/Untitled 21.png' | relative_url }}){: .center-image }

Note the `URL` above as well as the Operating System - Windows. This is useful information, remember it and add it to your recon notes (you’re taking notes, right?).

We also see the following function:

![img]({{ '/assets/images/flag3/Untitled 22.png' | relative_url }}){: .center-image }

With Azure Function Apps, functions can be exposed as `http` endpoints and accessed via a URL. If no custom routes are defined, the default URL to invoke the `HttpPharSightTrigger01` function would be [`https://pharsight-dev.azurewebsites.net/api/HttpPharSightTrigger01`](https://pharsight-dev.azurewebsites.net/api/HttpPharSightTrigger01).

Let’s test this in the browser:

![img]({{ '/assets/images/flag3/Untitled 23.png' | relative_url }}){: .center-image }

We can see from the above that the endpoint accepts a variable called `trialname`. Let’s find out if it’s vulnerable to injection attacks. Since the endpoint returns the message `enter a clinical trial name to return a list of participants and health information` this means it’s highly likely it’s pulling the information from a database. Since we’re dealing with Azure, it may be CosmosDB (NoSQL) or SQL Server. Remember in flag 2 where TruffleHog found `Detector Type: SQLServer` entries? With this bit of intel, let’s fire up Burp Suite and see what we can do with SQL injection.

With Burp running, `cURL` the endpoint (your port configuration may differ, 8080 is default):

```bash
curl -k -x http://127.0.0.1:8080 -L https://pharsight-dev.azurewebsites.net/api/HttpPharSightTrigger01
```

Check the request in Burp and send it to Repeater:

![img]({{ '/assets/images/flag3/Untitled 24.png' | relative_url }}){: .center-image }

## SQL injection

Let’s change the method to `POST`, add the `trialname` parameter with a SQL injection payload and add a `Content-Type: application/json` HTTP Header setting since we’re making an API call, and `json` is a common API data format. When we send the request we get:

![img]({{ '/assets/images/flag3/Untitled 25.png' | relative_url }}){: .center-image }

Nothing. Before we move on to another payload, let’s try and change our request in case the API accepts a different data format (`x-www-form-urlencoded` , `application/xml` , etc.). Modifying the header setting to `Content-Type: application/x-www-form-urlencoded` and sending the request again gives us:

![img]({{ '/assets/images/flag3/Untitled 26.png' | relative_url }}){: .center-image }

Success! Looks like the API has returned data related to people participating in medical trials. There are plenty of SQL injection tutorials out there (Port Swigger is a good start) but the payload we sent essentially says for `trialname` if `1=1`, return the entry, so you’ll see entries for various different `trialname`s.

Although we have managed to get a bunch of sensitive data, there’s nothing interesting in the output and no flag; however, we have confirmed the endpoint is vulnerable to SQL injection - to be specific, boolean-based injection. Let’s try another type of injection - time-based. This type of injection uses SQL commands to trigger delays, allowing an attacker to infer certain information based on the delay in response from the database. We’ll send another request to the endpoint but this time with the payload `"' WAITFOR DELAY '0:0:10';--"`. This causes the database to wait for 10 seconds before proceeding with the next operation. I chose 10 seconds as a conservative number because it shows an obvious delay and allows for latency. Let’s send this request:

![img]({{ '/assets/images/flag3/Untitled 27.png' | relative_url }}){: .center-image }

We get a response - check the time it took:

![img]({{ '/assets/images/flag3/Untitled 28.png' | relative_url }}){: .center-image }

As you can see, the response took just over 10 seconds. We’ll use `SQLMap` to exploit this vulnerability. Save the request to `flag3sql.r` - right click on the request and select “Copy to file”. Edit the file and replace the SQL injection payload with something like `test` (SQLMap doesn’t like the payload in the request file). The file should look like this:

```bash
POST /api/HttpPharSightTrigger01 HTTP/1.1
Host: pharsight-dev.azurewebsites.net
User-Agent: curl/8.5.0
Accept: */*
Connection: keep-alive
Content-Length: 52
Content-Type: application/x-www-form-urlencoded

{"trialname": "test"}
 
```

Run SQLMap with the following command:

```bash
sqlmap -r flag3sql.r --batch --technique=T -p "trialname" --skip-urlencode --dbs
```

> Note - we’re using time-based injection so the following SQLMap activities may take a while.

Also note - multi-threading (`--threads`) is not recommended for time-based attacks as it can lead to inaccurate results. If you do use multithreading, SQLMap will disable it by default when you use the `--batch` flag.

If you quit SQLMap and come back to it later, you can find previous activity under `<user path>/.local/share/sqlmap/output/pharsight-dev.azurewebsites.net/log`
> 

Explanation of the flags used:

`--batch` - skips user prompts.

`--technique` - only use technique specified. In this case `-T` or time-based.

`-p` - parameter to target.

`--skip-urlencode` - skip URL encoding.

`--dbs` - enumerate databases.

Let’s look at the result:

![img]({{ '/assets/images/flag3/Untitled 29.png' | relative_url }}){: .center-image }

As you can see, three databases were found:

```bash
available databases [3]:
[*] master
[*] pharsight-srv-1
[*] tempdb
```

I didn’t find anything useful in `master` or `tempdb`. Let’s focus on `pharsight-srv-1` . We have the database we’re going to target, now we need to dump the tables in the database. We can do that with:

```bash
sqlmap -r flag3sql.r --batch --technique=T -p "trialname" --skip-urlencode -D pharsight-srv-1 --tables
```

![img]({{ '/assets/images/flag3/Untitled 30.png' | relative_url }}){: .center-image }

## Flag

Three tables were found. We’re interested in `appusers` . Let’s dump the the table:

```bash
sqlmap -r flag3sql.r --batch --technique=T -p "trialname" --skip-urlencode -D pharsight-srv-1 -T appusers --dump
```

![img]({{ '/assets/images/flag3/Untitled 31.png' | relative_url }}){: .center-image }

Two entries are returned, one of which is flag 3! We also see a username and password for Nina - add that to your loot, you’ll need that as we move on to flag 4. She sells sea shells by the ~~sea shore~~ Win-dows.
