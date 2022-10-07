# GCP Plugin

## Destination
The destination plugin allows certificates to be uploaded to a given GCP account.
Currently there are 2 ways to authenticate against GCP. Via vault using [Google Cloud 
Secrets engine](https://www.vaultproject.io/docs/secrets/gcp) or by using [service account credentials](https://cloud.google.com/iam/docs/service-accounts).

#### Authentication by Vault
When setting up the new destination in the lemur console set the "using vault" value to True. 
Then enter the path to your secret credentials. Lemur will use this token to authenticate API requests.

#### Authentication by Service Account Credentials
In the GCP console generate a new set of Service Account Credentials. Store the json token on your server. Go to ADMIN > DESTINATIONS > CREATE, choose GCP as the plugin and "Service Account Token" for the "Authentication Method".
In the field labeled "Service Account Token Path" enter in the path to where you copied your auth json. eg: `/tmp/authentication.json`.


#### Testing Destination plugin locally
1. In the GCP console create a [service account](https://cloud.google.com/iam/docs/service-accounts) with the proper permissions for uploading a certificate. 
2. Create a key associated with the account that was created from step 1. Save the JSON key file locally and copy it into your local Lemur Dockerfile.
   1. ```COPY {path to key}/authentication.json /tmp/authentication.json```
3. Start your docker container and login to the lemur console. Go to ADMIN > DESTINATIONS > CREATE, choose GCP as the plugin and "Service Account Token" for the "Authentication Method".
In the field labeled "Service Account Token Path" enter in the path to where you copied your auth json. eg: `/tmp/authentication.json`.

## Source
The source plugin allows Lemur to discover certificates and endpoints in a given GCP account.
Authentication is handled the same way as the destination plugin. The plugin currently supports
fetching global endpoints (i.e. global HTTPS proxies and global SSL proxies).

#### Testing Source plugin locally
See `Testing Destination plugin locally`. By default, the source sync is done every 15 minutes.
You can override this to be every 1 minute in `docker/entrypoint` and set the following:

```text
cron_sync="${CRON_SYNC:-"*/1 * * * *"}"
```
