# Okta IDX Embedded Auth with SDK Sample

## Introduction

> :grey_exclamation: The use of this Sample uses an SDK that requires usage of the Okta Identity Engine.
This functionality is in general availability but is being gradually rolled out to customers. If you want
to request to gain access to the Okta Identity Engine, please reach out to your account manager. If you
do not have an account manager, please reach out to oie@okta.com for more information.

This Sample Application will show you the best practices for integrating Authentication into your app
using [Okta's Identity Engine](https://developer.okta.com/docs/concepts/ie-intro/). Specifically, this
application will cover some basic needed use cases to get you up and running quickly with Okta.
These Examples are:
1. Sign In
2. Sign Out
3. Sign Up
4. Sign In/Sign Up with Social Identity Providers
5. Sign In with Multifactor Authentication using Email or Phone

For information and guides on how to build your app with this sample, please take a look at the [Java
guides for Embedded Authentication](link to DevDoc SBS guide)

## Prerequisites

- [JDK 8](#jdk-8) or later
- [Apache Maven](#apache-maven) 3.6.x or later

## Installation & Running The App

1. Build the project from root level (see [here](https://github.com/okta/okta-idx-java/tree/direct-auth#building-the-sdk))
2. Navigate to folder `samples/embedded-auth-with-sdk` and run the below `mvn` command:

```bash
cd samples/embedded-auth-with-sdk/
mvn -Dokta.idx.issuer=https://{yourOktaDomain}/oauth2/default \
    -Dokta.idx.clientId={clientId} \
    -Dokta.idx.clientSecret={clientSecret} \ 
    -Dokta.idx.scopes="space separated scopes" 
    -Dokta.idx.redirectUri={redirectUri}
```

(or) set the below env variables and run `mvn`

```
export OKTA_IDX_ISSUER=https://{yourOktaDomain}/oauth2/default
export OKTA_IDX_CLIENTID={clientId}
export OKTA_IDX_CLIENTSECRET={clientSecret}
export OKTA_IDX_SCOPES="space separated scopes" # e.g. openid email profile
export OKTA_IDX_REDIRECTURI={redirectUri}
```

> :information_source: For root Org AS case, set issuer url to https://{yourOktaDomain}

Now navigate to http://localhost:8080 in your browser.

If you see a home page that prompts you to login, then things are working!

[jdk-8]: https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html
[apache-maven]: https://maven.apache.org/download.cgi
