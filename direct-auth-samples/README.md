# Okta IDX Direct Auth Example

This example shows you how to use the Okta IDX Direct Auth flows.

> :warning: The `direct auth` features are still in EARLY ACCESS, please contact Okta Support for how to turn on the feature in your org.

## Prerequisites

- [JDK 8](#jdk-8) or later
- [Apache Maven](#apache-maven) 3.6.x or later

## Running This Example

```bash
cd direct-auth-samples
mvn -Dokta.idx.issuer=https://{yourOktaDomain}/oauth2/default \
    -Dokta.idx.clientId={clientId} \
    -Dokta.idx.clientSecret={clientSecret} \ 
    -Dokta.idx.scopes="space separated scopes" 
    -Dokta.idx.redirectUri={redirectUri}
```

(or) set the below env variables and run `mvn`

```
export OKTA_IDX_ISSUER=https://{yourOktaDomain}/oauth2/default
export OKTA_IDX_CLIENTSECRET={clientId}
export OKTA_IDX_CLIENTID={clientSecret}
export OKTA_IDX_SCOPES="space separated scopes" # e.g. openid email profile
export OKTA_IDX_REDIRECTURI=http://localhost:8080/authorization-code/callback
```

> :info: For root Org AS case, set issuer to https://{yourOktaDomain}

Now navigate to http://localhost:8080 in your browser.

If you see a home page that prompts you to login, then things are working!

[jdk-8]: https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html
[apache-maven]: https://maven.apache.org/download.cgi