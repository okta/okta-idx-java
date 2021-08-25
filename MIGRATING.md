# Okta Java Authentication SDK Migration Guide

This guide intends to outline the details needed for a developer to migrate from [Java Auth SDK](https://github.com/okta/okta-auth-java#okta-java-authentication-sdk) to [Okta IDX SDK](https://github.com/okta/okta-idx-java#okta-idx-java-sdk).

## Migrating from Java Auth SDK 2.x to Java IDX SDK 1.x

The previous version of this library, [Okta Java Auth SDK](https://github.com/okta/okta-auth-java), has been rewritten from the ground up as [Okta IDX Java SDK](https://github.com/okta/okta-idx-java). This was done to take advantage of the [OIE features](https://www.okta.com/platform/identity-engine/) available via the IDX API.

Since we are using a different set of APIs and patterns, a new library was published starting with 1.0.0 

## Getting started

### Prerequisites

- [JDK 8](https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html) or [JDK-11](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
- [Apache Maven](https://maven.apache.org/download.cgi) 3.6.x or later

To use this SDK, you will need to include the following dependencies:

For Apache Maven:

``` xml
<dependency>
    <groupId>com.okta.idx.sdk</groupId>
    <artifactId>okta-idx-java-api</artifactId>
    <version>${okta.sdk.version}</version>
</dependency>
```

where `{okta.sdk.version}` is the Java IDX SDK version.

For Gradle:

```groovy
compile "com.okta.idx.sdk:okta-idx-java-api:${okta.sdk.version}"
```

where `okta.sdk.version` is the latest stable release version [here](https://github.com/okta/okta-idx-java/releases).

For more information check out the [IDX SDK Repository](https://github.com/okta/okta-idx-java).

## New configuration model

In order to use the `IDXAuthenticationWrapper` client, you will need to configure additional properties. For more information, check out our [embedded Auth guide](https://developer.okta.com/docs/guides/oie-embedded-sdk-overview/main/#get-started-with-the-sdk).

The simplest way to construct a client is via code:

```java
IDXAuthenticationWrapper idxAuthenticationWrapper = new IDXAuthenticationWrapper(
        "{issuer}",
        "{clientId}",
        "{clientSecret}",
        "{scopes}", // space separated e.g. "openid email profile"
        "{redirectUri}"); // should match your app redirect uri set via console
```

> Note: For additional configuration options, check out the [IDX SDK Configuration Reference](https://github.com/okta/okta-idx-java#configuration-reference).

## New methods

In the table below, you can see the methods available in the IDX client and their equivalent ones in the Auth SDK. For guidance about usage, check out [here](https://github.com/okta/okta-idx-java/#usage-guide).


| Before   |      Now      | Description  |
|----------|---------------|--------------|
|`authenticate` |  `authenticate` | Authenticates a user with username/password credentials |
|`resetPassword` <br /> `recoverPassword` | `recoverPassword` |   Changes user''s password |
|`activateFactor` <br /> `verifyFactor` | `selectFactor` | Activate a factor |
|`skip`| `skipAuthenticatorEnrollment`| Skips an optional authenticator during enrollment/verification |
|`answerRecoveryQuestion` <br /> `cancel`| N/A| Out of Scope |
|`verifyActivation` <br /> `sendActivationEmail` <br /> `resendVerifyFactor` <br /> `resendActivateFactor` | N/A||
|`unlockAccount` <br /> `verifyUnlockAccount` | N/A||

## Authentication Response

Similar to the Auth SDK, the IDX wrapper client return a response with an Authentication status that indicates how to proceed with the authentication flow. Check out the Authentication Status section [here](https://github.com/okta/okta-idx-java#authentication-status) for more details.

## Handling errors

The SDK throws `ProcessingException` everytime the server responds with an invalid status code, or if there is an internal error. You can get more information by calling `exception.getErrorResponse()`.

## Getting help

If you have questions about this library or about the Okta APIs, post a question on our [Developer Forum](https://devforum.okta.com).

If you find a bug or have a feature request for the IDX library specifically, [post an issue](https://github.com/okta/okta-idx-java/issues) here on GitHub.