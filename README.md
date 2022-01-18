[<img src="https://aws1.discourse-cdn.com/standard14/uploads/oktadev/original/1X/0c6402653dfb70edc661d4976a43a46f33e5e919.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.idx.sdk/okta-idx-java-api.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.idx.sdk%22%20a%3A%22okta-idx-java-api%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)][devforum]
[![API Reference](https://img.shields.io/badge/docs-reference-lightgrey.svg)][javadocs]
[![Build Status](https://travis-ci.com/okta/okta-idx-java.svg?branch=master)](https://travis-ci.com/okta/okta-idx-java)

# Okta IDX Java SDK

* [Release status](#release-status)
* [Need help?](#need-help)
* [Getting started](#getting-started)
* [Usage guide](#usage-guide)
* [Configuration reference](#configuration-reference)
* [Building the SDK](#building-the-sdk)
* [Contributing](#contributing)

This repository contains the Okta IDX SDK for Java. This SDK can be used in your server-side code to assist in authenticating users against the Okta Identity Engine using the [Interaction Code][interaction-code-intro] flow.

> :grey_exclamation: The use of this SDK requires usage of the Okta Identity Engine. This functionality is in general availability but is being gradually rolled out to customers. If you want to request to gain access to the Okta Identity Engine, please reach out to your account manager. If you do not have an account manager, please reach out to oie@okta.com for more information.

> This library is currently GA. See [release status](#release-status) for more information.

This library is built for projects in Java framework to communicate with Okta as an OAuth
2.0 + OpenID Connect provider. It works with [Okta's Identity Engine][okta-identity-engine] to authenticate and register users.

To see this library working in a sample, check out our [Java Samples][java-samples].

## Release Status

✔️ The current stable major version series is: 2.x

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 1.0.0 | :heavy_check_mark: Stable     |
| 2.0.0 | :heavy_check_mark: Stable     |

The latest release can always be found on the [releases page][github-releases].

## Need Help?
 
If you run into problems using the SDK, you can
 
* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)

## Getting Started

### Prerequisites

- [JDK 8][jdk-8] or [JDK-11][jdk-11]
- [Apache Maven][apache-maven] 3.6.x or later

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

where `okta.sdk.version` is the latest stable release version listed [here](#release-status).
### SNAPSHOT Dependencies

Snapshots are deployed off of the 'master' branch to [OSSRH](https://oss.sonatype.org/) and can be consumed using the following repository configured for Apache Maven or Gradle:

```txt
https://oss.sonatype.org/content/repositories/snapshots/
```

You will also need:

* An Okta account, called an _organization_ (sign up for a free [developer organization](https://developer.okta.com/signup) if you need one). 

## Usage guide

These examples will help you understand how to use this library.

`IDXAuthenticationWrapper` object needs to be instantiated to be able to invoke all the backend Okta APIs.

### Authenticate users

Begin Transaction:

```java
AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
```

Authenticate User:

```java
 AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.authenticate(new AuthenticationOptions(username, password), beginResponse.getProceedContext());
```

### Authentication Status

The `AuthenticationStatus` in `AuthenticationResponse` you get will indicate how to proceed to continue with the authentication flow.

#### Success

Type: `AuthenticationStatus.SUCCESS`

The user was successfully authenticated and you can retrieve the tokens from the response by calling `getTokenResponse()` on `AuthenticationResponse` object.

#### Password Expired

Type: `AuthenticationStatus.PASSWORD_EXPIRED`

The user needs to change their password to continue with the authentication flow and retrieve tokens.

#### Awaiting authenticator enrollment

Type: `AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION`

The user needs to enroll an authenticator to continue with the authentication flow and retrieve tokens. You can retrieve the authenticators information by calling `authnResponse.Authenticators`.

#### Awaiting challenge authenticator selection

Type: `AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION`

The user needs to select and challenge an additional authenticator to continue with the authentication flow and retrieve tokens.

There are other statuses that you can get in `AuthenticationStatus`:

#### Awaiting Authenticator Verification

Type: `AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION`

The user has successfully selected an authenticator to challenge so they now need to verify the selected authenticator. For example, if the user selected phone, this status indicates that they have to provide they code they received to verify the authenticator.

#### Awaiting Authenticator Enrollment Data

Type: `AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA`

The user needs to provide additional authenticator information. For example, when a user selects to enroll phone they will have to provide their phone number to complete the enrollment process.

#### Awaiting Challenge Authenticator Data

Type: `AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION_DATA`

The user needs to provide additional authenticator information. For example, when a user selects to challenge phone they will have to choose if they want to receive the code via voice or SMS.

#### Awaiting Password Reset

Type: `AuthenticationStatus.AWAITING_PASSWORD_RESET`

The user needs to reset their password to continue with the authentication flow and retrieve tokens.

### Revoke Tokens

```java
idxAuthenticationWrapper.revokeToken(TokenType.ACCESS_TOKEN, accessToken);
```

### Register a User

```java
// begin transaction
AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin();

// get proceed context
ProceedContext beginProceedContext = beginResponse.getProceedContext();

// enroll user
AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginProceedContext);

// set user profile
UserProfile userProfile = new UserProfile();
userProfile.addAttribute("lastName", lastname);
userProfile.addAttribute("firstName", firstname);
userProfile.addAttribute("email", email);

ProceedContext proceedContext = newUserRegistrationResponse.getProceedContext();

# register user with proceed context context
AuthenticationResponse authenticationResponse =
        idxAuthenticationWrapper.register(proceedContext, userProfile);
```

> Note: Check the response's `AuthenticationStatus` to determine what the next step is.

### Recover Password

```java
// recover password
 AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.recoverPassword(username, proceedContext);
```

> Note: Check the response's `AuthenticationStatus` to determine what the next step is.

### Error Handling

`AuthenticationResponse` contains the list of SDK errors as strings. 

```java
List<String> errors = authenticationResponse.getErrors();
```
### Thread Safety

Every instance of the SDK `Client` is thread-safe. You **should** use the same instance throughout the entire lifecycle of your application. Each instance has its own Connection pool and Caching resources that are automatically released when the instance is garbage collected.

## Configuration Reference
  
This library looks for configuration in the following sources:

0. An `okta.yaml` at the root of the applications classpath
0. An `okta.yaml` file in a `.okta` folder in the current user's home directory (`~/.okta/okta.yaml` or `%userprofile%\.okta\okta.yaml`)
0. Environment variables
0. Java System Properties
0. Configuration explicitly set programmatically (see the example in [Getting started](#getting-started))
 
Higher numbers win. In other words, configuration passed via the constructor will override configuration found in environment variables, which will override configuration in `okta.yaml` (if any), and so on.
 
### YAML Configuration
 
The full YAML configuration looks like:
 
```yaml
okta:
  idx:
    issuer: "https://{yourOktaDomain}/oauth2/{authorizationServerId}" # e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    clientId: "{clientId}"
    clientSecret: "{clientSecret}" # Required for confidential clients
    scopes:
    - "{scope1}"
    - "{scope2}"
    redirectUri: "{redirectUri}"
```
Here's an example config file 
```yaml
okta:
  idx:
    issuer: "https://dev-1234.okta.com/oauth2/default"
    clientId: "123xyz"
    clientSecret: "123456abcxyz" # Required for confidential clients
    scopes:
    - "openid"
    - "profile"
    - "offline_access"
    redirectUri: "https://loginredirect.com"
```
 
### Environment Variables
 
Each one of the configuration values above can be turned into an environment variable name with the `_` (underscore) character:

* `OKTA_IDX_ISSUER`
* `OKTA_IDX_CLIENTID`
* `OKTA_IDX_CLIENTSECRET`
* `OKTA_IDX_SCOPES`
* `OKTA_IDX_REDIRECTURI`

### System Properties

Each one of the configuration values written in 'dot' notation to be used as a Java system property:
* `okta.idx.issuer`
* `okta.idx.clientId`
* `okta.idx.clientSecret`
* `okta.idx.scopes`
* `okta.idx.redirectUri`

## Building the SDK

In most cases, you won't need to build the SDK from source. If you want to build it yourself, clone the repo and run `mvn install`.

By default, the Cucumber Integration tests are run on Maven builds (see [here](samples/embedded-auth-with-sdk/pom.xml)). 
If you wish to skip these Cucumber Integration tests, 
simply disable the associated Maven profile using `mvn clean install -P '!cucumber-it'`

## Contributing
 
We are happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[javadocs]: https://developer.okta.com/okta-idx-java/
[lang-landing]: https://developer.okta.com/code/java/
[github-issues]: https://github.com/okta/okta-idx-java/issues
[github-releases]: https://github.com/okta/okta-idx-java/releases
[okta-library-versioning]: https://developer.okta.com/code/library-versions
[jdk-8]: https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html
[jdk-11]: https://www.oracle.com/java/technologies/javase-jdk11-downloads.html
[java-samples]: https://github.com/okta/okta-idx-java/tree/master/samples
[apache-maven]: https://maven.apache.org/download.cgi
[okta-identity-engine]: https://developer.okta.com/docs/concepts/ie-intro/
[interaction-code-intro]: https://developer.okta.com/docs/guides/oie-embedded-sdk-overview/main/
