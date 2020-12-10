[<img src="https://aws1.discourse-cdn.com/standard14/uploads/oktadev/original/1X/0c6402653dfb70edc661d4976a43a46f33e5e919.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.sdk/okta-idx-java-api.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.sdk%22%20a%3A%22okta-idx-java-api%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)][devforum]
[![API Reference](https://img.shields.io/badge/docs-reference-lightgrey.svg)][javadocs]

# Okta IDX Java SDK

* [Release status](#release-status)
* [Need help?](#need-help)
* [Getting started](#getting-started)
* [Usage guide](#usage-guide)
* [Configuration reference](#configuration-reference)
* [Building the SDK](#building-the-sdk)
* [Contributing](#contributing)

This repository contains the Okta IDX SDK for Java. This SDK can be used in your server-side code to assist in authenticating users against the Okta Identity Engine.

> :warning: Beta alert! This library is in beta. See [release status](#release-status) for more information.

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.1.0 | :warning: Beta      |

The latest release can always be found on the [releases page][github-releases].

## Need help?
 
If you run into problems using the SDK, you can
 
* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)

## Getting started

### Prerequisites

* JDK 8 or later

To use this SDK, you will need to include the following dependencies:

For Apache Maven:

``` xml
<dependency>
    <groupId>com.okta.sdk</groupId>
    <artifactId>okta-idx-java-api</artifactId>
    <version>${okta.sdk.version}</version>
</dependency>
<dependency>
    <groupId>com.okta.sdk</groupId>
    <artifactId>okta-idx-java-impl</artifactId>
    <version>${okta.sdk.version}</version>
    <scope>runtime</scope>
</dependency>
```

For Gradle:

```groovy
compile "com.okta.sdk:okta-idx-java-api:${okta.sdk.version}"
runtime "com.okta.sdk:okta-idx-java-impl:${okta.sdk.version}"
```

where `okta.sdk.version` is the latest stable release version listed [here](#release-status).
### SNAPSHOT Dependencies

Snapshots are deployed off of the 'master' branch to [OSSRH](https://oss.sonatype.org/) and can be consumed using the following repository configured for Apache Maven or Gradle:

```txt
https://oss.sonatype.org/content/repositories/snapshots/
```

You will also need:

* An Okta account, called an _organization_ (sign up for a free [developer organization](https://developer.okta.com/signup) if you need one)
* An [API token](https://developer.okta.com/docs/api/getting_started/getting_a_token)
 
Construct a client instance by passing it your Okta domain name and API token:

[//]: # (NOTE: code snippets in this README are updated automatically via a Maven plugin by running: mvn okta-code-snippet:snip)

## Usage guide

These examples will help you understand how to use this library.

Once you initialize a `Client`, you can call methods to make requests to the Okta API.

### Create the Client

[//]: # (method: createClient)
```java
IDXClient client = Clients.builder()
        .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
        .setClientId("{clientId}")
        .setClientSecret("{clientSecret}")
        .setScopes(new HashSet<>(Arrays.asList("openid", "email")))
        .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
        .build();
```
[//]: # (end: createClient)

### Get Interaction Handle

[//]: # (method: getInteractionHandle)
```java
InteractResponse interactResponse = client.interact();
String interactHandle = interactResponse.getInteractionHandle();
```
[//]: # (end: getInteractionHandle)

### Get State Handle

[//]: # (method: exchangeInteractionHandleForStateHandle)
```java
// optional with interactionHandle or empty; if empty, a new interactionHandle will be obtained
IDXResponse idxResponse = client.introspect(Optional.of("{interactHandle}"));
String stateHandle = idxResponse.getStateHandle();
```
[//]: # (end: exchangeInteractionHandleForStateHandle)

### Get new tokens (access + id + refresh tokens) using interact code flow

In this example the sign-on policy has no authenticators required.

> Note: Steps to identify the user might change based on the Org configuration.

```java
// build client
IDXClient client = Clients.builder()
        .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
        .setClientId("{clientId}")
        .setClientSecret("{clientSecret}")
        .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
        .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
        .build();

// call introspect - interactionHandle is optional; if it's not provided, a new interactionHandle will be obtained.IDXResponse idxResponse = client.introspect(Optional.of(interactHandle));
IDXResponse idxResponse = client.introspect(Optional.empty());
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();

// // identify with username
idxResponse = client.identify(IdentifyRequestBuilder.builder()
        .withIdentifier(IDENTIFIER)
        .withStateHandle(stateHandle)
        .build());

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
    log.info("Token: {}", tokenResponse);
} else {
    // logon is not successful yet; we need to follow more remediation steps.
    log.info("Login not successful yet!: {}", idxResponse.raw());

    // get remediation options to go to the next step
    remediationOptions = idxResponse.remediation().remediationOptions();
    remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
    remediationOption = remediationOptionsOptional.get();

    // get authenticator options
    Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
    log.info("Authenticator Options: {}", authenticatorOptions);

    // select password authenticator
    Authenticator passwordAuthenticator = new Authenticator();
    passwordAuthenticator.setId(authenticatorOptions.get("password"));
    passwordAuthenticator.setMethodType("password");

    // build password authenticator challenge request
    ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(passwordAuthenticator)
        .withStateHandle(stateHandle)
        .build();
    idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);

    // check remediation options to continue the flow
    remediationOptions = idxResponse.remediation().remediationOptions();
    remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
    remediationOption = remediationOptionsOptional.get();

    // answer password authenticator challenge
    Credentials credentials = new Credentials();
    credentials.setPasscode(PASSWORD);

    // build answer password authenticator challenge request
    AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        build();
    idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

    // check if we landed success on login
    if (idxResponse.isLoginSuccessful()){
        log.info("Login Successful!");
        TokenResponse tokenResponse=idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
        tokenResponse.getAccessToken(),
        tokenResponse.getIdToken(),
        tokenResponse.getTokenType(),
        tokenResponse.getScope(),
        tokenResponse.getExpiresIn());
    }
```

### Cancel the OIE transaction and start new after that

In this example the Org is configured to require email as a second authenticator. After answering password challenge, a cancel request is send right before answering the email challenge.

```java
        // build client
        IDXClient client = Clients.builder()
                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
                .setClientId("{clientId}")
                .setClientSecret("{clientSecret}")
                .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
                .build();

        // get interactionHandle
        InteractResponse interactResponse = client.interact();
        String interactHandle = interactResponse.getInteractionHandle();

        // exchange interactHandle for stateHandle
        IDXResponse idxResponse = client.introspect(Optional.of(interactHandle));
        String stateHandle = idxResponse.getStateHandle();

        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

        // identify
        idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier(IDENTIFIER)
                .withStateHandle(stateHandle)
                .build());

        // check if we landed success on login
        if (idxResponse.isLoginSuccessful()) {
            log.info("Login Successful!");
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
            log.info("Token: {}", tokenResponse);
        } else {
            // logon is not successful yet; we need to follow more remediation steps.
            log.info("Login not successful yet!: {}", idxResponse.raw());

            // get remediation options to go to the next step
            remediationOptions = idxResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                    .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // get authenticator options
            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
            log.info("Authenticator Options: {}", authenticatorOptions);

            // select password authenticator
            Authenticator passwordAuthenticator = new Authenticator();
            passwordAuthenticator.setId(authenticatorOptions.get("password"));
            passwordAuthenticator.setMethodType("password");

            // build password authenticator challenge request
            ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                    .withAuthenticator(passwordAuthenticator)
                    .withStateHandle(stateHandle)
                    .build();
            idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);

            // check remediation options to continue the flow
            remediationOptions = idxResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // answer password authenticator challenge
            Credentials credentials = new Credentials();
            credentials.setPasscode(PASSWORD);

            // build answer password authenticator challenge request
            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();
            idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
        }
```

```java
// cancel
idxResponse = client.cancel("{stateHandle}");
// cancel returns new state handle
String newStateHandle = idxResponse.getStateHandle();
```

```java
// check remediation options to continue the flow for new transaction (with new state handle)
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
```

### Check Remediation Options

[//]: # (method: checkRemediationOptions)
```java
// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
```
[//]: # (end: checkRemediationOptions)

### Identify with or without Credentials

[//]: # (method: invokeIdentifyWithOrWithoutCredentials)
```java
IDXResponse idxResponse = client.introspect(Optional.of("{interactHandle}"));
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();

// check if 'credentials' is required to be sent in identify API request (next step)
Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
        .filter(x -> "credentials".equals(x.getName()))
        .findFirst();
if (credentialsFormValueOptional.isPresent()) {
    FormValue credentialsFormValue = credentialsFormValueOptional.get();

    if (credentialsFormValue.isRequired()) {
        // credentials required
        Credentials credentials = new Credentials();
        credentials.setPasscode("{password}".toCharArray());

        idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier("{identifier}") // email
                .withCredentials(credentials)
                .withStateHandle(stateHandle)
                .build());
    }
} else {
    // credentials is not required
    idxResponse = client.identify(IdentifyRequestBuilder.builder()
            .withIdentifier("{identifier}") // email
            .withStateHandle(stateHandle)
            .build());
}
```
[//]: # (end: invokeIdentifyWithOrWithoutCredentials)

### Check Remediation Options and Select Authenticator

[//]: # (method: checkRemediationOptionsAndSelectAuthenticator)
```java
// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();

// select an authenticator
Authenticator authenticator = new Authenticator();

// authenticator's 'id' value from remediation option above
authenticator.setId("{id}");

// authenticator's 'methodType' value from remediation option above
authenticator.setMethodType("{methodType}");
```
[//]: # (end: checkRemediationOptionsAndSelectAuthenticator)

### Authenticator Challenge

[//]: # (method: invokeChallengeAuthenticator)
```java
Authenticator passwordAuthenticator = new Authenticator();
passwordAuthenticator.setId("{id}");
passwordAuthenticator.setMethodType("{methodType}");

// build password authenticator challenge request
ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(passwordAuthenticator)
        .withStateHandle("{stateHandle}")
        .build();

// remediationOption object is a reference to the previous step's remediation options
IDXResponse idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);
```
[//]: # (end: invokeChallengeAuthenticator)

### Answer Authenticator Challenge

[//]: # (method: invokeAnswerChallengeAuthenticator)
```java
// check remediation options of authenticator challenge response (prior step)
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
Credentials credentials = new Credentials();

// passcode received in email
credentials.setPasscode("{emailPasscode}".toCharArray());

// build answer email authenticator challenge request
AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle("{stateHandle}")
        .withCredentials(credentials)
        .build();

// proceed
IDXResponse idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
```
[//]: # (end: invokeAnswerChallengeAuthenticator)

### Cancel Flow

[//]: # (method: cancel)
```java
// invalidates the supplied stateHandle and obtains a fresh one
IDXResponse idxResponse = client.cancel("{stateHandle}");
```
[//]: # (end: cancel)

### Enroll Authenticator

[//]: # (method: enrollAuthenticator)
```java
// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-enroll".equals(x.getName()))
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();

// select an authenticator
Authenticator authenticator = new Authenticator();

// authenticator's 'id' value from remediation option above
authenticator.setId("{id}");

// authenticator's 'methodType' value from remediation option above
authenticator.setMethodType("{methodType}");

// build enroll request
EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
        .withAuthenticator(authenticator)
        .withStateHandle("{stateHandle}")
        .build();

// proceed
IDXResponse idxResponse = remediationOption.proceed(client, enrollRequest);
```
[//]: # (end: enrollAuthenticator)

### Get Token with Interaction Code

[//]: # (method: getTokenWithInteractionCode)
```java
if (idxResponse.isLoginSuccessful()) {
    // exchange interaction code for token
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);

    String accessToken = tokenResponse.getAccessToken();
    String idToken = tokenResponse.getIdToken();
    Integer expiresIn = tokenResponse.getExpiresIn();
    String scope = tokenResponse.getScope();
    String tokenType = tokenResponse.getTokenType();
}
```
[//]: # (end: getTokenWithInteractionCode)

### Print Raw Response

[//]: # (method: printRawIdxResponse)
```java
String rawResponse = idxResponse.raw();
```
[//]: # (end: printRawIdxResponse)

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
 
### YAML configuration
 
The full YAML configuration looks like:
 
```yaml
okta:
  idx:
    issuer: "https://{yourOktaDomain}/oauth2/{authorizationServerId}" // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
    clientId: "{clientId}"
    clientSecret: "{clientSecret}" // Required for confidential clients
    scopes:
    - "{scope1}"
    - "{scope2}"
    redirectUri: "{redirectUri}"
```
 
### Environment variables
 
Each one of the configuration values above can be turned into an environment variable name with the `_` (underscore) character:

* `OKTA_IDX_ISSUER`
* `OKTA_IDX_CLIENTID`
* `OKTA_IDX_CLIENTSECRET`
* `OKTA_IDX_SCOPES`
* `OKTA_IDX_REDIRECTURI`

### System properties

Each one of the configuration values written in 'dot' notation to be used as a Java system property:
* `okta.idx.issuer`
* `okta.idx.clientId`
* `okta.idx.clientSecret`
* `okta.idx.scopes`
* `okta.idx.redirectUri`

## Building the SDK

In most cases, you won't need to build the SDK from source. If you want to build it yourself, clone the repo and run `mvn install`.

## Contributing
 
We are happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[javadocs]: https://developer.okta.com/okta-idx-java/
[lang-landing]: https://developer.okta.com/code/java/
[github-issues]: https://github.com/okta/okta-idx-java/issues
[github-releases]: https://github.com/okta/okta-idx-java/releases
[okta-library-versioning]: https://developer.okta.com/code/library-versions