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

This repository contains the Okta IDX SDK for Java. This SDK can be used in your server-side code to assist in authenticating users against the Okta Identity Engine.

> :grey_exclamation: The use of this SDK requires you to be a part of our limited general availability (LGA) program with access to Okta Identity Engine. If you want to request to be a part of our LGA program for Okta Identity Engine, please reach out to your account manager. If you do not have an account manager, please reach out to oie@okta.com for more information.

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
    <groupId>com.okta.idx.sdk</groupId>
    <artifactId>okta-idx-java-api</artifactId>
    <version>${okta.sdk.version}</version>
</dependency>
<dependency>
    <groupId>com.okta.idx.sdk</groupId>
    <artifactId>okta-idx-java-impl</artifactId>
    <version>${okta.sdk.version}</version>
    <scope>runtime</scope>
</dependency>
```

For Gradle:

```groovy
compile "com.okta.idx.sdk:okta-idx-java-api:${okta.sdk.version}"
runtime "com.okta.idx.sdk:okta-idx-java-impl:${okta.sdk.version}"
```

where `okta.sdk.version` is the latest stable release version listed [here](#release-status).
### SNAPSHOT Dependencies

Snapshots are deployed off of the 'master' branch to [OSSRH](https://oss.sonatype.org/) and can be consumed using the following repository configured for Apache Maven or Gradle:

```txt
https://oss.sonatype.org/content/repositories/snapshots/
```

You will also need:

* An Okta account, called an _organization_ (sign up for a free [developer organization](https://developer.okta.com/signup) if you need one). 

[//]: # (NOTE: code snippets in this README are updated automatically via a Maven plugin by running: mvn okta-code-snippet:snip)

## Usage guide

The below code snippets will help you understand how to use this library. Alternatively, you can look at [Quickstart](examples/src/main/java/Quickstart.java) to help get started.

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

### Get State Handle

[//]: # (method: exchangeInteractionHandleForStateHandle)
```java
IDXClientContext idxClientContext = client.interact();
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();
```
[//]: # (end: exchangeInteractionHandleForStateHandle)

### Get Interaction Handle and Code Verifier

[//]: # (method: getInteractionHandleAndCodeVerifier)
```java
IDXClientContext idxClientContext = client.interact();
String interactionHandle = idxClientContext.getInteractionHandle();
String codeVerifier = idxClientContext.getCodeVerifier();
```
[//]: # (end: getInteractionHandleAndCodeVerifier)

### Get New tokens (access_token/id_token/refresh_token)

In this example the sign-on policy has no authenticators required.

> Note: Steps to identify the user might change based on the Org configuration.

[//]: # (method: getNewTokens)
```java
// build client
IDXClient client = Clients.builder()
        .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
        .setClientId("{clientId}")
        .setClientSecret("{clientSecret}")
        .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
        .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
        .build();

// get client context
IDXClientContext idxClientContext = client.interact();

// introspect
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

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
credentials.setPasscode("password".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// exchange interaction code for token
TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
        tokenResponse.getAccessToken(),
        tokenResponse.getIdToken(),
        tokenResponse.getRefreshToken(),
        tokenResponse.getTokenType(),
        tokenResponse.getScope(),
        tokenResponse.getExpiresIn());
```
[//]: # (end: getNewTokens)

### Cancel the OIE transaction and start new after that

In this example the Org is configured to require email as a second authenticator. After answering password challenge, a cancel request is send right before answering the email challenge.

[//]: # (method: cancelAndStartNew)
```java
// build client
IDXClient client = Clients.builder()
        .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
        .setClientId("{clientId}")
        .setClientSecret("{clientSecret}")
        .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
        .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
        .build();

// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// select password authenticator
Authenticator passwordAuthenticator = new Authenticator();

// authenticator's 'id' value from remediation option above
passwordAuthenticator.setId("{id}");

// authenticator's 'methodType' value from remediation option above
passwordAuthenticator.setMethodType("{methodType}");

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
credentials.setPasscode("{password}".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// cancel
idxResponse = client.cancel("{stateHandle}");

// cancel returns new state handle
String newStateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow for new transaction (with new state handle)
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
remediationOption = remediationOptionsOptional.get();
```
[//]: # (end: cancelAndStartNew)

### Remediation/MFA scenarios with sign-on policy

#### Login using password + enroll security question authenticator

In this example, the Org is configured to require a security question as a second authenticator. After answering the password challenge, users have to select security question and then select a question and enter an answer to finish the process.

> Note: Steps to identify the user might change based on your Org configuration.

[//]: # (method: loginUsingPasswordAndEnrollSecQnAuthenticator)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// introspect
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();
Credentials credentials = new Credentials();
credentials.setPasscode("{password}".toCharArray());
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withCredentials(credentials)
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

// check remediation options to go to the next step
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-enroll".equals(x.getName()))
        .findFirst();
RemediationOption remediationOptionsSelectAuthenticatorOption = remediationOptionsSelectAuthenticatorOptional.get();

// select an authenticator
Authenticator secQnEnrollmentAuthenticator = new Authenticator();

// authenticator's 'id' value from remediation option above
secQnEnrollmentAuthenticator.setId("{id}");

// authenticator's 'methodType' value from remediation option above
secQnEnrollmentAuthenticator.setMethodType("{methodType}");

// build enroll request
EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
        .withAuthenticator(secQnEnrollmentAuthenticator)
        .withStateHandle("{stateHandle}")
        .build();

// proceed
idxResponse = remediationOptionsSelectAuthenticatorOption.proceed(client, enrollRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "enroll-authenticator".equals(x.getName()))
        .findFirst();
RemediationOption remediationOptionsEnrollAuthenticatorOption = remediationOptionsEnrollAuthenticatorOptional.get();
FormValue[] enrollAuthenticatorFormValues = remediationOptionsEnrollAuthenticatorOption.form();
Optional<FormValue> enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
        .filter(x -> "credentials".equals(x.getName()))
        .findFirst();
FormValue enrollAuthenticatorForm = enrollAuthenticatorFormOptional.get();
Options[] enrollmentAuthenticatorOptions = enrollAuthenticatorForm.options();
Optional<Options> chooseSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
        .filter(x -> "Choose a security question".equals(x.getLabel()))
        .findFirst();

// view default security questions list
Options choseSecQnOption = chooseSecQnOptionOptional.get();
Credentials secQnEnrollmentCredentials = new Credentials();

// e.g. "favorite_sports_player"
secQnEnrollmentCredentials.setQuestionKey("{questionKey}");

// e.g. "What is the name of your first stuffed animal?"
secQnEnrollmentCredentials.setQuestion("{question}");

// e.g. "Tiger Woods"
secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray());
AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle("{stateHandle}")
        .withCredentials(secQnEnrollmentCredentials)
        .build();

// proceed
idxResponse = remediationOptionsEnrollAuthenticatorOption.proceed(client, answerChallengeRequest);
```
[//]: # (end: loginUsingPasswordAndEnrollSecQnAuthenticator)

#### Login using password + email authenticator

In this example, the Org is configured to require an email as a second authenticator. After answering the password challenge, users have to select email and enter the code to finish the process.

> Note: Steps to identify the user might change based on your Org configuration.

> Note: If users click a magic link instead of providing a code, they will be redirected to the login page with a valid session if applicable.

[//]: # (method: loginUsingPasswordAndEmailAuthenticator)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

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
credentials.setPasscode("{password}".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// get authenticator options
authenticatorOptions = remediationOption.getAuthenticatorOptions();
log.info("Authenticator Options: {}", authenticatorOptions);

// select email authenticator
Authenticator emailAuthenticator = new Authenticator();
emailAuthenticator.setId(authenticatorOptions.get("email"));
emailAuthenticator.setMethodType("email");

// build email authenticator challenge request
ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(emailAuthenticator)
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, emailAuthenticatorChallengeRequest);

// answer email authenticator challenge
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();
credentials = new Credentials();

// passcode received in email
credentials.setPasscode("{passcode}".toCharArray());

// build answer email authenticator challenge request
AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    // exchange the received interaction code for a token
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
    log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
            tokenResponse.getAccessToken(),
            tokenResponse.getIdToken(),
            tokenResponse.getRefreshToken(),
            tokenResponse.getTokenType(),
            tokenResponse.getScope(),
            tokenResponse.getExpiresIn());
}
```
[//]: # (end: loginUsingPasswordAndEmailAuthenticator)

#### Login using password + phone authenticator (SMS/Voice)

In this example, the Org is configured to require a Phone factor (SMS/Voice) as a second authenticator. After answering the password challenge, users have to select SMS/Voice and enter the code to finish the process.

> Note: Steps to identify the user might change based on your Org configuration.

[//]: # (method: loginUsingPasswordAndPhoneAuthenticator)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

// get remediation options to go to the next step
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// get authenticator options
Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
log.info("Authenticator Options: {}", authenticatorOptions);

// select phone authenticator (sms or voice)
Authenticator phoneAuthenticator = new Authenticator();
phoneAuthenticator.setId(authenticatorOptions.get("sms,voice"));

/* id is the same for both sms and voice */
phoneAuthenticator.setEnrollmentId(authenticatorOptions.get("enrollmentId"));
phoneAuthenticator.setMethodType("sms");

// build password authenticator challenge request
ChallengeRequest phoneAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(phoneAuthenticator)
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, phoneAuthenticatorChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// answer password authenticator challenge
Credentials credentials = new Credentials();

// code received via sms or voice
credentials.setPasscode("code".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest phoneSmsCodeAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, phoneSmsCodeAuthenticatorAnswerChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// get authenticator options
authenticatorOptions = remediationOption.getAuthenticatorOptions();
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
credentials = new Credentials();
credentials.setPasscode("{password}".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
    log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
            tokenResponse.getAccessToken(),
            tokenResponse.getIdToken(),
            tokenResponse.getRefreshToken(),
            tokenResponse.getTokenType(),
            tokenResponse.getScope(),
            tokenResponse.getExpiresIn());
}
```
[//]: # (end: loginUsingPasswordAndPhoneAuthenticator)

#### Login using password + web authenticator

In this example, the Org is configured with fingerprint as a second authenticator. After answering the password challenge, users have to provide their fingerprint to finish the process.

Refer [here](https://developer.okta.com/docs/reference/api/authn/#get-the-signed-assertion-from-the-webauthn-authenticator) for information on how to extract the assertion data from browser.

> Note: Steps to identify the user might change based on your Org configuration.

[//]: # (method: loginUsingPasswordAndWebAuthnAuthenticator)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

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
Authenticator phoneAuthenticator = new Authenticator();
phoneAuthenticator.setId(authenticatorOptions.get("password"));
phoneAuthenticator.setMethodType("password");

// build password authenticator challenge request
ChallengeRequest phoneAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(phoneAuthenticator)
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, phoneAuthenticatorChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// answer password authenticator challenge
Credentials credentials = new Credentials();
credentials.setPasscode("{password}".toCharArray());

// build answer password authenticator challenge request
AnswerChallengeRequest phoneSmsCodeAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, phoneSmsCodeAuthenticatorAnswerChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// get authenticator options
authenticatorOptions = remediationOption.getAuthenticatorOptions();
log.info("Authenticator Options: {}", authenticatorOptions);

// select webauthn (fingerprint) authenticator
Authenticator webauthnAuthenticator = new Authenticator();
webauthnAuthenticator.setId(authenticatorOptions.get("webauthn"));
webauthnAuthenticator.setMethodType("webauthn");

// build fingerprint authenticator challenge request
ChallengeRequest fingerprintAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
        .withAuthenticator(webauthnAuthenticator)
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, fingerprintAuthenticatorChallengeRequest);

// check remediation options to continue the flow
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// build answer fingerprint authenticator challenge request
credentials = new Credentials();

// replace (extract this data from browser and supply it here)
credentials.setAuthenticatorData("");

// replace (extract this data from browser and supply it here)
credentials.setClientData("");

// replace (extract this data from browser and supply it here)
credentials.setSignatureData("");
AnswerChallengeRequest fingerprintAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, fingerprintAuthenticatorAnswerChallengeRequest);

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
    log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
            tokenResponse.getAccessToken(),
            tokenResponse.getIdToken(),
            tokenResponse.getRefreshToken(),
            tokenResponse.getTokenType(),
            tokenResponse.getScope(),
            tokenResponse.getExpiresIn());
}
```
[//]: # (end: loginUsingPasswordAndWebAuthnAuthenticator)

#### Login using password after password reset

In this example, the Org is configured to require password authenticator to login, with no additional authenticators. After sending the identify request with the username, the user can reset the password, after answering the security question. Login will be successful after password reset.

> Note: Steps to identify the user might change based on your Org configuration.

[//]: # (method: loginWithPasswordReset)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// check remediation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();
IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}") // email
        .withStateHandle(stateHandle)
        .build();

// identify
idxResponse = remediationOption.proceed(client, identifyRequest);

// start the password recovery/reset flow
RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, recoverRequest);

// since the org requires password only, we don't have the "select password authenticator" step as in previous examples
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// answer the security question authenticator which required to reset password
Credentials secQnEnrollmentCredentials = new Credentials();

// e.g. "favorite_sports_player"
secQnEnrollmentCredentials.setQuestionKey("{questionKey}");

// e.g. "Tiger Woods"
secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray());

// build answer authenticator challenge request
AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(secQnEnrollmentCredentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// select the "reset-authenticator" remediation option to set the new password
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "reset-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// set passcode to your new password value
Credentials credentials = new Credentials();
credentials.setPasscode("{new_password}".toCharArray());

// build answer password authenticator challenge request
passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    // exchange the received interaction code for a token
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
    log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
            tokenResponse.getAccessToken(),
            tokenResponse.getIdToken(),
            tokenResponse.getRefreshToken(),
            tokenResponse.getTokenType(),
            tokenResponse.getScope(),
            tokenResponse.getExpiresIn());
}
```
[//]: # (end: loginWithPasswordReset)

### User Enrollment - Registration and progressive profiling

Enroll a user with additional profile attributes.

[//]: # (method: enrollUserProfileUpdate)
```java
UserProfile userProfile = new UserProfile();
userProfile.addAttribute("key-1", "value-1");
userProfile.addAttribute("key-2", "value-2");
EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
        .withStateHandle("{stateHandle}")
        .withUserProfile(userProfile)
        .build();
IDXResponse idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);
```
[//]: # (end: enrollUserProfileUpdate)

### Registration Flow - New User Registration

Sign up a new user.

[//]: # (method: registrationFlow)
```java
// get client context
IDXClientContext idxClientContext = client.interact();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(idxClientContext);
String stateHandle = idxResponse.getStateHandle();

// get remediation options to go to the next step
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-enroll-profile".equals(x.getName()))
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .build();

// enroll new user
idxResponse = remediationOption.proceed(client, enrollRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "enroll-profile".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsOptional.get();

// supply only the "required" attributes
UserProfile up = new UserProfile();

// replace
up.addAttribute("lastName", "Coder");

// replace
up.addAttribute("firstName", "Joe");
Random randomGenerator = new Random();
int randomInt = randomGenerator.nextInt(1000);

// replace
up.addAttribute("email", "joe.coder" + randomInt + "@example.com");

// replace
up.addAttribute("age", "40");

// replace
up.addAttribute("sex", "Male");
EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
        .withUserProfile(up)
        .withStateHandle(stateHandle)
        .build();
idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);

// check remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-enroll".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();

// select an authenticator (sec qn in this case)
Authenticator secQnEnrollmentAuthenticator = new Authenticator();
secQnEnrollmentAuthenticator.setId(authenticatorOptions.get("security_question"));
secQnEnrollmentAuthenticator.setMethodType("security_question");

// build enroll request
enrollRequest = EnrollRequestBuilder.builder()
        .withAuthenticator(secQnEnrollmentAuthenticator)
        .withStateHandle(stateHandle)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, enrollRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "enroll-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
FormValue[] enrollAuthenticatorFormValues = remediationOption.form();
Optional<FormValue> enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
        .filter(x -> "credentials".equals(x.getName()))
        .findFirst();
FormValue enrollAuthenticatorForm = enrollAuthenticatorFormOptional.get();
Options[] enrollmentAuthenticatorOptions = enrollAuthenticatorForm.options();
Optional<Options> chooseSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
        .filter(x -> "Choose a security question".equals(x.getLabel()))
        .findFirst();

// view default security questions list
Options choseSecQnOption = chooseSecQnOptionOptional.get();
Credentials secQnEnrollmentCredentials = new Credentials();

// chosen one from the above list
secQnEnrollmentCredentials.setQuestionKey("disliked_food");
secQnEnrollmentCredentials.setQuestion("What is the food you least liked as a child?");
secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray());
AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(secQnEnrollmentCredentials)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, answerChallengeRequest);

// check remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-enroll".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
authenticatorOptions = remediationOption.getAuthenticatorOptions();

// select an authenticator (email in this case)
Authenticator emailAuthenticator = new Authenticator();
emailAuthenticator.setId(authenticatorOptions.get("email"));
emailAuthenticator.setMethodType("email");

// build enroll request
enrollRequest = EnrollRequestBuilder.builder()
        .withAuthenticator(emailAuthenticator)
        .withStateHandle(stateHandle)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, enrollRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "enroll-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
enrollAuthenticatorFormValues = remediationOption.form();
enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
        .filter(x -> "credentials".equals(x.getName()))
        .findFirst();

// enter passcode received in email
Scanner in = new Scanner(System.in, "UTF-8");
log.info("Enter Email Passcode: ");
String emailPasscode = in.nextLine();
Credentials credentials = new Credentials();
credentials.setPasscode(emailPasscode.toCharArray());
answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, answerChallengeRequest);

// check remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "select-authenticator-enroll".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
authenticatorOptions = remediationOption.getAuthenticatorOptions();

// select an authenticator (password in this case)
Authenticator passwordAuthenticator = new Authenticator();
passwordAuthenticator.setId(authenticatorOptions.get("password"));
passwordAuthenticator.setMethodType("password");

// build enroll request
enrollRequest = EnrollRequestBuilder.builder()
        .withAuthenticator(passwordAuthenticator)
        .withStateHandle(stateHandle)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, enrollRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
        .filter(x -> "enroll-authenticator".equals(x.getName()))
        .findFirst();
remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
enrollAuthenticatorFormValues = remediationOption.form();
enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
        .filter(x -> "credentials".equals(x.getName()))
        .findFirst();
credentials = new Credentials();
credentials.setPasscode("password".toCharArray());
answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();

// proceed
idxResponse = remediationOption.proceed(client, answerChallengeRequest);

// get remediation options to go to the next step
remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> skipAuthenticatorEnrollmentOptional = Arrays.stream(remediationOptions)
        .filter(x -> "skip".equals(x.getName()))
        .findFirst();
remediationOption = skipAuthenticatorEnrollmentOptional.get();
SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest = SkipAuthenticatorEnrollmentRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .build();

// proceed with skipping optional authenticator enrollment
idxResponse = remediationOption.proceed(client, skipAuthenticatorEnrollmentRequest);

// This response should contain the interaction code
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
    log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
            tokenResponse.getAccessToken(),
            tokenResponse.getIdToken(),
            tokenResponse.getRefreshToken(),
            tokenResponse.getTokenType(),
            tokenResponse.getScope(),
            tokenResponse.getExpiresIn());
}
```
[//]: # (end: registrationFlow)

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
