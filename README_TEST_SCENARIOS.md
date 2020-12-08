# Test Scenarios

## 1. Get new tokens (access + id + refresh tokens) using interact code flow

See [QuickStart.java](examples/src/main/java/Quickstart.java) - `runLoginFlowWithPasswordAndEmailAuthenticators()` or `runLoginFlowWithSecurityQnAndEmailAuthenticators()`.

## 2. Remediation/MFA scenarios with Okta sign-on policy - TODO


## 3. Remediation/MFA scenarios with App sign-on policy - TODO


## 4. Cancel the OIE transaction and start new after that

### Start login operation 

```java
        // build client
        IDXClient client = Clients.builder()
                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
                .setClientId("{clientId}")
                .setClientSecret("{clientSecret}")
                .setScopes(new HashSet<>(Arrays.asList("openid", "email")))
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

### Cancel when authenticator remediation required

```java
// cancel
idxResponse = client.cancel("{stateHandle}");
// cancel returns new state handle
String newStateHandle = idxResponse.getStateHandle();
```

### Restart the login operation

```java
// check remediation options to continue the flow for new transaction (with new state handle)
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
        .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
```

## 5. Registration and progressive profiling - TODO


## 6. Enroll in a new factor - TODO

