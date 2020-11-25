# okta-identity-engine-java

[//]: # (method: main)
```java
// build the client
IDXClient client = Clients.builder()
    .setIssuer("{issuer}")
    .setClientId("{clientId}")
    .setClientSecret("{clientSecret}")
    .setScopes(new HashSet<>(Arrays.asList("{scope-1}", "{scope-2}")))
    .build();

// start the OIE flow with an empty interactionHandle
InteractResponse interactResponse = client.interact(Optional.empty());
String interactHandle = interactResponse.getInteractionHandle();

// exchange interactHandle for stateHandle
IDXResponse idxResponse = client.introspect(interactHandle);
String stateHandle = idxResponse.getStateHandle();

// check remedation options to continue the flow
RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
    .findFirst();
RemediationOption remediationOption = remediationOptionsOptional.get();
FormValue[] formValues = remediationOption.form();

// check of credentials are required to move on to next step
Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
    .filter(x -> "credentials".equals(x.getName()))
    .findFirst();
if (credentialsFormValueOptional.isPresent()) {
    FormValue credentialsFormValue = credentialsFormValueOptional.get();

    // check if credentials are required to be sent in identify API
    if (credentialsFormValue.isRequired()) {
        log.info("Credentials are REQUIRED to be sent in identify request (next step)");
        Credentials credentials = new Credentials();
        credentials.setPasscode("{password}");

        idxResponse = client.identify(IdentifyRequestBuilder.builder()
            .withIdentifier("{identifier}") // email
            .withCredentials(credentials)
            .withStateHandle(stateHandle)
            .build());
    }
} else {
    // credentials are not necessary; so sending just the identifier
    idxResponse = client.identify(IdentifyRequestBuilder.builder()
        .withIdentifier("{identifier}")
        .withStateHandle(stateHandle)
        .build());
}

// check if we landed success on login
if (idxResponse.isLoginSuccessful()) {
    log.info("Login Successful!");
    TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
    log.info("Token: {}", tokenResponse);
}
else {
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

    // check remedation options to continue the flow
    remediationOptions = idxResponse.remediation().remediationOptions();
    remediationOptionsOptional = Arrays.stream(remediationOptions)
        .filter(x -> "challenge-authenticator".equals(x.getName()))
        .findFirst();
    remediationOption = remediationOptionsOptional.get();

    // answer password authenticator challenge
    Credentials credentials = new Credentials();
    credentials.setPasscode("{password}"); // password associated with your email identifier

    // build answer password authenticator challenge request
    AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
        .withStateHandle(stateHandle)
        .withCredentials(credentials)
        .build();
    idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

    // check if we landed success on login
    if (idxResponse.isLoginSuccessful()) {
        log.info("Login Successful!");
        log.info("Exchanged interaction code for token {}",
            idxResponse.getSuccessWithInteractionCode().exchangeCode(client));
    } else {
        // logon is not successful yet; we need to follow more remediation steps.
        log.info("Login not successful yet!: {}", idxResponse.raw());

        // check remedation options to continue the flow
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

        // enter passcode received in email
        Scanner in = new Scanner(System.in, "UTF-8");
        log.info("Enter Email Passcode: ");
        String emailPasscode = in.nextLine();

        credentials = new Credentials();
        credentials.setPasscode(emailPasscode);

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
            log.info("Exchanged interaction code for token {}",
                idxResponse.getSuccessWithInteractionCode().exchangeCode(client));
        }
    }
}
```
[//]: # (end: main)
