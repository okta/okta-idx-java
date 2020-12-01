/*
 * Copyright 2020-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.fasterxml.jackson.core.JsonProcessingException;
import com.okta.sdk.api.client.Clients;
import com.okta.sdk.api.client.IDXClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.model.Authenticator;
import com.okta.sdk.api.model.Credentials;
import com.okta.sdk.api.model.FormValue;
import com.okta.sdk.api.model.RemediationOption;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.ChallengeRequestBuilder;
import com.okta.sdk.api.request.EnrollRequest;
import com.okta.sdk.api.request.EnrollRequestBuilder;
import com.okta.sdk.api.request.IdentifyRequestBuilder;
import com.okta.sdk.api.response.IDXResponse;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;

/**
 * Example snippets used for this projects README.md.
 * <p>
 * Manually run {@code mvn okta-code-snippet:snip} after changing this file to update the README.md.
 */
@SuppressWarnings({"unused"})
public class ReadmeSnippets {

    private static final Logger log = LoggerFactory.getLogger(ReadmeSnippets.class);

    private static final IDXClient client = Clients.builder().build();

    private static IDXResponse idxResponse;
    private static RemediationOption remediationOption;

    public static void main(String... args) throws ProcessingException, JsonProcessingException {

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
                credentials.setPasscode("Sclass15683!".toCharArray()); // replace

                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                        .withIdentifier("arvind.krishnakumar@okta.com") // replace
                        .withCredentials(credentials)
                        .withStateHandle(stateHandle)
                        .build());
            }
        } else {
            // credentials are not necessary; so sending just the identifier
            idxResponse = client.identify(IdentifyRequestBuilder.builder()
                    .withIdentifier("arvind.krishnakumar@okta.com") // replace
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

            // check remediation options to continue the flow
            remediationOptions = idxResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // answer password authenticator challenge
            Credentials credentials = new Credentials();
            credentials.setPasscode("Sclass15683!".toCharArray()); // password associated with your email identifier

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

                // enter passcode received in email
                Scanner in = new Scanner(System.in, "UTF-8");
                log.info("Enter Email Passcode: ");
                String emailPasscode = in.nextLine();

                credentials = new Credentials();
                credentials.setPasscode(emailPasscode.toCharArray());

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
    }

    private void createClient() {
        IDXClient client = Clients.builder()
                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
                .setClientId("{clientId}")
                .setClientSecret("{clientSecret}")
                .setScopes(new HashSet<>(Arrays.asList("openid", "email")))
                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
                .build();
    }

    private void getInteractionHandle() throws ProcessingException {
        InteractResponse interactResponse = client.interact();
        String interactHandle = interactResponse.getInteractionHandle();
    }

    private void exchangeInteractionHandleForStateHandle() throws ProcessingException {
        // optional with interactionHandle or empty; if empty, a new interactionHandle will be obtained
        idxResponse = client.introspect(Optional.of("{interactHandle}"));
        String stateHandle = idxResponse.getStateHandle();
    }

    private void printRawIdxResponse() throws JsonProcessingException {
        String rawResponse = idxResponse.raw();
    }

    private void checkRemediationOptions() {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();
    }

    private void invokeIdentifyWithOrWithoutCredentials() throws ProcessingException {

        idxResponse = client.introspect(Optional.of("{interactHandle}"));
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
                // credentials are REQUIRED
                Credentials credentials = new Credentials();
                credentials.setPasscode("{password}".toCharArray());

                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                        .withIdentifier("{identifier}") // email
                        .withCredentials(credentials)
                        .withStateHandle(stateHandle)
                        .build());
            }
        } else {
            // credentials are not necessary; so populating just the identifier
            idxResponse = client.identify(IdentifyRequestBuilder.builder()
                    .withIdentifier("{identifier}") // email
                    .withStateHandle(stateHandle)
                    .build());
        }
    }

    private void checkRemediationOptionsAndSelectAuthenticator() {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        // select an authenticator
        Authenticator authenticator = new Authenticator();
        authenticator.setId("{id}"); // authenticator's 'id' value from remediation option above
        authenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above
    }

    private void invokeChallengeAuthenticator() throws ProcessingException {
        Authenticator passwordAuthenticator = new Authenticator();
        passwordAuthenticator.setId("{id}");
        passwordAuthenticator.setMethodType("{methodType}");

        // build password authenticator challenge request
        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withAuthenticator(passwordAuthenticator)
                .withStateHandle("{stateHandle}")
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest); // remediationOption object is a reference to the previous step's remediation options
    }

    private void invokeAnswerChallengeAuthenticator() throws ProcessingException {
        // check remediation options of authenticator challenge response (prior step)
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "challenge-authenticator".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        Credentials credentials = new Credentials();
        credentials.setPasscode("{emailPasscode}".toCharArray());  // passcode received in email

        // build answer email authenticator challenge request
        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("{stateHandle}")
                .withCredentials(credentials)
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
    }

    private void cancel() throws ProcessingException {
        // invalidates the supplied stateHandle and obtains a fresh one
        idxResponse = client.cancel("{stateHandle}");
    }

    private void enrollAuthenticator() throws ProcessingException {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        // select an authenticator
        Authenticator authenticator = new Authenticator();
        authenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
        authenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above

        // build enroll request
        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                .withAuthenticator(authenticator)
                .withStateHandle("{stateHandle}")
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, enrollRequest);
    }

    private void checkForLoginSuccess() {
        if (idxResponse.isLoginSuccessful()) {
            // login successful
        } else {
            // check remediation options and continue the flow
        }
    }

    private void getTokenWithInteractionCode() throws ProcessingException {
        if (idxResponse.isLoginSuccessful()) {
            // exchange interaction code for token
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);

            String accessToken = tokenResponse.getAccessToken();
            String idToken = tokenResponse.getIdToken();
            Integer expiresIn = tokenResponse.getExpiresIn();
            String scope = tokenResponse.getScope();
            String tokenType = tokenResponse.getTokenType();
        }
    }
}
