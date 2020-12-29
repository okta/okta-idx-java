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
import com.okta.idx.sdk.api.client.Clients;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.Options;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollRequestBuilder;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequestBuilder;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.InteractResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
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

    private void getNewTokens() throws ProcessingException {
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

        // identify
        idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier("{identifier}") // email
                .withStateHandle(stateHandle)
                .build());

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
        TokenResponse tokenResponse=idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                tokenResponse.getAccessToken(),
                tokenResponse.getIdToken(),
                tokenResponse.getRefreshToken(),
                tokenResponse.getTokenType(),
                tokenResponse.getScope(),
                tokenResponse.getExpiresIn());
    }

    private void exchangeInteractionHandleForStateHandle() throws ProcessingException {
        // optional with interactionHandle or empty; if empty, a new interactionHandle will be obtained
        IDXResponse idxResponse = client.introspect(Optional.of("{interactHandle}"));
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
        // introspect
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
            // credentials not required
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
        IDXResponse idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest); // remediationOption object is a reference to the previous step's remediation options
    }

    private void invokeAnswerChallengeAuthenticator() throws ProcessingException {
        // check remediation options of authenticator challenge response (prior step)
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "challenge-authenticator".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        Credentials credentials = new Credentials();
        credentials.setPasscode("{passcode}".toCharArray());  // passcode received in email

        // build answer email authenticator challenge request
        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("{stateHandle}")
                .withCredentials(credentials)
                .build();

        // proceed
        IDXResponse idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
    }

    private void cancel() throws ProcessingException {
        // invalidates the supplied stateHandle and obtains a fresh one
        IDXResponse idxResponse = client.cancel("{stateHandle}");
    }

    private void loginUsingPasswordAndEnrollSecQnAuthenticator() throws ProcessingException {
        // introspect
        IDXResponse idxResponse = client.introspect(Optional.of("{interactHandle}"));
        String stateHandle = idxResponse.getStateHandle();

        Credentials credentials = new Credentials();
        credentials.setPasscode("{password}".toCharArray());

        // identify
        idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier("{identifier}") // email
                .withCredentials(credentials)
                .withStateHandle(stateHandle)
                .build());

        // check remediation options to go to the next step
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOptionsSelectAuthenticatorOption = remediationOptionsSelectAuthenticatorOptional.get();

        // select an authenticator
        Authenticator secQnEnrollmentAuthenticator = new Authenticator();
        secQnEnrollmentAuthenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
        secQnEnrollmentAuthenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above

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

        Options choseSecQnOption = chooseSecQnOptionOptional.get(); // view default security questions list

        Credentials secQnEnrollmentCredentials = new Credentials();
        secQnEnrollmentCredentials.setQuestionKey("{questionKey}"); // e.g. "favorite_sports_player"
        secQnEnrollmentCredentials.setQuestion("{question}"); // e.g. "What is the name of your first stuffed animal?"
        secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray()); // e.g. "Tiger Woods"

        AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("{stateHandle}")
                .withCredentials(secQnEnrollmentCredentials)
                .build();

        // proceed
        idxResponse = remediationOptionsEnrollAuthenticatorOption.proceed(client, answerChallengeRequest);
    }

    private void loginUsingPasswordAndEmailAuthenticator() throws ProcessingException {
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
                .withIdentifier("{identifier}") // email
                .withStateHandle(stateHandle)
                .build());

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
        credentials.setPasscode("{passcode}".toCharArray()); // passcode received in email

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
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                    tokenResponse.getAccessToken(),
                    tokenResponse.getIdToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getTokenType(),
                    tokenResponse.getScope(),
                    tokenResponse.getExpiresIn());
        }
    }

    private void loginUsingPasswordAndPhoneAuthenticator() throws ProcessingException {
        // get interactionHandle
        InteractResponse interactResponse = client.interact();
        String interactHandle = interactResponse.getInteractionHandle();

        // exchange interactHandle for stateHandle
        IDXResponse idxResponse = client.introspect(Optional.of(interactHandle));
        String stateHandle = idxResponse.getStateHandle();

        // identify
        idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier("{identifier}") // email
                .withStateHandle(stateHandle)
                .build());

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
        phoneAuthenticator.setId(authenticatorOptions.get("sms,voice")); /* id is the same for both sms and voice */
        phoneAuthenticator.setEnrollmentId(authenticatorOptions.get("enrollmentId"));
        phoneAuthenticator.setMethodType("sms"); /* or "voice" */

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
        credentials.setPasscode("code".toCharArray()); // code received via sms or voice

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
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                    tokenResponse.getAccessToken(),
                    tokenResponse.getIdToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getTokenType(),
                    tokenResponse.getScope(),
                    tokenResponse.getExpiresIn());
        }
    }

    private void cancelAndStartNew() throws ProcessingException {
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
                .withIdentifier("{identifier}") // email
                .withStateHandle(stateHandle)
                .build());

        // get remediation options to go to the next step
        remediationOptions = idxResponse.remediation().remediationOptions();
        remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                .findFirst();
        remediationOption = remediationOptionsOptional.get();

        // select password authenticator
        Authenticator passwordAuthenticator = new Authenticator();
        passwordAuthenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
        passwordAuthenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above

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
    }

    private void enrollUserProfileUpdate() throws ProcessingException {
        UserProfile userProfile = new UserProfile();
        userProfile.addAttribute("key-1", "value-1");
        userProfile.addAttribute("key-2", "value-2");

        EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
                .withStateHandle("{stateHandle}")
                .withUserProfile(userProfile)
                .build();

        IDXResponse idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);
    }
}
