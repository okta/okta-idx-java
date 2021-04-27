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
//import com.okta.idx.sdk.api.client.Clients;
//import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.Options;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.request.*;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Scanner;

/**
 * Example snippets used for this projects README.md.
 * <p>
 * Manually run {@code mvn okta-code-snippet:snip} after changing this file to update the README.md.
 */
@SuppressWarnings({"unused"})
public class ReadmeSnippets {

//    private static final Logger log = LoggerFactory.getLogger(ReadmeSnippets.class);
//
//    private static final IDXClient client = Clients.builder().build();
//
//    private static IDXResponse idxResponse;
//    private static RemediationOption remediationOption;
//
//    private void createClient() {
//        IDXClient client = Clients.builder()
//                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
//                .setClientId("{clientId}")
//                .setClientSecret("{clientSecret}")
//                .setScopes(new HashSet<>(Arrays.asList("openid", "email")))
//                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
//                .build();
//    }
//
//    private void getInteractionHandleAndCodeVerifier() throws ProcessingException {
//        IDXClientContext idxClientContext = client.interact();
//        String interactionHandle = idxClientContext.getInteractionHandle();
//        String codeVerifier = idxClientContext.getCodeVerifier();
//    }
//
//    private void getNewTokens() throws ProcessingException {
//        // build client
//        IDXClient client = Clients.builder()
//                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
//                .setClientId("{clientId}")
//                .setClientSecret("{clientSecret}")
//                .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
//                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
//                .build();
//
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // introspect
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select password authenticator
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId(authenticatorOptions.get("password"));
//        passwordAuthenticator.setMethodType("password");
//
//        // build password authenticator challenge request
//        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("password".toCharArray());
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // exchange interaction code for token
//        TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                tokenResponse.getAccessToken(),
//                tokenResponse.getIdToken(),
//                tokenResponse.getRefreshToken(),
//                tokenResponse.getTokenType(),
//                tokenResponse.getScope(),
//                tokenResponse.getExpiresIn());
//    }
//
//    private void exchangeInteractionHandleForStateHandle() throws ProcessingException {
//        IDXClientContext idxClientContext = client.interact();
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//    }
//
//    private void printRawIdxResponse() throws JsonProcessingException {
//        String rawResponse = idxResponse.raw();
//    }
//
//    private void checkRemediationOptions() {
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//    }
//
//    private void invokeIdentifyWithOrWithoutCredentials() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // introspect
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        // check if 'credentials' is required to be sent in identify API request (next step)
//        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
//                .filter(x -> "credentials".equals(x.getName()))
//                .findFirst();
//
//        IdentifyRequest identifyRequest = null;
//
//        if (credentialsFormValueOptional.isPresent()) {
//            FormValue credentialsFormValue = credentialsFormValueOptional.get();
//
//            if (credentialsFormValue.isRequired()) {
//                // credentials required
//                Credentials credentials = new Credentials();
//                credentials.setPasscode("{password}".toCharArray());
//
//                identifyRequest = IdentifyRequestBuilder.builder()
//                        .withIdentifier("{identifier}") // email
//                        .withCredentials(credentials)
//                        .withStateHandle(stateHandle)
//                        .build();
//            }
//        } else {
//            // credentials not required
//            identifyRequest = IdentifyRequestBuilder.builder()
//                    .withIdentifier("{identifier}") // email
//                    .withStateHandle(stateHandle)
//                    .build();
//        }
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//    }
//
//    private void checkRemediationOptionsAndSelectAuthenticator() {
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//
//        // select an authenticator
//        Authenticator authenticator = new Authenticator();
//        authenticator.setId("{id}"); // authenticator's 'id' value from remediation option above
//        authenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above
//    }
//
//    private void invokeChallengeAuthenticator() throws ProcessingException {
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId("{id}");
//        passwordAuthenticator.setMethodType("{methodType}");
//
//        // build password authenticator challenge request
//        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle("{stateHandle}")
//                .build();
//
//        // proceed
//        IDXResponse idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest); // remediationOption object is a reference to the previous step's remediation options
//    }
//
//    private void invokeAnswerChallengeAuthenticator() throws ProcessingException {
//        // check remediation options of authenticator challenge response (prior step)
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{passcode}".toCharArray());  // passcode received in email
//
//        // build answer email authenticator challenge request
//        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle("{stateHandle}")
//                .withCredentials(credentials)
//                .build();
//
//        // proceed
//        IDXResponse idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
//    }
//
//    private void cancel() throws ProcessingException {
//        // invalidates the supplied stateHandle and obtains a fresh one
//        IDXResponse idxResponse = client.cancel("{stateHandle}");
//    }
//
//    private void loginUsingPasswordAndEnrollSecQnAuthenticator() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // introspect
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{password}".toCharArray());
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withCredentials(credentials)
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // check remediation options to go to the next step
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
//                .findFirst();
//        RemediationOption remediationOptionsSelectAuthenticatorOption = remediationOptionsSelectAuthenticatorOptional.get();
//
//        // select an authenticator
//        Authenticator secQnEnrollmentAuthenticator = new Authenticator();
//        secQnEnrollmentAuthenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
//        secQnEnrollmentAuthenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above
//
//        // build enroll request
//        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
//                .withAuthenticator(secQnEnrollmentAuthenticator)
//                .withStateHandle("{stateHandle}")
//                .build();
//
//        // proceed
//        idxResponse = remediationOptionsSelectAuthenticatorOption.proceed(client, enrollRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "enroll-authenticator".equals(x.getName()))
//                .findFirst();
//        RemediationOption remediationOptionsEnrollAuthenticatorOption = remediationOptionsEnrollAuthenticatorOptional.get();
//
//        FormValue[] enrollAuthenticatorFormValues = remediationOptionsEnrollAuthenticatorOption.form();
//        Optional<FormValue> enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
//                .filter(x -> "credentials".equals(x.getName()))
//                .findFirst();
//        FormValue enrollAuthenticatorForm = enrollAuthenticatorFormOptional.get();
//
//        Options[] enrollmentAuthenticatorOptions = enrollAuthenticatorForm.options();
//        Optional<Options> chooseSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
//                .filter(x -> "Choose a security question".equals(x.getLabel()))
//                .findFirst();
//
//        Options choseSecQnOption = chooseSecQnOptionOptional.get(); // view default security questions list
//
//        Credentials secQnEnrollmentCredentials = new Credentials();
//        secQnEnrollmentCredentials.setQuestionKey("{questionKey}"); // e.g. "favorite_sports_player"
//        secQnEnrollmentCredentials.setQuestion("{question}"); // e.g. "What is the name of your first stuffed animal?"
//        secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray()); // e.g. "Tiger Woods"
//
//        AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle("{stateHandle}")
//                .withCredentials(secQnEnrollmentCredentials)
//                .build();
//
//        // proceed
//        idxResponse = remediationOptionsEnrollAuthenticatorOption.proceed(client, answerChallengeRequest);
//    }
//
//    private void loginUsingPasswordAndEmailAuthenticator() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select password authenticator
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId(authenticatorOptions.get("password"));
//        passwordAuthenticator.setMethodType("password");
//
//        // build password authenticator challenge request
//        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{password}".toCharArray());
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select email authenticator
//        Authenticator emailAuthenticator = new Authenticator();
//        emailAuthenticator.setId(authenticatorOptions.get("email"));
//        emailAuthenticator.setMethodType("email");
//
//        // build email authenticator challenge request
//        ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(emailAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, emailAuthenticatorChallengeRequest);
//
//        // answer email authenticator challenge
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        credentials = new Credentials();
//        credentials.setPasscode("{passcode}".toCharArray()); // passcode received in email
//
//        // build answer email authenticator challenge request
//        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
//
//        // check if we landed success on login
//        if (idxResponse.isLoginSuccessful()) {
//            log.info("Login Successful!");
//            // exchange the received interaction code for a token
//            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                    tokenResponse.getAccessToken(),
//                    tokenResponse.getIdToken(),
//                    tokenResponse.getRefreshToken(),
//                    tokenResponse.getTokenType(),
//                    tokenResponse.getScope(),
//                    tokenResponse.getExpiresIn());
//        }
//    }
//
//    private void loginUsingPasswordAndPhoneAuthenticator() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // get remediation options to go to the next step
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select phone authenticator (sms or voice)
//        Authenticator phoneAuthenticator = new Authenticator();
//        phoneAuthenticator.setId(authenticatorOptions.get("sms,voice")); /* id is the same for both sms and voice */
//        phoneAuthenticator.setEnrollmentId(authenticatorOptions.get("enrollmentId"));
//        phoneAuthenticator.setMethodType("sms"); /* or "voice" */
//
//        // build password authenticator challenge request
//        ChallengeRequest phoneAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(phoneAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, phoneAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("code".toCharArray()); // code received via sms or voice
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest phoneSmsCodeAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, phoneSmsCodeAuthenticatorAnswerChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select password authenticator
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId(authenticatorOptions.get("password"));
//        passwordAuthenticator.setMethodType("password");
//
//        // build password authenticator challenge request
//        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        credentials = new Credentials();
//        credentials.setPasscode("{password}".toCharArray());
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // check if we landed success on login
//        if (idxResponse.isLoginSuccessful()) {
//            log.info("Login Successful!");
//            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                    tokenResponse.getAccessToken(),
//                    tokenResponse.getIdToken(),
//                    tokenResponse.getRefreshToken(),
//                    tokenResponse.getTokenType(),
//                    tokenResponse.getScope(),
//                    tokenResponse.getExpiresIn());
//        }
//    }
//
//    private void loginUsingPasswordAndWebAuthnAuthenticator() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select password authenticator
//        Authenticator phoneAuthenticator = new Authenticator();
//        phoneAuthenticator.setId(authenticatorOptions.get("password"));
//        phoneAuthenticator.setMethodType("password");
//
//        // build password authenticator challenge request
//        ChallengeRequest phoneAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(phoneAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, phoneAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{password}".toCharArray());
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest phoneSmsCodeAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, phoneSmsCodeAuthenticatorAnswerChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // get authenticator options
//        authenticatorOptions = remediationOption.getAuthenticatorOptions();
//        log.info("Authenticator Options: {}", authenticatorOptions);
//
//        // select webauthn (fingerprint) authenticator
//        Authenticator webauthnAuthenticator = new Authenticator();
//        webauthnAuthenticator.setId(authenticatorOptions.get("webauthn"));
//        webauthnAuthenticator.setMethodType("webauthn");
//
//        // build fingerprint authenticator challenge request
//        ChallengeRequest fingerprintAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(webauthnAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, fingerprintAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // build answer fingerprint authenticator challenge request
//        credentials = new Credentials();
//        credentials.setAuthenticatorData("");   // replace (extract this data from browser and supply it here)
//        credentials.setClientData("");          // replace (extract this data from browser and supply it here)
//        credentials.setSignatureData("");       // replace (extract this data from browser and supply it here)
//
//        AnswerChallengeRequest fingerprintAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, fingerprintAuthenticatorAnswerChallengeRequest);
//
//        // check if we landed success on login
//        if (idxResponse.isLoginSuccessful()) {
//            log.info("Login Successful!");
//            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                    tokenResponse.getAccessToken(),
//                    tokenResponse.getIdToken(),
//                    tokenResponse.getRefreshToken(),
//                    tokenResponse.getTokenType(),
//                    tokenResponse.getScope(),
//                    tokenResponse.getExpiresIn());
//        }
//    }
//
//    private void loginWithPasswordReset() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // start the password recovery/reset flow
//        RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .build();
//
//        idxResponse = remediationOption.proceed(client, recoverRequest);
//
//        // get remediation options to go to the next step
//        // since the org requires password only, we don't have the "select password authenticator" step as in previous examples
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer the security question authenticator which required to reset password
//        Credentials secQnEnrollmentCredentials = new Credentials();
//        // e.g. "favorite_sports_player"
//        secQnEnrollmentCredentials.setQuestionKey("{questionKey}");
//
//        // e.g. "Tiger Woods"
//        secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray());
//
//        // build answer authenticator challenge request
//        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(secQnEnrollmentCredentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // check remediation options to continue the flow
//        // select the "reset-authenticator" remediation option to set the new password
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "reset-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // set passcode to your new password value
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{new_password}".toCharArray());
//
//        // build answer password authenticator challenge request
//        passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // check if we landed success on login
//        if (idxResponse.isLoginSuccessful()) {
//            log.info("Login Successful!");
//            // exchange the received interaction code for a token
//            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                    tokenResponse.getAccessToken(),
//                    tokenResponse.getIdToken(),
//                    tokenResponse.getRefreshToken(),
//                    tokenResponse.getTokenType(),
//                    tokenResponse.getScope(),
//                    tokenResponse.getExpiresIn());
//        }
//    }
//
//    private void cancelAndStartNew() throws ProcessingException {
//        // build client
//        IDXClient client = Clients.builder()
//                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
//                .setClientId("{clientId}")
//                .setClientSecret("{clientSecret}")
//                .setScopes(new HashSet<>(Arrays.asList("openid", "profile", "offline_access")))
//                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
//                .build();
//
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//        FormValue[] formValues = remediationOption.form();
//
//        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
//                .withIdentifier("{identifier}") // email
//                .withStateHandle(stateHandle)
//                .build();
//
//        // identify
//        idxResponse = remediationOption.proceed(client, identifyRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // select password authenticator
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
//        passwordAuthenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above
//
//        // build password authenticator challenge request
//        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);
//
//        // check remediation options to continue the flow
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "challenge-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // answer password authenticator challenge
//        Credentials credentials = new Credentials();
//        credentials.setPasscode("{password}".toCharArray());
//
//        // build answer password authenticator challenge request
//        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//        idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);
//
//        // cancel
//        idxResponse = client.cancel("{stateHandle}");
//
//        // cancel returns new state handle
//        String newStateHandle = idxResponse.getStateHandle();
//
//        // check remediation options to continue the flow for new transaction (with new state handle)
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//    }
//
//    private void enrollUserProfileUpdate() throws ProcessingException {
//        UserProfile userProfile = new UserProfile();
//        userProfile.addAttribute("key-1", "value-1");
//        userProfile.addAttribute("key-2", "value-2");
//
//        EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
//                .withStateHandle("{stateHandle}")
//                .withUserProfile(userProfile)
//                .build();
//
//        IDXResponse idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);
//    }
//
//    private void registrationFlow() throws ProcessingException {
//        // get client context
//        IDXClientContext idxClientContext = client.interact();
//
//        // exchange interactHandle for stateHandle
//        IDXResponse idxResponse = client.introspect(idxClientContext);
//        String stateHandle = idxResponse.getStateHandle();
//
//        // get remediation options to go to the next step
//        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-enroll-profile".equals(x.getName()))
//                .findFirst();
//        RemediationOption remediationOption = remediationOptionsOptional.get();
//
//        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .build();
//
//        // enroll new user
//        idxResponse = remediationOption.proceed(client, enrollRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "enroll-profile".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsOptional.get();
//
//        // supply only the "required" attributes
//        UserProfile up = new UserProfile();
//        up.addAttribute("lastName", "Coder");   // replace
//        up.addAttribute("firstName", "Joe");    // replace
//        Random randomGenerator = new Random();
//        int randomInt = randomGenerator.nextInt(1000);
//        up.addAttribute("email", "joe.coder" + randomInt + "@example.com"); // replace
//        up.addAttribute("age", "40"); // replace
//        up.addAttribute("sex", "Male"); // replace
//
//        EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
//                .withUserProfile(up)
//                .withStateHandle(stateHandle)
//                .build();
//
//        idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);
//
//        // enroll authenticators next
//
//        // check remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
//
//        Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
//
//        // select an authenticator (sec qn in this case)
//        Authenticator secQnEnrollmentAuthenticator = new Authenticator();
//        secQnEnrollmentAuthenticator.setId(authenticatorOptions.get("security_question"));
//        secQnEnrollmentAuthenticator.setMethodType("security_question");
//
//        // build enroll request
//        enrollRequest = EnrollRequestBuilder.builder()
//                .withAuthenticator(secQnEnrollmentAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, enrollRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "enroll-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
//
//        FormValue[] enrollAuthenticatorFormValues = remediationOption.form();
//        Optional<FormValue> enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
//                .filter(x -> "credentials".equals(x.getName()))
//                .findFirst();
//        FormValue enrollAuthenticatorForm = enrollAuthenticatorFormOptional.get();
//
//        Options[] enrollmentAuthenticatorOptions = enrollAuthenticatorForm.options();
//        Optional<Options> chooseSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
//                .filter(x -> "Choose a security question".equals(x.getLabel()))
//                .findFirst();
//
//        Options choseSecQnOption = chooseSecQnOptionOptional.get(); // view default security questions list
//
//        Credentials secQnEnrollmentCredentials = new Credentials();
//        secQnEnrollmentCredentials.setQuestionKey("disliked_food");  // chosen one from the above list
//        secQnEnrollmentCredentials.setQuestion("What is the food you least liked as a child?");
//        secQnEnrollmentCredentials.setAnswer("{answer}".toCharArray());
//
//        AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(secQnEnrollmentCredentials)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, answerChallengeRequest);
//
//        // check remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
//
//        authenticatorOptions = remediationOption.getAuthenticatorOptions();
//
//        // select an authenticator (email in this case)
//        Authenticator emailAuthenticator = new Authenticator();
//        emailAuthenticator.setId(authenticatorOptions.get("email"));
//        emailAuthenticator.setMethodType("email");
//
//        // build enroll request
//        enrollRequest = EnrollRequestBuilder.builder()
//                .withAuthenticator(emailAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, enrollRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "enroll-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
//
//        enrollAuthenticatorFormValues = remediationOption.form();
//        enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
//                .filter(x -> "credentials".equals(x.getName()))
//                .findFirst();
//
//        // enter passcode received in email
//        Scanner in = new Scanner(System.in, "UTF-8");
//        log.info("Enter Email Passcode: ");
//        String emailPasscode = in.nextLine();
//
//        Credentials credentials = new Credentials();
//        credentials.setPasscode(emailPasscode.toCharArray());
//
//        answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, answerChallengeRequest);
//
//        // check remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsSelectAuthenticatorOptional.get();
//
//        authenticatorOptions = remediationOption.getAuthenticatorOptions();
//
//        // select an authenticator (password in this case)
//        Authenticator passwordAuthenticator = new Authenticator();
//        passwordAuthenticator.setId(authenticatorOptions.get("password"));
//        passwordAuthenticator.setMethodType("password");
//
//        // build enroll request
//        enrollRequest = EnrollRequestBuilder.builder()
//                .withAuthenticator(passwordAuthenticator)
//                .withStateHandle(stateHandle)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, enrollRequest);
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "enroll-authenticator".equals(x.getName()))
//                .findFirst();
//        remediationOption = remediationOptionsEnrollAuthenticatorOptional.get();
//
//        enrollAuthenticatorFormValues = remediationOption.form();
//        enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
//                .filter(x -> "credentials".equals(x.getName()))
//                .findFirst();
//
//        credentials = new Credentials();
//        credentials.setPasscode("password".toCharArray());
//
//        answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .withCredentials(credentials)
//                .build();
//
//        // proceed
//        idxResponse = remediationOption.proceed(client, answerChallengeRequest);
//
//        // continue until "skip" is available as a remediation option. When skip becomes available, it indicates
//        // that the minimal required authenticators have been setup.
//
//        // get remediation options to go to the next step
//        remediationOptions = idxResponse.remediation().remediationOptions();
//        Optional<RemediationOption> skipAuthenticatorEnrollmentOptional = Arrays.stream(remediationOptions)
//                .filter(x -> "skip".equals(x.getName()))
//                .findFirst();
//        remediationOption = skipAuthenticatorEnrollmentOptional.get();
//
//        SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest = SkipAuthenticatorEnrollmentRequestBuilder.builder()
//                .withStateHandle(stateHandle)
//                .build();
//
//        // proceed with skipping optional authenticator enrollment
//        idxResponse = remediationOption.proceed(client, skipAuthenticatorEnrollmentRequest);
//
//        // This response should contain the interaction code
//        if (idxResponse.isLoginSuccessful()) {
//            log.info("Login Successful!");
//            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
//            log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
//                    tokenResponse.getAccessToken(),
//                    tokenResponse.getIdToken(),
//                    tokenResponse.getRefreshToken(),
//                    tokenResponse.getTokenType(),
//                    tokenResponse.getScope(),
//                    tokenResponse.getExpiresIn());
//        }
//    }
}
