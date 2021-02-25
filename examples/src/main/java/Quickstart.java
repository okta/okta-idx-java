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
import com.okta.idx.sdk.api.model.IDXClientContext;
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
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequestBuilder;
import com.okta.idx.sdk.api.request.RecoverRequestBuilder;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Scanner;

/**
 * This class demonstrates the SDK usage to help get started.
 */
public class Quickstart {

    private static final Logger log = LoggerFactory.getLogger(Quickstart.class);

    private static final IDXClient client = Clients.builder().build();

    private static final String IDENTIFIER = "someone@example.com";                   // replace
    private static final char[] PASSWORD = "Topsecret123!".toCharArray();             // replace
    private static final char[] NEW_PASSWORD = "Supersecret123!".toCharArray();       // replace
    private static final char[] SECURITY_QUESTION_ANSWER = "Okta".toCharArray();      // replace

    public static void main(String... args) throws JsonProcessingException {

        // One of the below flows could be chosen depending on how the Authenticators are setup in your org.

        // complete login flow with Password & Email Authenticators
        runLoginFlowWithPasswordAndEmailAuthenticators();

        // complete login flow with Security question & Email Authenticators
        //runLoginFlowWithSecurityQnAndEmailAuthenticators();

        // enroll security authenticator flow (new user with no authenticators enrolled yet)
        //runEnrollSecurityQnAuthenticatorFlow();

        // complete login flow with profiling
        //runLoginFlowWithPasswordAndProgressiveProfiling();

        // complete login flow with one required authenticator enrollment (sec qn) and skip the other optional authenticator
        //runLoginFlowWithOptionalAuthenticatorEnrollment();

        // complete login flow with password and phone (sms/voice) authenticators
        //runLoginFlowWithPasswordAndPhoneAuthenticators();

        // complete login flow with password and webauthn
        //runLoginFlowWithPasswordAndWebAuthnAuthenticators();

        // complete reset password flow
        //runLoginFlowWithPasswordReset();

        // complete registration flow for new user (Sign Up)
        //runRegistrationFlow();
    }

    private static void runRegistrationFlow() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
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
            up.addAttribute("lastName", "Coder");   // replace
            up.addAttribute("firstName", "Joe");    // replace
            Random randomGenerator = new Random();
            int randomInt = randomGenerator.nextInt(1000);
            up.addAttribute("email", "joe.coder" + randomInt + "@example.com"); // replace
            up.addAttribute("age", "40"); // replace
            up.addAttribute("sex", "Male"); // replace

            EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
                    .withUserProfile(up)
                    .withStateHandle(stateHandle)
                    .build();

            idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);

            // enroll authenticators next

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

            Options choseSecQnOption = chooseSecQnOptionOptional.get(); // view default security questions list

            Credentials secQnEnrollmentCredentials = new Credentials();
            secQnEnrollmentCredentials.setQuestionKey("disliked_food");  // chosen one from the above list
            secQnEnrollmentCredentials.setQuestion("What is the food you least liked as a child?");
            secQnEnrollmentCredentials.setAnswer(SECURITY_QUESTION_ANSWER);

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
            credentials.setPasscode(PASSWORD);

            answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();

            // proceed
            idxResponse = remediationOption.proceed(client, answerChallengeRequest);

            // continue until "skip" is available as a remediation option. When skip becomes available, it indicates
            // that the minimal required authenticators have been setup.

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
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runEnrollSecurityQnAuthenticatorFlow() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
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
                } else {
                    // login is not successful yet; we need to follow more remediation steps.
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
                        TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                                tokenResponse.getAccessToken(),
                                tokenResponse.getIdToken(),
                                tokenResponse.getRefreshToken(),
                                tokenResponse.getTokenType(),
                                tokenResponse.getScope(),
                                tokenResponse.getExpiresIn());
                    } else {

                        // check remediation options to go to the next step
                        remediationOptions = idxResponse.remediation().remediationOptions();
                        Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
                                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
                                .findFirst();
                        RemediationOption remediationOptionsSelectAuthenticatorOption = remediationOptionsSelectAuthenticatorOptional.get();

                        authenticatorOptions = remediationOptionsSelectAuthenticatorOption.getAuthenticatorOptions();

                        // select an authenticator
                        Authenticator secQnEnrollmentAuthenticator = new Authenticator();
                        secQnEnrollmentAuthenticator.setId(authenticatorOptions.get("security_question"));
                        secQnEnrollmentAuthenticator.setMethodType("security_question");

                        // build enroll request
                        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                                .withAuthenticator(secQnEnrollmentAuthenticator)
                                .withStateHandle(stateHandle)
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
                        secQnEnrollmentCredentials.setQuestionKey("my_own_sec_qn_key");
                        secQnEnrollmentCredentials.setQuestion("Which is your most favorite pet?");
                        secQnEnrollmentCredentials.setAnswer(SECURITY_QUESTION_ANSWER);

                        AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                                .withStateHandle(stateHandle)
                                .withCredentials(secQnEnrollmentCredentials)
                                .build();

                        // proceed
                        idxResponse = remediationOptionsEnrollAuthenticatorOption.proceed(client, answerChallengeRequest);
                    }
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithPasswordAndEmailAuthenticators() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
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
                } else {
                    // login is not successful yet; we need to follow more remediation steps.
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
                        TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                                tokenResponse.getAccessToken(),
                                tokenResponse.getIdToken(),
                                tokenResponse.getRefreshToken(),
                                tokenResponse.getTokenType(),
                                tokenResponse.getScope(),
                                tokenResponse.getExpiresIn());
                    }
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithPasswordAndProgressiveProfiling() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();

            FormValue[] formValues = remediationOption.form();

            IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                    .withIdentifier(IDENTIFIER)
                    .withStateHandle(stateHandle)
                    .build();

            // credentials are not necessary; so sending just the identifier
            idxResponse = remediationOption.proceed(client, identifyRequest);

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
            } else {
                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "enroll-profile".equals(x.getName()))
                        .findFirst();
                remediationOption = remediationOptionsOptional.get();
                formValues = remediationOption.form();

                // check if credentials are required to move on to next step
                Optional<FormValue> userProfile = Arrays.stream(formValues)
                        .filter(x -> "userProfile".equals(x.getName()))
                        .findFirst();
                FormValue credentialsFormValue = userProfile.get();

                UserProfile up = new UserProfile();
                up.addAttribute("blah1", "35");
                up.addAttribute("blah2", "35");

                EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
                        .withUserProfile(up)
                        .withStateHandle(stateHandle)
                        .build();

                // This response should contain the interaction code
                idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);

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
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithOptionalAuthenticatorEnrollment() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                log.info("Token: {}", tokenResponse);
            } else {
                // logon is not successful yet; we need to follow more remediation steps.
                log.info("Login not successful yet!: {}", idxResponse.raw());

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
                } else {
                    // check remediation options to go to the next step
                    remediationOptions = idxResponse.remediation().remediationOptions();
                    Optional<RemediationOption> remediationOptionsSelectAuthenticatorOptional = Arrays.stream(remediationOptions)
                            .filter(x -> "select-authenticator-enroll".equals(x.getName()))
                            .findFirst();
                    RemediationOption remediationOptionsSelectAuthenticatorOption = remediationOptionsSelectAuthenticatorOptional.get();

                    Map<String, String> authenticatorOptions = remediationOptionsSelectAuthenticatorOption.getAuthenticatorOptions();

                    // select an authenticator
                    Authenticator secQnEnrollmentAuthenticator = new Authenticator();
                    secQnEnrollmentAuthenticator.setId(authenticatorOptions.get("security_question"));
                    secQnEnrollmentAuthenticator.setMethodType("security_question");

                    // build enroll request
                    EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                            .withAuthenticator(secQnEnrollmentAuthenticator)
                            .withStateHandle(stateHandle)
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
                    secQnEnrollmentCredentials.setQuestionKey("my_own_sec_qn_key");
                    secQnEnrollmentCredentials.setQuestion("Which is your most favorite pet?");
                    secQnEnrollmentCredentials.setAnswer(SECURITY_QUESTION_ANSWER);

                    AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                            .withStateHandle(stateHandle)
                            .withCredentials(secQnEnrollmentCredentials)
                            .build();

                    // proceed
                    idxResponse = remediationOptionsEnrollAuthenticatorOption.proceed(client, answerChallengeRequest);

                    // skip the optional authenticator

                    // get remediation options to go to the next step
                    remediationOptions = idxResponse.remediation().remediationOptions();
                    Optional<RemediationOption> skipAuthenticatorEnrollmentOptional = Arrays.stream(remediationOptions)
                            .filter(x -> "skip".equals(x.getName()))
                            .findFirst();
                    RemediationOption skipAuthenticatorEnrollmentRemediationOption = skipAuthenticatorEnrollmentOptional.get();

                    SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest = SkipAuthenticatorEnrollmentRequestBuilder.builder()
                            .withStateHandle(stateHandle)
                            .build();

                    // proceed with skipping optional authenticator enrollment
                    idxResponse = skipAuthenticatorEnrollmentRemediationOption.proceed(client, skipAuthenticatorEnrollmentRequest);

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
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithSecurityQnAndEmailAuthenticators() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                log.info("Token: {}", tokenResponse);
            } else {
                // login is not successful yet; we need to follow more remediation steps.
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

                // select security question authenticator
                Authenticator secQnAuthenticator = new Authenticator();
                secQnAuthenticator.setId(authenticatorOptions.get("security_question"));
                secQnAuthenticator.setMethodType("security_question");

                // build security question authenticator challenge request
                ChallengeRequest secQnAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                        .withAuthenticator(secQnAuthenticator)
                        .withStateHandle(stateHandle)
                        .build();
                idxResponse = remediationOption.proceed(client, secQnAuthenticatorChallengeRequest);

                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "challenge-authenticator".equals(x.getName()))
                        .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // answer security question authenticator challenge
                Credentials credentials = new Credentials();
                credentials.setAnswer(SECURITY_QUESTION_ANSWER);

                // build answer password authenticator challenge request
                AnswerChallengeRequest secQnAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .withCredentials(credentials)
                        .build();
                idxResponse = remediationOption.proceed(client, secQnAuthenticatorAnswerChallengeRequest);

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
                } else {
                    // login is not successful yet; we need to follow more remediation steps.
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
                        TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                        log.info("Exchanged interaction code for token: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                                tokenResponse.getAccessToken(),
                                tokenResponse.getIdToken(),
                                tokenResponse.getRefreshToken(),
                                tokenResponse.getTokenType(),
                                tokenResponse.getScope(),
                                tokenResponse.getExpiresIn());
                    }
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithPasswordAndPhoneAuthenticators() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
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

                // enter sms code received on phone (via sms or voice)
                Scanner in = new Scanner(System.in, "UTF-8");
                log.info("Enter SMS or Voice Code: ");
                String smsCode = in.nextLine();

                // answer password authenticator challenge
                Credentials credentials = new Credentials();
                credentials.setPasscode(smsCode.toCharArray());

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
                credentials.setPasscode(PASSWORD);

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
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithPasswordAndWebAuthnAuthenticators() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                    .withIdentifier(IDENTIFIER)
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
            credentials.setPasscode(PASSWORD);

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
            Authenticator fingerPrintAuthenticator = new Authenticator();
            fingerPrintAuthenticator.setId(authenticatorOptions.get("webauthn"));
            fingerPrintAuthenticator.setMethodType("webauthn");

            // build fingerprint authenticator challenge request
            ChallengeRequest fingerprintAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                    .withAuthenticator(fingerPrintAuthenticator)
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
            credentials.setAuthenticatorData("");   // replace (extract this data from browser and supply it here)
            credentials.setClientData("");          // replace (extract this data from browser and supply it here)
            credentials.setSignatureData("");       // replace (extract this data from browser and supply it here)

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
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithPasswordReset() throws JsonProcessingException {

        try {
            // get client context
            IDXClientContext idxClientContext = client.interact();

            // get stateHandle
            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if credentials are required to be sent in identify API
                if (credentialsFormValue.isRequired()) {
                    log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(PASSWORD);

                    identifyRequest = IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build();
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify
            idxResponse = remediationOption.proceed(client, identifyRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                log.info("Token: {}", tokenResponse);
            } else {
                // logon is not successful yet; we need to follow more remediation steps.
                log.info("Login not successful yet!: {}", idxResponse.raw());

                // Self Service Password Recovery
                RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .build();

                idxResponse = remediationOption.proceed(client, recoverRequest);

                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "challenge-authenticator".equals(x.getName()))
                        .findFirst();
                remediationOption = remediationOptionsOptional.get();

                Credentials secQnEnrollmentCredentials = new Credentials();
                secQnEnrollmentCredentials.setQuestionKey("disliked_food");
                secQnEnrollmentCredentials.setAnswer(SECURITY_QUESTION_ANSWER);

                // build answer security question authenticator challenge request
                AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .withCredentials(secQnEnrollmentCredentials)
                        .build();
                idxResponse = remediationOption.proceed(client, answerChallengeRequest);

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
                } else {
                    // login is not successful yet; we need to follow more remediation steps.
                    log.info("Login not successful yet!: {}", idxResponse.raw());

                    // check remediation options to continue the flow
                    remediationOptions = idxResponse.remediation().remediationOptions();
                    remediationOptionsOptional = Arrays.stream(remediationOptions)
                            .filter(x -> "reset-authenticator".equals(x.getName()))
                            .findFirst();
                    remediationOption = remediationOptionsOptional.get();

                    // get authenticator options
                    Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
                    log.info("Authenticator Options: {}", authenticatorOptions);

                    // answer password authenticator challenge
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(NEW_PASSWORD);

                    // build answer password authenticator challenge request
                    answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                            .withStateHandle(stateHandle)
                            .withCredentials(credentials)
                            .build();

                    idxResponse = remediationOption.proceed(client, answerChallengeRequest);

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
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }
}
