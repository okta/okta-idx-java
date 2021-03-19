/*
 * Copyright 2021-Present Okta, Inc.
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

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.Clients;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.Scanner;

public class ConvenienceExamples {

    private static final Logger log = LoggerFactory.getLogger(Quickstart.class);

    private static final IDXClient client = Clients.builder().build();

    /**
     * Authenticate user with username and password by completing the password authenticator
     * challenge and returns the Token (access_token/id_token/refresh_token).
     *
     * Note: This requires 'Password' as the only required factor in app Sign-on policy configuration.
     *
     * @param username the email
     * @param password the password
     * @return the token response
     */
    static TokenResponse authenticate(String username, String password) {

        TokenResponse tokenResponse = null;

        try {
            IDXClientContext idxClientContext = client.interact();
            Assert.hasText(idxClientContext.getInteractionHandle(), "Missing interaction handle");

            IDXResponse idxResponse = client.introspect(idxClientContext);
            String stateHandle = idxResponse.getStateHandle();
            Assert.hasText(stateHandle, "Missing state handle");

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation options");

            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if password credential is required to be sent in identify user step
                if (credentialsFormValue.isRequired()) {
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(password.toCharArray());

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(username)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // password credential is not necessary, so sending just the identifier (username)
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(username)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify user
            idxResponse = remediationOption.proceed(client, identifyRequest);

            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
            } else if (idxResponse.getMessages() != null && idxResponse.remediation() == null) {
                log.error("Terminal error occurred");
                Arrays.stream(idxResponse.getMessages().getValue()).forEach(msg -> log.error("{}", msg.getMessage()));
            } else {
                log.info("Attempting to follow next remediation option(s)");

                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "challenge-authenticator".equals(x.getName()))
                        .findFirst();

                Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing challenge-authenticator remediation option");

                remediationOption = remediationOptionsOptional.get();

                // answer password authenticator challenge
                Credentials credentials = new Credentials();
                credentials.setPasscode(password.toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .withCredentials(credentials)
                        .build();
                idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

                if (idxResponse.isLoginSuccessful()) {
                    log.info("Login Successful!");
                    tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                } else if (idxResponse.getMessages() != null && idxResponse.remediation() == null) {
                    log.error("Terminal error occurred");
                    Arrays.stream(idxResponse.getMessages().getValue()).forEach(msg -> log.error("Error: {}", msg.getMessage()));
                } else {
                    log.error("Could not authenticate user with password factor alone. Please review your app Sign-on policy configuration.");
                }
            }
        } catch (ProcessingException e) {
            log.error("Something went wrong!", e);
        } catch (IllegalArgumentException e) {
            log.error("Exception occurred", e);
        }

        return tokenResponse;
    }

    public static void main(String... args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Username: ");
        String username = scanner.nextLine();
        System.out.print("Enter Password: ");
        String password = scanner.nextLine();

        TokenResponse tokenResponse = authenticate(username, password);

        log.info("TokenResponse: \naccessToken: {}, \nidToken: {}, \nrefreshToken: {}, \ntokenType: {}, \nscope: {}, \nexpiresIn:{}",
                tokenResponse.getAccessToken(),
                tokenResponse.getIdToken(),
                tokenResponse.getRefreshToken(),
                tokenResponse.getTokenType(),
                tokenResponse.getScope(),
                tokenResponse.getExpiresIn());
    }
}
