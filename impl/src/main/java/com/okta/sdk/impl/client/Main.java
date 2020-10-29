package com.okta.sdk.impl.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.collect.Sets;
import com.okta.commons.lang.Strings;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.model.Authenticator;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.client.Client;
import com.okta.sdk.api.client.Clients;
import com.okta.sdk.api.model.Credentials;
import com.okta.sdk.api.model.FormValue;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;
import com.okta.sdk.api.model.Options;
import com.okta.sdk.api.model.RemediationOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This is a Driver Application to exercise the Okta Identity Engine SDK Client to invoke the core backend APIs.
 *
 * TODO: This class MUST be removed from repo before merging to master.
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final ObjectMapper objectMapper = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public static void main(String... args) throws Exception {

        // build the Okta Identity Engine client
        final Client client = Clients.builder()
            .setIssuer("https://devex-idx-testing.oktapreview.com")
            .setClientId("test-client-id")
            .setScopes(Sets.newHashSet("test-scope-1", "test-scope-2"))
            .build();

        // obtain state handle from browser and enter it
        final String stateHandle = JOptionPane.showInputDialog("Enter stateHandle: ");

        if (Strings.isEmpty(stateHandle)) {
            log.error("Missing stateHandle");
            return;
        }

        // 1. invoke introspect endpoint with the state handle
        OktaIdentityEngineResponse introspectResponse = client.introspect(stateHandle);
        printInfo(objectMapper.writeValueAsString(introspectResponse), "Introspect API Response");

        if (introspectResponse != null) {
            final String identifier = JOptionPane.showInputDialog("Enter identifier (email): ");

            if (Strings.isEmpty(identifier)) {
                log.error("Missing identifier");
                return;
            }

            // 2. invoke identify endpoint & get remediation options
            IdentifyRequest identifyRequest = new IdentifyRequest(identifier, stateHandle, false);
            printInfo(objectMapper.writeValueAsString(identifyRequest), "Identify API Request");

            OktaIdentityEngineResponse identifyResponse = client.identify(identifyRequest);
            printInfo(objectMapper.writeValueAsString(identifyResponse), "Identify API Response");

            if (identifyResponse != null) {
                if (identifyResponse.getMessages() != null && identifyResponse.getMessages().hasErrorValue()) {
                    JOptionPane.showMessageDialog(null,
                        objectMapper.writeValueAsString(identifyResponse.getMessages()), "Authentication Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                RemediationOption[] identifyRemediationOptions = identifyResponse.remediation().remediationOptions();

                Optional<RemediationOption> identifyRemediationOptionOptional = Arrays.stream(identifyRemediationOptions)
                    .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                    .findFirst();

                // populate methodType -> id mapping
                Map<String, String> authenticatorOptionsMap = getAuthenticatorOptions(identifyRemediationOptionOptional.get());

                // security_question authentication (step-1)

                // challenge
                ChallengeRequest secQnAuthenticatorChallengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorOptionsMap.get("security_question"), "security_question"));
                printInfo(objectMapper.writeValueAsString(secQnAuthenticatorChallengeRequest), "Challenge API Request (Security Question Authentication)");

                OktaIdentityEngineResponse secQnAuthenticatorChallengeResponse = identifyRemediationOptionOptional.get().proceed(client, secQnAuthenticatorChallengeRequest);
                printInfo(objectMapper.writeValueAsString(secQnAuthenticatorChallengeResponse), "Challenge API Response (Security Question Authentication)");

                RemediationOption[] secQnAuthenticatorChallengeResponseRemediationOptions = secQnAuthenticatorChallengeResponse.remediation().remediationOptions();

                Optional<RemediationOption> challengeAuthenticatorRemediationOption = Arrays.stream(secQnAuthenticatorChallengeResponseRemediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();

                // answer challenge
                final String secQnAnswer = JOptionPane.showInputDialog("Enter Security Question Answer: ");

                if (Strings.isEmpty(secQnAnswer)) {
                    log.error("Missing Security Question Answer");
                    return;
                }

                AnswerChallengeRequest secQnAuthenticatorAnswerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(null, secQnAnswer));
                printInfo(objectMapper.writeValueAsString(secQnAuthenticatorAnswerChallengeRequest), "Answer Challenge API Request (Security Question Authentication)");

                OktaIdentityEngineResponse secQnAuthenticatorAnswerChallengeResponse = challengeAuthenticatorRemediationOption.get().proceed(client, secQnAuthenticatorAnswerChallengeRequest);
                printInfo(objectMapper.writeValueAsString(secQnAuthenticatorAnswerChallengeResponse), "Answer Challenge API Response (Security Question Authentication)");

                RemediationOption[] secQnAuthenticatorAnswerChallengeResponseRemediationOptions = secQnAuthenticatorAnswerChallengeResponse.remediation().remediationOptions();

/*
                // below segment is commented out because, only either of security question or password authenticator is required, not both.

                // password authentication (step 1)

                // challenge
                ChallengeRequest passwordAuthenticatorChallengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorOptionsMap.get("password"), "password"));
                printInfo(objectMapper.writeValueAsString(passwordAuthenticatorChallengeRequest), "Challenge API Request (Password Authentication)");

                OktaIdentityEngineResponse passwordAuthenticatorChallengeResponse = identifyRemediationOptionOptional.get().proceed(client, passwordAuthenticatorChallengeRequest);
                printInfo(objectMapper.writeValueAsString(passwordAuthenticatorChallengeResponse), "Challenge API Response (Password Authentication)");

                RemediationOption[] passwordAuthenticatorChallengeResponseRemediationOptions = passwordAuthenticatorChallengeResponse.remediation().remediationOptions();

                Optional<RemediationOption> challengeAuthenticatorRemediationOption = Arrays.stream(passwordAuthenticatorChallengeResponseRemediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();

                // answer challenge
                final String password = getUserPassword();

                if (Strings.isEmpty(password)) {
                    log.error("Missing password");
                    return;
                }

                AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(password, null));
                printInfo(objectMapper.writeValueAsString(passwordAuthenticatorAnswerChallengeRequest), "Answer Challenge API Request (Password Authentication)");

                OktaIdentityEngineResponse passwordAuthenticatorAnswerChallengeResponse = challengeAuthenticatorRemediationOption.get().proceed(client, passwordAuthenticatorAnswerChallengeRequest);
                printInfo(objectMapper.writeValueAsString(passwordAuthenticatorAnswerChallengeResponse), "Answer Challenge API Response (Password Authentication)");

                RemediationOption[] passwordAuthenticatorAnswerChallengeResponseRemediationOptions = passwordAuthenticatorAnswerChallengeResponse.remediation().remediationOptions();
*/

                // email authentication (step 2)

                // challenge
                Optional<RemediationOption> emailAuthenticatorRemediationOption = Arrays.stream(secQnAuthenticatorAnswerChallengeResponseRemediationOptions)
                    .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                    .findFirst();

                ChallengeRequest emailAuthenticatorChallengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorOptionsMap.get("email"), "email"));
                printInfo(objectMapper.writeValueAsString(emailAuthenticatorChallengeRequest), "Challenge API Request (Email Authentication)");

                OktaIdentityEngineResponse emailAuthenticatorChallengeResponse = emailAuthenticatorRemediationOption.get().proceed(client, emailAuthenticatorChallengeRequest);
                printInfo(objectMapper.writeValueAsString(emailAuthenticatorChallengeResponse), "Challenge API Response (Email Authentication)");

                RemediationOption[] emailAuthenticatorChallengeResponseRemediationOptions = emailAuthenticatorChallengeResponse.remediation().remediationOptions();

                challengeAuthenticatorRemediationOption = Arrays.stream(emailAuthenticatorChallengeResponseRemediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();

                // answer challenge
                final String emailPasscode = JOptionPane.showInputDialog("Enter email passcode: ");

                if (Strings.isEmpty(emailPasscode)) {
                    log.error("Missing email passcode");
                    return;
                }

                AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(emailPasscode, null));
                printInfo(objectMapper.writeValueAsString(emailAuthenticatorAnswerChallengeRequest), "Answer Challenge API Request (Email Authentication)");

                OktaIdentityEngineResponse emailAuthenticatorAnswerChallengeResponse = challengeAuthenticatorRemediationOption.get().proceed(client, emailAuthenticatorAnswerChallengeRequest);
                printInfo(objectMapper.writeValueAsString(emailAuthenticatorAnswerChallengeResponse), "Answer Challenge API Response (Email Authentication)");

                if (emailAuthenticatorAnswerChallengeResponse.getSuccess() != null && emailAuthenticatorAnswerChallengeResponse.remediation() == null) {
                    // no more remediation steps and we have completed successfully!
                    printInfo(objectMapper.writeValueAsString(emailAuthenticatorAnswerChallengeResponse.getSuccess()), "Success");
                }
            }
        }
    }

    // helper to extract authenticator options from remediation options in oie response

    static Map<String, String> getAuthenticatorOptions(RemediationOption remediationOption) {

        // store methodType -> id mapping
        Map<String, String> authenticatorOptionsMap = new HashMap<>();

        FormValue[] formValues = remediationOption.form();

        Optional<FormValue> formValueOptional = Arrays.stream(formValues)
            .filter(x -> "authenticator".equals(x.getName()))
            .findFirst();

        if (formValueOptional.isPresent()) {
            Options[] options = formValueOptional.get().options();

            for (Options option : options) {
                String key = null, val = null;
                FormValue[] optionFormValues = option.getValue().getForm().getValue();
                for (FormValue formValue : optionFormValues) {
                    if (formValue.getName().equals("methodType")) {
                        key = String.valueOf(formValue.getValue());
                    }
                    if (formValue.getName().equals("id")) {
                        val = String.valueOf(formValue.getValue());
                    }
                }
                authenticatorOptionsMap.put(key, val);
            }
        }
        return authenticatorOptionsMap;
    }

    // helper for masked password input
    static String getUserPassword() {
        JPasswordField jpf = new JPasswordField(25);
        JLabel jl = new JLabel("Enter Password: ");
        Box box = Box.createHorizontalBox();
        box.add(jl);
        box.add(jpf);
        int x = JOptionPane.showConfirmDialog(null, box, "Password Challenge", JOptionPane.OK_OPTION);
        return jpf.getText();
    }

    // helper to print info in ui
    static void printInfo(String text, String title) {
        JFrame frame = new JFrame ("Identity Engine Java Client Demo");
        frame.setSize(180,100);
        frame.setResizable(true);

        JTextArea ta = new JTextArea(50, 50);
        ta.setText(text);
        ta.setWrapStyleWord(true);
        ta.setLineWrap(true);
        ta.setCaretPosition(0);
        ta.setEditable(false);

        JScrollPane scroll = new JScrollPane(ta);
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        frame.add(scroll);
        frame.setVisible(false);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JOptionPane.showMessageDialog(frame, new JScrollPane(ta), title, JOptionPane.INFORMATION_MESSAGE);
    }
}
