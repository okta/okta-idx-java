package com.okta.sdk.impl.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.collect.Sets;
import com.okta.sdk.model.AnswerChallengeRequest;
import com.okta.sdk.model.Authenticator;
import com.okta.sdk.model.ChallengeRequest;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.model.Credentials;
import com.okta.sdk.model.FormValue;
import com.okta.sdk.model.IdentifyRequest;
import com.okta.sdk.model.OktaIdentityEngineResponse;
import com.okta.sdk.model.Options;
import com.okta.sdk.model.RemediationOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.HashMap;
import java.util.Map;

public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String... args) throws Exception {

        final Client client = Clients.builder()
            .setIssuer("https://devex-idx-testing.oktapreview.com")
            .setClientId("test-client-id")
            .setScopes(Sets.newHashSet("test-scope"))
            .build();

        // obtain state handle from browser and enter it
        final String stateHandle = JOptionPane.showInputDialog("Enter stateHandle: ");

        // invoke introspect endpoint with the state handle & get remediation options
        OktaIdentityEngineResponse introspectResponse =
            client.introspect(stateHandle);

        if (introspectResponse != null) {
            RemediationOption[] introspectRemediationOptions = introspectResponse.remediation().remediationOptions();

            // invoke identify endpoint & get remediation options
            IdentifyRequest identifyRequest = new IdentifyRequest("arvind.mercedes@gmail.com", stateHandle, false);
            OktaIdentityEngineResponse identifyResponse = client.identify(identifyRequest);

            if (identifyResponse != null) {
                RemediationOption[] identifyRemediationOptions = identifyResponse.remediation().remediationOptions();
                //log.info("=== IDENTIFY REMEDIATION OPTIONS === {}", objectMapper.writeValueAsString(identifyRemediationOptions));

                FormValue[] formValues = identifyRemediationOptions[0].form();
                Options[] options = formValues[0].options();

                // store methodType -> id mapping
                Map<String, String> authenticatorLookupMap = new HashMap<>();

                for (Options option : options) {
                    String key = null, val = null;
                    //log.info("=== OPTION LABEL === {}", objectMapper.writeValueAsString(option.getLabel()));
                    FormValue[] optionFormValues = option.getValue().getForm().getValue();
                    //log.info("=== OPTION VALUE === {}", objectMapper.writeValueAsString(optionFormValues));
                    for (FormValue formValue : optionFormValues) {
                        if (formValue.getName().equals("methodType")) {
                            key = String.valueOf(formValue.getValue());
                        }
                        if (formValue.getName().equals("id")) {
                            val = String.valueOf(formValue.getValue());
                        }
                    }
                    authenticatorLookupMap.put(key, val);
                }

                //log.info("=== AUTHENTICATOR MAP === {}", authenticatorLookupMap);

                // invoke challenge endpoint with authenticator id & method type (password)
                ChallengeRequest challengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorLookupMap.get("password"), "password"));
                OktaIdentityEngineResponse challengeResponse = client.challenge(challengeRequest);
                RemediationOption[] challengeResponseRemediationOptions = challengeResponse.remediation().remediationOptions();
                //log.info("=== CHALLENGE RESPONSE (password) REMEDIATION OPTIONS === {}", objectMapper.writeValueAsString(challengeResponseRemediationOptions));

                // answer challenge (password)
                final String password = getUserPassword();

                AnswerChallengeRequest answerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(password));
                OktaIdentityEngineResponse answerChallengeResponse = client.answerChallenge(answerChallengeRequest);
                RemediationOption[] answerChallengeResponseRemediationOptions = answerChallengeResponse.remediation().remediationOptions();
                //log.info("=== ANSWER CHALLENGE RESPONSE (password) REMEDIATION OPTIONS === {}", objectMapper.writeValueAsString(answerChallengeResponseRemediationOptions));

                // invoke challenge endpoint with authenticator id & method type (email)
                challengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorLookupMap.get("email"), "email"));
                challengeResponse = client.challenge(challengeRequest);
                challengeResponseRemediationOptions = challengeResponse.remediation().remediationOptions();
                //log.info("=== CHALLENGE RESPONSE REMEDIATION (email) OPTIONS === {}", objectMapper.writeValueAsString(challengeResponseRemediationOptions));

                // answer challenge (email)
                final String passcodeInEmail = JOptionPane.showInputDialog("Enter Email Passcode: ");

                answerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(passcodeInEmail));
                answerChallengeResponse = client.answerChallenge(answerChallengeRequest);

                if (answerChallengeResponse.remediation() == null && answerChallengeResponse.getSuccess() != null) {
                    // no more remediation steps and we have completed successfully!
                    log.info("=== SUCCESS === {}", objectMapper.writeValueAsString(answerChallengeResponse.getSuccess()));
                }
            }
        }
    }

    // helper for masked password input
    static String getUserPassword() {
        JPasswordField jpf = new JPasswordField(30);
        JLabel jl = new JLabel("Enter Password: ");
        Box box = Box.createHorizontalBox();
        box.add(jl);
        box.add(jpf);
        int x = JOptionPane.showConfirmDialog(null, box, "Password Challenge", JOptionPane.OK_CANCEL_OPTION);

        if (x == JOptionPane.OK_OPTION) {
            return jpf.getText();
        }
        return null;
    }
}
