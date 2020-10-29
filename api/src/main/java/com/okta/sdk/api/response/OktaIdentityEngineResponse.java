package com.okta.sdk.api.response;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.okta.sdk.api.model.App;
import com.okta.sdk.api.model.Cancel;
import com.okta.sdk.api.model.Messages;
import com.okta.sdk.api.model.Remediation;
import com.okta.sdk.api.model.Success;
import com.okta.sdk.api.model.User;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class OktaIdentityEngineResponse {

    private static final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * The stateHandle is used for all calls for the flow.
     */
    private String stateHandle;

    /**
     * The version that needs to be used in the headers
     */
    private String version;

    /**
     * When the current remediation flow expires
     */
    private String expiresAt;

    /**
     * The intent of the Okta Identity Engine flow
     */
    private String intent;

    private Remediation remediation;

    private Messages messages;

    // TODO: model below objects

/*
    currentAuthenticator
    currentAuthenticatorEnrollment
    authenticators
    authenticatorEnrollments
    recoveryAuthenticator
    enrollmentAuthenticator
    unenrollmentAuthenticator
    authenticatorChallenge
*/

    private User user;

    private App app;

    private Success success;

    private Cancel cancel;

    /**
     * Return the current remediation object. MAY be null if there are no further remediation steps necessary
     *
     * @return Remediation|null
     */
    public Remediation remediation() {
        return this.remediation;
    }

    /**
     * The method to call when you want to cancel the Okta Identity Engine flow. This will return an OktaIdentityEngineResponse
     *
     * @return OktaIdentityEngineResponse
     */
    public OktaIdentityEngineResponse cancel() {
        //TODO: do actual cancel from here? better for client to call client.cancel instead.
        return null;
    }

    /**
     * Returns the raw JSON body of the Okta Identity Engine response.
     *
     * @return stdObj JSON body
     */
    public String raw() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    public Success getSuccess() {
        return success;
    }

    public Messages getMessages() {
        return messages;
    }

}
