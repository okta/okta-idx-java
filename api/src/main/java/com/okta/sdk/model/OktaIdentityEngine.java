package com.okta.sdk.model;

import java.util.List;

public interface OktaIdentityEngine {

    /**
     * Convenience method to start the OIE Flow.
     *
     * NOTE: The call to `start()` is a convenience method to call `interact()` and `introspect()`
     * automatically for the developer. This will kick off the flow for the LOGIN intent
     * for authentication against the application and authorization server specified.
     *
     * @param issuer The issuer for your authorization server.
     * @param clientId The client ID for your application.
     * @param scopes The list of string based scopes.
     *
     * @return OktaIdentityEngineResponse
     *
     * @throws IllegalArgumentException
     *   MUST be thrown if any of the following conditions met:
     *     - Issuer fails validation for standard Okta Copy/Paste Concerns
     *     - ClientId fails validation for standard Okta Copy/Paste Concerns
     *     - Scope is neither an array nor a Traversable list of strings
     */
    OktaIdentityEngineResponse start(String issuer, String clientId, List<String> scopes);

    /**
     * Begin the interaction with the Okta Identity Engine
     *
     * @param issuer The issuer for your authorization server.
     * @param clientId The client ID for your application.
     * @param scopes The list of string based scopes.
     *
     * @return stdObj An Object that contains the `interact_handle` that will be used for `introspect()`
     *
     * @throws IllegalArgumentException
     *   MUST be thrown if any of the following conditions met:
     *     - Issuer fails validation for standard Okta Copy/Paste Concerns
     *     - ClientId fails validation for standard Okta Copy/Paste Concerns
     *     - Scope is neither an array nor a Traversable list of Strings
     */
    Object interact(String issuer, String clientId, List<String> scopes);

    /**
     * Call the Okta Identity Engine introspect endpoint to get remediation steps
     *
     * @param interactionHandle The interaction handle that was returned by the `interact()` call
     *
     * @return OktaIdentityEngineResponse
     */
    OktaIdentityEngineResponse introspect(String interactionHandle);
}
