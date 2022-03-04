/*
 * Copyright (c) 2021-Present, Okta, Inc.
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
package com.okta.idx.sdk.api.util;

import com.okta.commons.lang.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;

public class ClientUtil {

    private static final Logger logger = LoggerFactory.getLogger(ClientUtil.class);

    /**
     * Construct the normalized URL given an issuer and a resource uri.
     *
     * @param issuer the issuer url
     * @param resourceUri the uri of resource
     * @return the normalized full url
     * @throws IllegalArgumentException if the issuer URi is malformed
     * @deprecated This method has been renamed to getNormalizedIssuerUri
     */
    @Deprecated
    public static String getNormalizedUri(String issuer, String resourceUri) throws MalformedURLException {
        return normalizedIssuerUri(issuer, resourceUri);
    }

    /**
     * Construct the normalized URL given an issuer and a resource uri.
     *
     * @param issuer the issuer url
     * @param resourceUri the uri of resource
     * @return the normalized full url
     * @throws IllegalArgumentException if the issuer URi is malformed
     */
    public static String normalizedIssuerUri(String issuer, String resourceUri) {
        // remove trailing forward slash
        String normalizedUri = issuer.replaceAll("$/", "");

        if (isRootOrgIssuer(issuer)) {
            normalizedUri = normalizedUri + "/oauth2" + resourceUri;
        } else {
            normalizedUri = normalizedUri + resourceUri;
        }

        return normalizedUri;
    }

    /**
     * Check if the issuer is root/org URI.
     *
     * Issuer URL that does not follow the pattern '/oauth2/default' (or) '/oauth2/some_id_string' is
     * considered root/org issuer.
     *
     * e.g. https://sample.okta.com (root/org url)
     *      https://sample.okta.com/oauth2/default (non-root issuer/org url)
     *      https://sample.okta.com/oauth2/ausar5cbq5TRRsbcJ0h7 (non-root issuer/org url)
     *
     * @param issuerUri the issuer uri
     * @return true if root/org, false otherwise
     */
    public static boolean isRootOrgIssuer(String issuerUri) {
        try {
            String uriPath = new URL(issuerUri).getPath();

            if (Strings.hasText(uriPath)) {
                String[] tokenizedUri = uriPath.substring(uriPath.indexOf("/") + 1).split("/");

                if (tokenizedUri.length >= 2 &&
                    "oauth2".equals(tokenizedUri[0]) &&
                    Strings.hasText(tokenizedUri[1])) {
                    logger.debug("The issuer URL: '{}' is an Okta custom authorization server", issuerUri);
                    return false;
                }
            }

            logger.debug("The issuer URL: '{}' is an Okta root/org authorization server", issuerUri);
            return true;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Issuer URL was not a valid URL", e);
        }
    }
}
