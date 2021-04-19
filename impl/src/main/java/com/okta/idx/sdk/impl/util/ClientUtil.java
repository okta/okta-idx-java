package com.okta.idx.sdk.impl.util;

import com.okta.commons.lang.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;

public class ClientUtil {

    private static final Logger logger = LoggerFactory.getLogger(ClientUtil.class);

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
     * @param issuerUri
     * @return true if root/org, false otherwise
     */
    public static boolean isRootOrgIssuer(String issuerUri) throws MalformedURLException {
        String uriPath = new URL(issuerUri).getPath();

        if (Strings.hasText(uriPath)) {
            String[] tokenizedUri = uriPath.substring(uriPath.indexOf("/")+1).split("/");

            if (tokenizedUri.length >= 2 &&
                    "oauth2".equals(tokenizedUri[0]) &&
                    Strings.hasText(tokenizedUri[1])) {
                logger.debug("The issuer URL: '{}' is an Okta custom authorization server", issuerUri);
                return false;
            }
        }

        logger.debug("The issuer URL: '{}' is an Okta root/org authorization server", issuerUri);
        return true;
    }
}
