package com.okta.idx.sdk.impl.util


import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat

class TestClientUtil {

    @Test
    void issuerUri_rootOrgTest() {
        assertThat "issuer uri expected to be root/org)",
                ClientUtil.isRootOrgIssuer("https://sample.okta.com")
        assertThat "issuer uri expected to be root/org)",
                ClientUtil.isRootOrgIssuer("https://dev-12345.oktapreview.com/")
        assertThat "issuer uri expected to be root/org)",
                ClientUtil.isRootOrgIssuer("https://example.io")
    }

    @Test
    void issuerUri_nonRootOrgTest() {
        assertThat "issuer uri expected to be non-root/org)",
                !ClientUtil.isRootOrgIssuer("https://sample.okta.com/oauth2/default")
        assertThat "issuer uri expected to be non-root/org)",
                !ClientUtil.isRootOrgIssuer("https://example.io/oauth2/ausvd5ple5TRRsbcJ0h7")
    }
}
