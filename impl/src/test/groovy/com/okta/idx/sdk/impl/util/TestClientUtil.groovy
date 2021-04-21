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
package com.okta.idx.sdk.impl.util

import static com.okta.idx.sdk.api.util.ClientUtil.isRootOrgIssuer
import static com.okta.idx.sdk.api.util.ClientUtil.getNormalizedUri

import org.testng.annotations.Test

import static org.hamcrest.Matchers.is
import static org.hamcrest.MatcherAssert.assertThat

class TestClientUtil {

    @Test
    void issuerUri_rootOrgTest() {
        assertThat "issuer uri expected to be root/org)",
                isRootOrgIssuer("https://sample.okta.com")
        assertThat "issuer uri expected to be root/org)",
                isRootOrgIssuer("https://dev-12345.oktapreview.com/")
        assertThat "issuer uri expected to be root/org)",
                isRootOrgIssuer("https://example.io")
        assertThat "issuer uri expected to be root/org)",
                isRootOrgIssuer("https://example.io/")
        assertThat "issuer uri expected to be root/org)",
                isRootOrgIssuer("https://example.io//")
    }

    @Test
    void issuerUri_nonRootOrgTest() {
        assertThat "issuer uri expected to be non-root/org)",
                !isRootOrgIssuer("https://sample.okta.com/oauth2/default")
        assertThat "issuer uri expected to be non-root/org)",
                !isRootOrgIssuer("https://example.io/oauth2/ausvd5ple5TRRsbcJ0h7")
    }

    @Test
    void normalizedUri_rootOrgTest() {
        String issuer = "https://sample.okta.com"
        String resourceUri = "/v1/interact"
        assertThat(getNormalizedUri(issuer, resourceUri), is(issuer + "/oauth2" + resourceUri))

        issuer = "https://example.io/"
        assertThat(getNormalizedUri(issuer, resourceUri), is(issuer + "/oauth2" + resourceUri))

        issuer = "https://example.io//"
        assertThat(getNormalizedUri(issuer, resourceUri), is(issuer + "/oauth2" + resourceUri))
    }

    @Test
    void normalizedUri_nonRootOrgTest() {
        String issuer = "https://sample.okta.com/oauth2/default"
        String resourceUri = "/v1/interact"
        assertThat(getNormalizedUri(issuer, resourceUri), is(issuer + resourceUri))

        issuer = "https://example.io/oauth2/ausvd5ple5TRRsbcJ0h7"
        assertThat(getNormalizedUri(issuer, resourceUri), is(issuer + resourceUri))
    }
}
