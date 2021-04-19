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
