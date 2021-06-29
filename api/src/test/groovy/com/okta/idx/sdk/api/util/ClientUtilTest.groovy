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
package com.okta.idx.sdk.api.util

import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class ClientUtilTest {

    @Test
    void testNormalizedUrl() {
        // root org issuer
        assertThat(ClientUtil.getNormalizedUri("https://foo.oktapreview.com", "/v1/interact"),
                is("https://foo.oktapreview.com/oauth2/v1/interact"))
        // non root org issuer
        assertThat(ClientUtil.getNormalizedUri("https://foo.oktapreview.com/oauth2/default", "/v1/interact"),
                is("https://foo.oktapreview.com/oauth2/default/v1/interact"))
    }

    @Test
    void testRootOrgIssuer() {
        // root org issuer
        assertThat(ClientUtil.isRootOrgIssuer("https://foo.oktapreview.com"), is(true))
        // non root org issuer
        assertThat(ClientUtil.isRootOrgIssuer("https://foo.oktapreview.com/oauth2/default"), is(false))
    }
}
