/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.sdk.api.client;

import com.okta.idx.sdk.api.model.IDXClientContext;

/**
 * An opaque to the developer object that's expected to be given back on the next request.
 *
 * We use this internally to know the current state of the authentication flow.
 */
public final class ProceedContext {
    private final IDXClientContext clientContext;
    private final String stateHandle;
    private final String href;
    private final String skipHref;
    private final boolean isIdentifyInOneStep;
    private final String selectProfileEnrollHref;

    ProceedContext(IDXClientContext clientContext, String stateHandle, String href, String skipHref, boolean isIdentifyInOneStep,
                   String selectProfileEnrollHref) {
        this.clientContext = clientContext;
        this.stateHandle = stateHandle;
        this.href = href;
        this.skipHref = skipHref;
        this.isIdentifyInOneStep = isIdentifyInOneStep;
        this.selectProfileEnrollHref = selectProfileEnrollHref;
    }

    public IDXClientContext getClientContext() {
        return clientContext;
    }

    String getStateHandle() {
        return stateHandle;
    }

    String getHref() {
        return href;
    }

    String getSkipHref() {
        return skipHref;
    }

    boolean isIdentifyInOneStep() {
        return isIdentifyInOneStep;
    }

    String getSelectProfileEnrollHref() {
        return selectProfileEnrollHref;
    }
}
