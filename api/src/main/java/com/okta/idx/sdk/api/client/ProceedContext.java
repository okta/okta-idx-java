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
package com.okta.idx.sdk.api.client;

import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.PollInfo;
import com.okta.idx.sdk.api.model.Remediation;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.response.IDXResponse;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * An opaque to the developer object that's expected to be given back on the next request.
 * We use this internally to know the current state of the authentication flow.
 */
public final class ProceedContext {
    private final IDXClientContext clientContext;
    private final String stateHandle;
    private final String href;
    private final String skipHref;
    private final boolean isIdentifyInOneStep;
    private final String selectProfileEnrollHref;
    private final String resendHref;
    private final PollInfo pollInfo;
    private final Duration refresh;
    private final IDXResponse idxResponse;

    ProceedContext(IDXClientContext clientContext, String stateHandle, String href, String skipHref, boolean isIdentifyInOneStep,
                   String selectProfileEnrollHref, String resendHref, PollInfo pollInfo, Duration refresh, IDXResponse idxResponse) {
        this.clientContext = clientContext;
        this.stateHandle = stateHandle;
        this.href = href;
        this.skipHref = skipHref;
        this.isIdentifyInOneStep = isIdentifyInOneStep;
        this.selectProfileEnrollHref = selectProfileEnrollHref;
        this.resendHref = resendHref;
        this.pollInfo = pollInfo;
        this.refresh = refresh;
        this.idxResponse = idxResponse;
    }

    public IDXClientContext getClientContext() {
        return clientContext;
    }

    String getStateHandle() {
        if (idxResponse == null) {
            return stateHandle;
        }
        Remediation remediation = idxResponse.remediation();
        if (remediation != null && remediation.remediationOptions() != null && remediation.remediationOptions().size() > 0) {
            RemediationOption remediationOption = remediation.remediationOptions().get(0);
            String remediationStateHandle = WrapperUtil.getStateHandle(remediationOption.form());
            if (remediationStateHandle != null) {
                return remediationStateHandle;
            }
        }
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

    public String getResendHref() {
        return resendHref;
    }

    public PollInfo getPollInfo() {
        return pollInfo;
    }

    public Duration getRefresh() {
        return Duration.of(refresh.getSeconds(), ChronoUnit.MILLIS);
    }

    /**
     * Identifier first flow is one where just the identifier (email) is sufficient to start
     * the flow (i.e. password is not required at the start of flow).
     * @return true if identifier first flow, false otherwise
     */
    public boolean isIdentifierFirstFlow() {
        return !isIdentifyInOneStep();
    }

    IDXResponse getIdxResponse() {
        return idxResponse;
    }
}
