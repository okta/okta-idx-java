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

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

final class Util {
    private static final Logger logger = LoggerFactory.getLogger(Util.class);

    private Util() {
        // No instances.
    }

    static void printRemediationOptions(RemediationOption[] remediationOptions) {
        logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                .map(RemediationOption::getName)
                .collect(Collectors.toList()));
    }

    static RemediationOption extractRemediationOption(RemediationOption[] remediationOptions,
            String remediationType) {
        Optional<RemediationOption> remediationOptionsOptional = extractOptionalRemediationOption(remediationOptions, remediationType);
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + remediationType);
        return remediationOptionsOptional.get();
    }

    static Optional<RemediationOption> extractOptionalRemediationOption(RemediationOption[] remediationOptions,
            String remediationType) {
        return Arrays.stream(remediationOptions)
                .filter(x -> remediationType.equals(x.getName()))
                .findFirst();
    }

    static RemediationOption extractRemediationOption(RemediationOption[] remediationOptions,
            Set<String> remediationTypes) {
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> remediationTypes.contains(x.getName()))
                .findFirst();
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + remediationTypes);
        return remediationOptionsOptional.get();
    }

    static void copyErrorMessages(IDXResponse idxResponse, AuthenticationResponse authenticationResponse) {
        Arrays.stream(idxResponse.getMessages().getValue())
                .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
    }

    static boolean isRemediationRequireCredentials(String remediationOptionName,
            IDXResponse idxResponse) {
        if (idxResponse.remediation() == null) {
            return false;
        }
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();

        RemediationOption remediationOption = extractRemediationOption(remediationOptions, remediationOptionName);
        FormValue[] formValues = remediationOption.form();

        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }
}
