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
package com.okta.idx.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.io.Serializable;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ContextualData implements Serializable {

    private static final long serialVersionUID = -8922607300607832245L;
    private QrCode qrcode;
    private String sharedSecret;
    private ActivationData activationData;
    private ChallengeData challengeData;
    private String correctAnswer;

    public QrCode getQrcode() {
        return qrcode;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public ActivationData getActivationData() { return activationData; }

    public ChallengeData getChallengeData() { return challengeData; }

    public String getCorrectAnswer() { return correctAnswer; }
}
