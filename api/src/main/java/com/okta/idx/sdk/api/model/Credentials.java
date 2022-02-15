/*
 * Copyright (c) 2020-Present, Okta, Inc.
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

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Credentials {

    public char[] passcode;

    public String questionKey;

    public String question;

    public char[] answer;

    public String authenticatorData;

    public String clientData;

    public String attestation;

    public String signatureData;

    public String totp;

    public void setPasscode(char[] passcode) {
        this.passcode = passcode;
    }

    public void setQuestionKey(String questionKey) {
        this.questionKey = questionKey;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public void setAnswer(char[] answer) {
        this.answer = answer;
    }

    public void setAuthenticatorData(String authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

    public void setAttestation(String attestation) {
        this.attestation = attestation;
    }

    public void setSignatureData(String signatureData) {
        this.signatureData = signatureData;
    }

    public void setTotp(String totp) {
        this.totp = totp;
    }
}
