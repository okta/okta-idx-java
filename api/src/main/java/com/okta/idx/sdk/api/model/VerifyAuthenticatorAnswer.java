/*
 * Copyright (c) 2022-Present, Okta, Inc.
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

public class VerifyAuthenticatorAnswer {

    private String answer;

    private String questionKey;

    public VerifyAuthenticatorAnswer(String answer, String questionKey) {
        this.answer = answer;
        this.questionKey = questionKey;
    }

    public String getAnswer() {
        return answer;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public String getQuestionKey() {
        return questionKey;
    }

    public void setQuestionKey(String questionKey) {
        this.questionKey = questionKey;
    }
}
