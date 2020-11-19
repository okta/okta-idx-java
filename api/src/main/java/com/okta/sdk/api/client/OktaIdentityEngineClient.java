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
package com.okta.sdk.api.client;

import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.model.Token;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;

/**
 * Client to interact with the IDX backend APIs.
 */
public interface OktaIdentityEngineClient {

    InteractResponse interact() throws ProcessingException;

    OktaIdentityEngineResponse introspect(String interactionHandle) throws ProcessingException;

    OktaIdentityEngineResponse identify(IdentifyRequest identifyRequest) throws ProcessingException;

    OktaIdentityEngineResponse challenge(ChallengeRequest challengeRequest) throws ProcessingException;

    OktaIdentityEngineResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest) throws ProcessingException;

    OktaIdentityEngineResponse cancel(String stateHandle) throws ProcessingException;

    OktaIdentityEngineResponse start() throws ProcessingException;

    OktaIdentityEngineResponse start(String interactionHandle) throws ProcessingException;

    Token token(String grantType, String interactionCode) throws ProcessingException;
}
