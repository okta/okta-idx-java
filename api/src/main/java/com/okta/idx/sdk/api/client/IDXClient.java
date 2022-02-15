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
package com.okta.idx.sdk.api.client;

import com.okta.commons.http.Response;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.PollRequest;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;

/**
 * Client to interact with the IDX backend APIs.
 */
public interface IDXClient {

    IDXClientContext interact() throws ProcessingException;

    IDXClientContext interact(String recoveryToken) throws ProcessingException;

    IDXResponse introspect(IDXClientContext idxClientContext) throws ProcessingException;

    IDXResponse identify(IdentifyRequest identifyRequest, String href) throws ProcessingException;

    IDXResponse enroll(EnrollRequest enrollRequest, String href) throws ProcessingException;

    IDXResponse challenge(ChallengeRequest challengeRequest, String href) throws ProcessingException;

    IDXResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest, String href) throws ProcessingException;

    IDXResponse cancel(String stateHandle) throws ProcessingException;

    IDXResponse enrollUpdateUserProfile(EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest, String href) throws ProcessingException;

    IDXResponse skip(SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest, String href) throws ProcessingException;

    IDXResponse recover(RecoverRequest recoverRequest, String href) throws ProcessingException;

    IDXResponse poll(PollRequest pollRequest, String href) throws ProcessingException;

    TokenResponse token(String url, String grantType, String interactionCode, IDXClientContext idxClientContext) throws ProcessingException;

    void revokeToken(String tokenType, String token) throws ProcessingException;

    Response verifyEmailToken(String token) throws ProcessingException;
}
