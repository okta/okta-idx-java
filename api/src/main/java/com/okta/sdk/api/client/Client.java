package com.okta.sdk.api.client;

import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.model.Cancel;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;

public interface Client {

    OktaIdentityEngineResponse introspect(String stateHandle);

    OktaIdentityEngineResponse identify(IdentifyRequest identifyRequest);

    OktaIdentityEngineResponse challenge(ChallengeRequest challengeRequest);

    OktaIdentityEngineResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest);

    OktaIdentityEngineResponse cancel(Cancel cancel);
}
