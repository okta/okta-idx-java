package com.okta.sdk.client;

import com.okta.sdk.model.AnswerChallengeRequest;
import com.okta.sdk.model.Cancel;
import com.okta.sdk.model.ChallengeRequest;
import com.okta.sdk.model.IdentifyRequest;
import com.okta.sdk.model.OktaIdentityEngineResponse;

public interface Client {

    OktaIdentityEngineResponse introspect(String stateHandle);

    OktaIdentityEngineResponse identify(IdentifyRequest identifyRequest);

    OktaIdentityEngineResponse challenge(ChallengeRequest challengeRequest);

    OktaIdentityEngineResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest);

    OktaIdentityEngineResponse cancel(Cancel cancel);
}
