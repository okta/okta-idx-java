/*
 * Copyright 2017 Okta
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
package quickstart;

import com.okta.sdk.api.client.Clients;
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.model.Credentials;
import com.okta.sdk.api.model.Token;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;
import com.okta.sdk.api.exception.ProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This class demonstrates the code found in the SDK QuickStart Guide
 *
 * @since 1.0.0
 */
@SuppressWarnings("PMD.UnusedLocalVariable")
public class Quickstart {

    public static void main(String[] args) throws ProcessingException {
        Set<String> scope = new HashSet<>(Arrays.asList("openid", "profile"));

        OktaIdentityEngineClient client = Clients.builder()
            .setIssuer("https://idx-devex.trexcloud.com")
            .setClientId("0oa3jxy2kpqZs9fOU0g7")
            .setClientSecret("6NMR5HuSlZ8LOM5X7jHqE9Up9xLOqoHA7NGymjPo")
            .setScopes(scope)
            .build();

        OktaIdentityEngineResponse oktaIdentityEngineResponse = client.start();

        String stateHandle = oktaIdentityEngineResponse.getStateHandle();

        oktaIdentityEngineResponse = client.identify(new IdentifyRequest("arvind.krishnakumar@okta.com", new Credentials("Sclass15683!", null), false, stateHandle));

        if (oktaIdentityEngineResponse.loginSuccess()) {
            Token token = oktaIdentityEngineResponse.getSuccessWithInteractionCode().exchangeCode(client);
            println(token.getAccessToken());
        }
    }

    private static void println(String message) {
        System.out.println(message);
        System.out.flush();
    }
}
