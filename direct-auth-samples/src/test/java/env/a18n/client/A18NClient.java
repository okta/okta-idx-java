package env.a18n.client;

import env.a18n.client.response.A18NEmail;
import env.a18n.client.response.A18NProfile;

public interface A18NClient {

    A18NProfile createProfile();

    void deleteProfile(A18NProfile profile);

    A18NEmail getLatestEmail(A18NProfile profile);
}
