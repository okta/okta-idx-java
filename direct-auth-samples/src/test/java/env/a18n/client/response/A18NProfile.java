package env.a18n.client.response;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class A18NProfile {

    private static final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private String profileId;

    private String phoneNumber;

    private String emailAddress;

    private String url;

    public String raw() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    public String getProfileId() {
        return profileId;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public String getUrl() {
        return url;
    }
}
