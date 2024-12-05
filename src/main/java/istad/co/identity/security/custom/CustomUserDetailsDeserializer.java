package istad.co.identity.security.custom;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Set;

@Slf4j
public class CustomUserDetailsDeserializer extends JsonDeserializer<CustomUserDetails> {

    private static final TypeReference<Set<UserAuthority>> SIMPLE_GRANTED_AUTHORITY_LIST = new TypeReference<>() {
    };

    @Override
    public CustomUserDetails deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode jsonNode = mapper.readTree(p);

        JsonNode userJsonNode = readJsonNode(jsonNode, "user");

        Set<UserAuthority> userAuthorities = mapper.convertValue(
                jsonNode.get("userAuthorities"),
                SIMPLE_GRANTED_AUTHORITY_LIST
        );

        log.info("Authorities: {}", userAuthorities);

        Long id = readJsonNode(userJsonNode, "id").asLong();
        String uuid = readJsonNode(userJsonNode, "uuid").asText();
        String username = readJsonNode(userJsonNode, "username").asText();
        String email = readJsonNode(userJsonNode, "email").asText();
        String password = readJsonNode(userJsonNode, "password").asText();
        boolean isEnabled = readJsonNode(userJsonNode, "isEnabled").asBoolean();
        boolean accountNoExpired = readJsonNode(userJsonNode, "accountNoExpired").asBoolean();
        boolean credentialsNonExpired = readJsonNode(userJsonNode, "credentialsNonExpired").asBoolean();
        boolean accountNonLocked = readJsonNode(userJsonNode, "accountNonLocked").asBoolean();

        String familyName = readJsonNode(userJsonNode, "familyName").asText();
        String givenName = readJsonNode(userJsonNode, "givenName").asText();
        String dob = readJsonNode(userJsonNode, "dob").asText();
        String gender = readJsonNode(userJsonNode, "gender").asText();
        String profileImage = readJsonNode(userJsonNode, "profileImage").asText();
        boolean emailVerified = readJsonNode(userJsonNode, "emailVerified").asBoolean();
        String ipAddress = readJsonNode(userJsonNode, "ipAddress").asText();
        String phoneNumber = readJsonNode(userJsonNode, "phoneNumber").asText();

        User user = new User();
        user.setId(id);
        user.setUuid(uuid);
        user.setUsername(username);
        user.setUserAuthorities(userAuthorities);
        user.setEmail(email);
        user.setPassword(password);
        user.setProfileImage(profileImage);
        log.info("DOB: {}", dob);
        user.setEmailVerified(emailVerified);
        user.setIsEnabled(isEnabled);
        user.setCredentialsNonExpired(credentialsNonExpired);
        user.setAccountNonLocked(accountNonLocked);
        user.setAccountNonExpired(accountNoExpired);
        user.setIpAddress(ipAddress);

        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setUser(user);

        return customUserDetails;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}
