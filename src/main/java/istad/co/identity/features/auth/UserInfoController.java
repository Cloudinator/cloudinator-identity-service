package istad.co.identity.features.auth;

import istad.co.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class UserInfoController {

    private final UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @AuthenticationPrincipal OAuth2User oauth2User,
            Authentication authentication) {

        Map<String, Object> userInfo = new HashMap<>();

        if (oauth2User != null) {
            // Get provider type
            String provider = "local";
            if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
                provider = oauth2Authentication.getAuthorizedClientRegistrationId();
            }

            userInfo.put("provider", provider);

            // Get common attributes
            userInfo.put("name", oauth2User.getAttribute("name"));
            userInfo.put("email", oauth2User.getAttribute("email"));

            // Add provider-specific attributes
            switch (provider) {
                case "facebook" -> {
                    userInfo.put("id", oauth2User.getAttribute("id"));
                    Map<String, Object> picture = oauth2User.getAttribute("picture");
                    if (picture != null && picture.get("data") instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> pictureData = (Map<String, Object>) picture.get("data");
                        userInfo.put("picture", pictureData.get("url"));
                    }
                }
                case "github" -> {
                    userInfo.put("id", oauth2User.getAttribute("id"));
                    userInfo.put("login", oauth2User.getAttribute("login"));
                    userInfo.put("avatar_url", oauth2User.getAttribute("avatar_url"));
                }
                case "google" -> {
                    userInfo.put("picture", oauth2User.getAttribute("picture"));
                    userInfo.put("email_verified", oauth2User.getAttribute("email_verified"));
                }
            }

            // Add user details from our database
            String email = oauth2User.getAttribute("email");
            if (email != null) {
                userRepository.findByEmail(email).ifPresent(user -> {
                    userInfo.put("userUuid", user.getUuid());
                    userInfo.put("databaseUsername", user.getUsername());
                });
            }

            return ResponseEntity.ok(userInfo);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/user/details")
    public ResponseEntity<Map<String, Object>> getUserDetails(Authentication authentication) {
        Map<String, Object> details = new HashMap<>();

        if (authentication != null && authentication.isAuthenticated()) {
            details.put("name", authentication.getName());
            details.put("authorities", authentication.getAuthorities());

            if (authentication.getPrincipal() instanceof OAuth2User oauth2User) {
                details.put("attributes", oauth2User.getAttributes());
            }

            return ResponseEntity.ok(details);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/user/token")
    public ResponseEntity<Map<String, Object>> getTokenInfo(
            @AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> tokenInfo = new HashMap<>();
        tokenInfo.put("attributes", principal.getAttributes());
        tokenInfo.put("authorities", principal.getAuthorities());
        tokenInfo.put("name", principal.getName());

        return ResponseEntity.ok(tokenInfo);
    }
}