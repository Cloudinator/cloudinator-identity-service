package istad.co.identity.features.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/github")
public class GithubController {
    // Use constructor injection for RestTemplate
    private final RestTemplate restTemplate;

    /**
     * Fetches GitHub repositories for the authenticated user
     * @param oauth2User The authenticated OAuth2 user
     * @param authorizedClient The authorized GitHub OAuth2 client
     * @return ResponseEntity containing repos and user data
     */
    @GetMapping("/repos")
    public ResponseEntity<Object> getGithubRepos(
            @AuthenticationPrincipal OAuth2User oauth2User,
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient
    ) {
        // Verify the user is authenticated with GitHub
        if (!isGithubUser()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authenticated with GitHub"));
        }

        try {
            // Prepare GitHub API request
            HttpHeaders headers = createGithubHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // Get repos from GitHub API
            String reposUrl = oauth2User.getAttribute("repos_url");
            ResponseEntity<Object[]> reposResponse = restTemplate.exchange(
                    reposUrl,
                    HttpMethod.GET,
                    entity,
                    Object[].class
            );

            // Return repos and user data
            return ResponseEntity.ok(Map.of(
                    "repos", reposResponse.getBody(),
                    "user", oauth2User.getAttributes()
            ));
        } catch (Exception e) {
            log.error("Error fetching GitHub repositories: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch GitHub data: " + e.getMessage()));
        }
    }

    /**
     * Fetches GitHub profile information for the authenticated user
     * @param oauth2User The authenticated OAuth2 user
     * @return ResponseEntity containing profile information
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getGithubProfile(
            @AuthenticationPrincipal OAuth2User oauth2User
    ) {
        if (oauth2User == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
        }

        Map<String, Object> profile = new HashMap<>();
        // Extract relevant profile information
        profile.put("username", oauth2User.getAttribute("login"));
        profile.put("name", oauth2User.getAttribute("name"));
        profile.put("avatar", oauth2User.getAttribute("avatar_url"));
        profile.put("url", oauth2User.getAttribute("html_url"));
        profile.put("followers", oauth2User.getAttribute("followers"));
        profile.put("following", oauth2User.getAttribute("following"));
        profile.put("public_repos", oauth2User.getAttribute("public_repos"));
        profile.put("bio", oauth2User.getAttribute("bio"));
        profile.put("location", oauth2User.getAttribute("location"));
        profile.put("created_at", oauth2User.getAttribute("created_at"));

        return ResponseEntity.ok(profile);
    }

    /**
     * Retrieves the GitHub OAuth token information
     * @param authorizedClient The authorized GitHub OAuth2 client
     * @return ResponseEntity containing token information
     */
    @GetMapping("/token")
    public ResponseEntity<Map<String, Object>> getGithubToken(
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient
    ) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        Map<String, Object> tokenInfo = new HashMap<>();
        tokenInfo.put("token_value", accessToken.getTokenValue());
        tokenInfo.put("token_type", accessToken.getTokenType().getValue());
        tokenInfo.put("expires_at", accessToken.getExpiresAt());
        tokenInfo.put("scopes", accessToken.getScopes());

        return ResponseEntity.ok(tokenInfo);
    }

    // Helper methods
    private boolean isGithubUser() {
        return SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken auth
                && "github".equals(auth.getAuthorizedClientRegistrationId());
    }

    private HttpHeaders createGithubHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Accept", "application/vnd.github.v3+json");
        return headers;
    }

}