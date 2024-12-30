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
import java.util.List;
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
    // Get GitHub repository details
    //http://localhost:8888/api/github/repos/MuyleangIng/angular-jenkins
    @GetMapping("/repos/{owner}/{repo}")
    public ResponseEntity<Object> getGithubRepoDetails(
            @PathVariable String owner,
            @PathVariable String repo,
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient
    ) {
        try {
            HttpHeaders headers = createGithubHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // Get repo details
            String repoUrl = String.format("https://api.github.com/repos/%s/%s", owner, repo);
            ResponseEntity<Map> repoResponse = restTemplate.exchange(
                    repoUrl,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            // Get repository contents
            String contentsUrl = repoUrl + "/contents";
            ResponseEntity<List> contentsResponse = restTemplate.exchange(
                    contentsUrl,
                    HttpMethod.GET,
                    entity,
                    List.class
            );

            Map<String, Object> response = new HashMap<>();
            response.put("repository", repoResponse.getBody());
            response.put("contents", contentsResponse.getBody());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error fetching GitHub repository details: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // Get file content from GitHub
    @GetMapping("/github/repos/{owner}/{repo}/contents/{path}")
    public ResponseEntity<Object> getGithubFileContent(
            @PathVariable String owner,
            @PathVariable String repo,
            @PathVariable String path,
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient
    ) {
        try {
            HttpHeaders headers = createGithubHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            String contentUrl = String.format("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path);
            ResponseEntity<Map> response = restTemplate.exchange(
                    contentUrl,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            log.error("Error fetching GitHub file content: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
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