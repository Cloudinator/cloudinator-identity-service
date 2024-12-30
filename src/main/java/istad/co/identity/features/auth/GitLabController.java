package istad.co.identity.features.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/gitlab")
public  class GitLabController {
    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientService clientService;

    @GetMapping("/repos")
    public ResponseEntity<Object> getGitLabRepos(
            @AuthenticationPrincipal OAuth2User oauth2User,
            @RegisteredOAuth2AuthorizedClient("gitlab") OAuth2AuthorizedClient authorizedClient,
            @RequestParam(required = false) String visibility,
            @RequestParam(required = false) String search
    ) {
        if (!isGitLabUser()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authenticated with GitLab"));
        }

        try {
            HttpHeaders headers = createGitLabHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            String baseUrl = "https://gitlab.com/api/v4/projects";
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(baseUrl)
                    .queryParam("owned", true);

            if (visibility != null) {
                builder.queryParam("visibility", visibility);
            }
            if (search != null) {
                builder.queryParam("search", search);
            }

            ResponseEntity<Object[]> reposResponse = restTemplate.exchange(
                    builder.toUriString(),
                    HttpMethod.GET,
                    entity,
                    Object[].class
            );

            return ResponseEntity.ok(Map.of(
                    "repos", reposResponse.getBody(),
                    "user", oauth2User.getAttributes()
            ));
        } catch (Exception e) {
            log.error("Error fetching GitLab repositories: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch GitLab data: " + e.getMessage()));
        }
    }
    @GetMapping("/gitlab/token")
    public ResponseEntity<Map<String, Object>> getGitlabToken(
            @RegisteredOAuth2AuthorizedClient("gitlab") OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User
    ) {
        if (!isGitlabUser()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authenticated with GitLab"));
        }

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        Map<String, Object> tokenInfo = new HashMap<>();
        tokenInfo.put("access_token", accessToken.getTokenValue());
        tokenInfo.put("token_type", accessToken.getTokenType().getValue());
        tokenInfo.put("expires_at", accessToken.getExpiresAt());
        tokenInfo.put("scopes", accessToken.getScopes());
        tokenInfo.put("user", Map.of(
                "id", oauth2User.getAttribute("sub"),
                "username", oauth2User.getAttribute("preferred_username"),
                "name", oauth2User.getAttribute("name"),
                "email", oauth2User.getAttribute("email")
        ));

        return ResponseEntity.ok(tokenInfo);
    }
    private boolean isGitlabUser() {
        return SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken auth
                && "gitlab".equals(auth.getAuthorizedClientRegistrationId());
    }
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getGitLabProfile(
            @AuthenticationPrincipal OAuth2User oauth2User
    ) {
        if (oauth2User == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
        }

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", oauth2User.getAttribute("preferred_username"));
        profile.put("name", oauth2User.getAttribute("name"));
        profile.put("email", oauth2User.getAttribute("email"));
        profile.put("avatar", oauth2User.getAttribute("picture"));
        profile.put("website", oauth2User.getAttribute("website"));
        profile.put("groups", oauth2User.getAttribute("groups"));

        return ResponseEntity.ok(profile);
    }

    private boolean isGitLabUser() {
        return SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken auth
                && "gitlab".equals(auth.getAuthorizedClientRegistrationId());
    }

    private HttpHeaders createGitLabHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return headers;
    }
    // Get GitHub repository details


    // Get GitLab repository details
    @GetMapping("/gitlab/repos/{projectId}")
    public ResponseEntity<Object> getGitlabRepoDetails(
            @PathVariable String projectId,
            @RegisteredOAuth2AuthorizedClient("gitlab") OAuth2AuthorizedClient authorizedClient
    ) {
        try {
            HttpHeaders headers = createGitLabHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // Get project details
            String projectUrl = String.format("https://gitlab.com/api/v4/projects/%s", projectId);
            ResponseEntity<Map> projectResponse = restTemplate.exchange(
                    projectUrl,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            // Get repository tree
            String treeUrl = projectUrl + "/repository/tree?recursive=true";
            ResponseEntity<List> treeResponse = restTemplate.exchange(
                    treeUrl,
                    HttpMethod.GET,
                    entity,
                    List.class
            );

            Map<String, Object> response = new HashMap<>();
            response.put("project", projectResponse.getBody());
            response.put("tree", treeResponse.getBody());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error fetching GitLab repository details: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }
    @GetMapping("/gitlab/repos/{projectId}/files/**")
    public ResponseEntity<Object> getGitlabFileContent(
            @PathVariable String projectId,
            HttpServletRequest request,
            @RegisteredOAuth2AuthorizedClient("gitlab") OAuth2AuthorizedClient authorizedClient
    ) {
        try {
            String filePath = request.getRequestURI()
                    .split(String.format("/gitlab/repos/%s/files/", projectId))[1];

            HttpHeaders headers = createGitLabHeaders(authorizedClient.getAccessToken().getTokenValue());
            HttpEntity<String> entity = new HttpEntity<>(headers);

            String fileUrl = String.format(
                    "https://gitlab.com/api/v4/projects/%s/repository/files/%s/raw",
                    projectId,
                    UriUtils.encodePath(filePath, "UTF-8")
            );

            ResponseEntity<String> response = restTemplate.exchange(
                    fileUrl,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            return ResponseEntity.ok(Map.of("content", response.getBody()));
        } catch (Exception e) {
            log.error("Error fetching GitLab file content: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }
    // Endpoint to refresh tokens
    @PostMapping("/{provider}/refresh")
    public ResponseEntity<?> refreshToken(
            @PathVariable String provider,
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient
    ) {
        try {
            OAuth2AuthorizedClient refreshedClient = clientService.loadAuthorizedClient(
                    provider,
                    authorizedClient.getPrincipalName()
            );

            if (refreshedClient != null && refreshedClient.getAccessToken() != null) {
                Map<String, Object> response = new HashMap<>();
                response.put("access_token", refreshedClient.getAccessToken().getTokenValue());
                response.put("token_type", refreshedClient.getAccessToken().getTokenType().getValue());
                response.put("expires_at", refreshedClient.getAccessToken().getExpiresAt());

                return ResponseEntity.ok(response);
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Could not refresh token"));

        } catch (Exception e) {
            log.error("Error refreshing token for provider {}: {}", provider, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to refresh token"));
        }
    }

}
