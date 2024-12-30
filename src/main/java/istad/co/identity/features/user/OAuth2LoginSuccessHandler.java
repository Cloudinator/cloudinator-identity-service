//package istad.co.identity.features.user;
//
//import istad.co.identity.features.user.UserService;
//import istad.co.identity.features.user.dto.UserResponse;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//
//@Component
//@RequiredArgsConstructor
//@Slf4j
//public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
//    private final UserService userService;
//    private final UserRepository userRepository;
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) throws IOException, ServletException {
//        if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
//            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
//            log.info("Provider: {}", registrationId);
//            Object principal = oauth2Token.getPrincipal();
//
//            try {
//                switch (registrationId) {
//                    case "gitlab" -> {
//                        if (principal instanceof OAuth2User oauth2User) {
//                            String gitlabId = oauth2User.getAttribute("sub");
//                            // Check if user exists first
//                            if (!userRepository.existsByUsername(gitlabId)) {
//                                userService.createGitLabUser(oauth2User);
//                            }
//                        }
//                    }
//                    case "google" -> {
//                        if (principal instanceof OAuth2User oauth2User) {
//                            String email = oauth2User.getAttribute("email");
//                            // Check if user exists first
//                            if (!userRepository.existsByEmail(email)) {
//                                userService.createGoogleUser(oauth2User);
//                            }
//                        }
//                    }
//                    case "github" -> {
//                        if (principal instanceof OAuth2User oauth2User) {
//                            String githubId = oauth2User.getAttribute("id").toString();
//                            // Check if user exists first
//                            if (!userRepository.existsByUsername(githubId)) {
//                                userService.createGithubUser(oauth2User);
//                            }
//                        }
//                    }
//                }
//            } catch (Exception e) {
//                log.error("Error during OAuth2 login: {}", e.getMessage());
//            }
//        }
//
//        super.onAuthenticationSuccess(request, response, authentication);
//    }
//
//    private void handleGitLabLogin(DefaultOidcUser oidcUser) {
//        String email = oidcUser.getEmail();
//        String gitlabId = oidcUser.getSubject();
//        log.info("GitLab Login - Email: {}, ID: {}", email, gitlabId);
//
//        if (!userService.existsByEmail(email)) {
//            userService.createGitLabUser(oidcUser);
//            log.info("Created new GitLab user with ID: {}", gitlabId);
//        }
//    }
//
//    private void handleGoogleLogin(DefaultOidcUser oidcUser) {
//        String email = oidcUser.getEmail();
//        log.info("Google Login - Email: {}", email);
//
//        try {
//            if (!userService.existsByEmail(email)) {
//                UserResponse response = userService.createGoogleUser(oidcUser);
//                log.info("Created new Google user with email: {} and userUuid: {}",
//                        email, response.username());
//            } else {
//                log.info("Google user already exists with email: {}", email);
//            }
//        } catch (Exception e) {
//            log.error("Error creating Google user: {}", e.getMessage(), e);
//            throw e;
//        }
//    }
//
//    private void handleGithubLogin(OAuth2User oauth2User) {
//        String username = oauth2User.getAttribute("login");
//        log.info("GitHub Login - Username: {}", username);
//
//        if (!userService.existsByUsername(username)) {
//            userService.createGithubUser(oauth2User);
//            log.info("Created new GitHub user with username: {}", username);
//        }
//    }
//}
package istad.co.identity.features.user;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final UserService userService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
            log.info("Provider: {}", registrationId);
            Object principal = oauth2Token.getPrincipal();

            try {
                switch (registrationId) {
                                        case "gitlab" -> {
                        if (principal instanceof OAuth2User oauth2User) {
                            String gitlabId = oauth2User.getAttribute("sub");
                            // Check if user exists first
                            if (!userRepository.existsByUsername(gitlabId)) {
                                userService.createGitLabUser(oauth2User);
                            }
                        }
                    }
                    case "google" -> handleGoogleLogin((OAuth2User) principal, request);
                    case "github" -> {
                        if (principal instanceof OAuth2User oauth2User) {
                            String githubId = oauth2User.getAttribute("id").toString();
                            // Check if user exists first
                            if (!userRepository.existsByUsername(githubId)) {
                                userService.createGithubUser(oauth2User);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Error during OAuth2 login: {}", e.getMessage());
                request.getSession().setAttribute("oauthError", "An error occurred during login. Please try again.");
            }
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void handleGitLabLogin(DefaultOidcUser oidcUser) {
        String email = oidcUser.getEmail();
        String gitlabId = oidcUser.getSubject();
        log.info("GitLab Login - Email: {}, ID: {}", email, gitlabId);

        if (!userService.existsByEmail(email)) {
            userService.createGitLabUser(oidcUser);
            log.info("Created new GitLab user with ID: {}", gitlabId);
        }
    }

    private void handleGoogleLogin(OAuth2User oauth2User, HttpServletRequest request) {
        String email = oauth2User.getAttribute("email");

        if (userRepository.existsByEmail(email)) {
            log.info("Google user already exists with email: {}", email);
            request.getSession().setAttribute("oauthError", "An account with this email already exists. Please log in or reset your password.");
        } else {
            userService.createGoogleUser(oauth2User);
            log.info("Created new Google user with email: {}", email);
            request.getSession().setAttribute("oauthMessage", "Account created successfully!");
        }
    }

        private void handleGithubLogin(OAuth2User oauth2User, HttpServletRequest request) {
        String username = oauth2User.getAttribute("login");
        log.info("GitHub Login - Username: {}", username);

        if (!userService.existsByUsername(username)) {
            userService.createGithubUser(oauth2User);
            log.info("Created new GitHub user with username: {}", username);
        }
    }
}

