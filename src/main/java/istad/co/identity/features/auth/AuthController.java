package istad.co.identity.features.auth;

import istad.co.identity.features.auth.dto.*;
import istad.co.identity.features.user.UserService;
import istad.co.identity.features.user.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private  final UserService userService;
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authService.register(registerRequest));
    }
    @PostMapping("/forgot-password")
    public void forgotPassword(@RequestBody ForgotPasswordRequest forgotPasswordRequest){
        authService.forgotPassword(forgotPasswordRequest);
    }

    @PostMapping("/change-forgot-password")
    public void changeForgotPassword(@RequestBody ChangeForgotPasswordRequest changeForgotPasswordRequest){
        authService.changeForgotPassword(changeForgotPasswordRequest);
    }
    @PostMapping("/change-password")
    public void changePassword(Authentication authentication, @RequestBody ChangePasswordRequest changePasswordRequest){
        authService.changePassword(authentication,changePasswordRequest);
    }


    @PostMapping("/login")
    ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }
//    @PreAuthorize("hasAnyAuthority('ADMIN','USER')")
//
////    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
//    @GetMapping("/me")
//    UserResponse findMe(Authentication authentication) {
//
//        Jwt jwt = (Jwt) authentication.getPrincipal();
//        System.out.println(jwt.getTokenValue());
//
//        return authService.findMe(authentication);
//    }
@PreAuthorize("hasAnyAuthority('ADMIN', 'USER', 'OAUTH2_USER')")
@GetMapping("/me")
public UserResponse findMe(Authentication authentication) {
    logger.debug("Authentication type: {}", authentication.getClass().getName());

    try {
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return userService.findByEmail(jwt.getSubject());
        } else if (authentication instanceof OAuth2AuthenticationToken oauth2Auth) {
            OAuth2User oauth2User = oauth2Auth.getPrincipal();
            String email = oauth2User.getAttribute("email");

            // First try to find the user
            try {
                return userService.findByEmail(email);
            } catch (ResponseStatusException e) {
                if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                    // User doesn't exist yet, create them
                    if (oauth2Auth.getAuthorizedClientRegistrationId().equals("google")) {
                        return userService.createGoogleUser((DefaultOidcUser) oauth2User);
                    } else if (oauth2Auth.getAuthorizedClientRegistrationId().equals("github")) {
                        return userService.createGithubUser(oauth2User);
                    }
                }
                throw e;
            }
        }

        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Unsupported authentication type"
        );
    } catch (Exception e) {
        logger.error("Error in findMe:", e);
        throw e;
    }
}
//    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
//    @PutMapping("/me/change-password")
//    BasedMessage changePassword(Authentication authentication,
//                                @Valid @RequestBody ChangeForgotPasswordRequest changePasswordRequest) {
//        authService.changePassword(changePasswordRequest);
//        return new BasedMessage("Password has been changed");
//    }


}
