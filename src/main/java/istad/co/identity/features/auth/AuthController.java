package istad.co.identity.features.auth;

import istad.co.identity.base.BasedMessage;
import istad.co.identity.features.auth.dto.ChangePasswordRequest;
import istad.co.identity.features.auth.dto.LoginRequest;
import istad.co.identity.features.auth.dto.RegisterRequest;
import istad.co.identity.features.user.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authService.register(registerRequest));
    }

    @PostMapping("/login")
    ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @GetMapping("/me")
    UserResponse findMe(Authentication authentication) {

        Jwt jwt = (Jwt) authentication.getPrincipal();
        System.out.println(jwt.getTokenValue());

        return authService.findMe(authentication);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @PutMapping("/me/change-password")
    BasedMessage changePassword(Authentication authentication,
                                @Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
        authService.changePassword(authentication, changePasswordRequest);
        return new BasedMessage("Password has been changed");
    }


}
