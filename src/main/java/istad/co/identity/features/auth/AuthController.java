package istad.co.identity.features.auth;

import istad.co.identity.features.auth.dto.*;
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

    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
    @GetMapping("/me")
    UserResponse findMe(Authentication authentication) {

        Jwt jwt = (Jwt) authentication.getPrincipal();
        System.out.println(jwt.getTokenValue());

        return authService.findMe(authentication);
    }

//    @PreAuthorize("hasAnyAuthority('SCOPE_USER', 'SCOPE_profile')")
//    @PutMapping("/me/change-password")
//    BasedMessage changePassword(Authentication authentication,
//                                @Valid @RequestBody ChangeForgotPasswordRequest changePasswordRequest) {
//        authService.changePassword(changePasswordRequest);
//        return new BasedMessage("Password has been changed");
//    }


}
