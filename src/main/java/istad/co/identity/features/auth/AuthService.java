package istad.co.identity.features.auth;

import istad.co.identity.features.auth.dto.*;
import istad.co.identity.features.user.dto.UserResponse;
import org.springframework.security.core.Authentication;

import java.util.Optional;

public interface AuthService {

    UserResponse register(RegisterRequest registerRequest);

    UserResponse findMe(Authentication authentication);

//    void changePassword(ChangeForgotPasswordRequest changePasswordRequest);

    void isNotAuthenticated(Authentication authentication);

    void forgotPassword(ForgotPasswordRequest forgotPasswordRequest);

    UserResponse login(LoginRequest loginRequest);

    Optional<UserResponse> findByEmail(String email);

    Optional<UserResponse> findByUsername(String username);

    void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest);

    void changeForgotPassword(ChangeForgotPasswordRequest changeForgotPasswordRequest);
}
