package istad.co.identity.features.auth;

import istad.co.identity.features.auth.dto.ChangePasswordRequest;
import istad.co.identity.features.auth.dto.LoginRequest;
import istad.co.identity.features.auth.dto.RegisterRequest;
import istad.co.identity.features.user.dto.UserResponse;
import org.springframework.security.core.Authentication;

public interface AuthService {

    UserResponse register(RegisterRequest registerRequest);

    UserResponse findMe(Authentication authentication);

    void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest);

    void isNotAuthenticated(Authentication authentication);

    UserResponse login(LoginRequest loginRequest);

}
