package istad.co.identity.features.user;


import istad.co.identity.domain.User;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
import istad.co.identity.features.user.dto.UserResponse;
import org.springframework.data.domain.Page;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.transaction.annotation.Transactional;

public interface UserService {

    void createNewUser(UserCreateRequest userCreateRequest);


    UserResponse createOAuth2User(String email, String name, String picture, String provider);

    UserResponse findByEmail(String email);

    void isNotAuthenticated(Authentication authentication);

    UserPasswordResetResponse resetPassword(String username);

    void enable(String username);

    void disable(String username);

    Page<UserResponse> findList(int pageNumber, int pageSize);

    UserResponse findByUsername(String username);

    void checkForPasswords(String password, String confirmPassword);

    void checkTermsAndConditions(String value);

    void existsByUsername(String username);

    void existsByEmail(String email);
    void checkConfirmPasswords(String password, String confirmPassword);


    @Transactional
    void verifyEmail(User user);

    void checkForOldPassword(String username, String oldPassword);
    UserResponse createGoogleUser(DefaultOidcUser oidcUser);

    UserResponse createGithubUser(OAuth2User oidcUser);
}
