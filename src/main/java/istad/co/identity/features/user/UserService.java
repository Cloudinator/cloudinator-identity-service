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

/**
 * Service interface for managing user operations in the ISTAD Identity System.
 * Handles user creation, authentication, and profile management.
 *
 * @author Muy Leanging
 * @version 1.0
 * @since 2023
 */
public interface UserService {

    /**
     * Creates a new user in the system.
     *
     * @param userCreateRequest the user creation request containing user details
     */
    void createNewUser(UserCreateRequest userCreateRequest);

    /**
     * Finds a user by their email address.
     *
     * @param email the email address to search for
     * @return the user response if found
     */
    UserResponse findByEmail(String email);

    /**
     * Checks if the user is not authenticated.
     *
     * @param authentication the authentication object to check
     */
    void isNotAuthenticated(Authentication authentication);

    /**
     * Resets a user's password.
     *
     * @param username the username of the user
     * @return the password reset response containing the new password
     */
    UserPasswordResetResponse resetPassword(String username);

    /**
     * Enables a user account.
     *
     * @param username the username of the account to enable
     */
    void enable(String username);

    /**
     * Disables a user account.
     *
     * @param username the username of the account to disable
     */
    void disable(String username);

    /**
     * Retrieves a paginated list of users.
     *
     * @param pageNumber the page number to retrieve
     * @param pageSize the number of items per page
     * @return a page of user responses
     */
    Page<UserResponse> findList(int pageNumber, int pageSize);

    /**
     * Finds a user by their username.
     *
     * @param username the username to search for
     * @return the user response if found
     */
    UserResponse findByUsername(String username);

    /**
     * Validates that two passwords match.
     *
     * @param password the password to check
     * @param confirmPassword the confirmation password
     */
    void checkForPasswords(String password, String confirmPassword);

    /**
     * Validates terms and conditions acceptance.
     *
     * @param value the acceptance value to check
     */
    void checkTermsAndConditions(String value);

    /**
     * Checks if a username already exists.
     *
     * @param username the username to check
     * @return true if username exists, false otherwise
     */
    boolean existsByUsername(String username);

    /**
     * Checks if an email already exists.
     *
     * @param email the email to check
     * @return true if email exists, false otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Validates password confirmation.
     *
     * @param password the password to check
     * @param confirmPassword the confirmation password
     */
    void checkConfirmPasswords(String password, String confirmPassword);

    /**
     * Verifies a user's email address.
     *
     * @param user the user to verify
     */
    @Transactional
    void verifyEmail(User user);

    /**
     * Validates the old password during password change.
     *
     * @param username the username of the user
     * @param oldPassword the old password to validate
     */
    void checkForOldPassword(String username, String oldPassword);

    /**
     * Creates a new user from GitLab OAuth2 authentication.
     *
     * @param oidcUser the OAuth2 user information from GitLab
     * @return the created user response
     */
    @Transactional
    UserResponse createGitLabUser(OAuth2User oidcUser);

    /**
     * Creates a new user from Google OAuth2 authentication.
     *
     * @param oauth2User the OAuth2 user information from Google
     * @return the created user response
     */
    @Transactional
    UserResponse createGoogleUser(OAuth2User oauth2User);

    /**
     * Creates a new user from GitHub OAuth2 authentication.
     *
     * @param oidcUser the OAuth2 user information from GitHub
     * @return the created user response
     */
    UserResponse createGithubUser(OAuth2User oidcUser);

    /**
     * Retrieves the currently authenticated user.
     *
     * @param authentication the current authentication object
     * @return the authenticated user response or null if not authenticated
     */
    UserResponse getAuthenticatedUser(Authentication authentication);
}