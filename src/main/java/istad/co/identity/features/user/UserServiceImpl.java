package istad.co.identity.features.user;

import istad.co.identity.domain.Authority;
import istad.co.identity.domain.PersonalToken;
import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
import istad.co.identity.features.user.dto.UserProfileResponse;
import istad.co.identity.features.user.dto.UserResponse;
import istad.co.identity.mapper.UserMapper;
import istad.co.identity.util.RandomTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.stream.Collectors;
/**
 * Implementation of UserService that provides user management functionality for the ISTAD Identity System.
 * This service handles user operations including:
 * - User creation and management
 * - Authentication and authorization
 * - OAuth2 integration (GitLab, Google, GitHub)
 * - Email verification
 * - Password management
 *
 * @author Muy Leanging
 * @version 1.0
 * @since 2024
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final AuthorityRepository authorityRepository;
    private final UserAuthorityRepository userAuthorityRepository;
    private final EmailVerificationTokenService emailVerificationTokenService;

    public final GitLabServiceFein gitLabServiceFein;
    private final PersonalRepository personalRepository;
    // === User Creation and Setup Methods ===

    /**
     * Creates a new user in the system with the provided details.
     * This method handles:
     * 1. Input validation
     * 2. User creation
     * 3. Authority assignment
     * 4. Email verification setup
     *
     * @param userCreateRequest DTO containing user creation details
     * @throws ResponseStatusException if validation fails or user creation encounters an error
     */
    @Override
    @Transactional
    public void createNewUser(UserCreateRequest userCreateRequest) {

        log.info("Creating new user with username: {}", userCreateRequest.username());

        // Validate unique constraints
        validateNewUser(userCreateRequest);

        String password = "Qwerty@2025Git";



        try {
            // Create user
            User user = userMapper.fromUserCreationRequest(userCreateRequest);
            setupNewUser(user, userCreateRequest);

            // Save user
            userRepository.save(user);

            User user1 = userRepository.findByUsername(userCreateRequest.username()).get();

            log.info("User testing: {}", user1.getUsername());

            //gitLabServiceFein.createUser(user1.getUsername() , user1.getEmail(), password);

            // Add authorities
            addUserAuthorities(user, userCreateRequest);

            // Create GitLab user if needed
//            createGitLabUser(user, userCreateRequest);

            // Generate and send verification email
            emailVerificationTokenService.generate(user);


            log.info("Successfully created new user: {}", user.getUsername());
        } catch (Exception e) {
            log.error("Error creating new user: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to create user: " + e.getMessage());
        }
    }

    private void validateNewUser(UserCreateRequest userCreateRequest) {
        // Check if username exists
        if (userRepository.existsByUsername(userCreateRequest.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }

        // Check if email exists
        if (userRepository.existsByEmail(userCreateRequest.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }

        // Validate password match
        if (!userCreateRequest.password().equals(userCreateRequest.confirmedPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Passwords do not match");
        }

        // Validate terms acceptance
        if (!"true".equalsIgnoreCase(userCreateRequest.acceptTerms())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "You must accept the terms and conditions");
        }
    }
    /**
     * Sets up initial user properties including:
     * - UUID generation
     * - Password encryption
     * - Default profile image
     * - Account status flags
     *
     * @param user the user entity to setup
     * @param userCreateRequest the original creation request
     */
    private void setupNewUser(User user, UserCreateRequest userCreateRequest) {
        user.setUuid(UUID.randomUUID().toString());
        user.setPassword(passwordEncoder.encode(userCreateRequest.password()));
        user.setProfileImage("default.png");
        user.setEmailVerified(false);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        user.setIsEnabled(true);
        user.setUserAuthorities(new HashSet<>());
    }
    // === OAuth2 Integration Methods ===

    /**
     * Adds only the default USER authority to a user.
     * Used primarily for OAuth2 user creation where custom authorities
     * are not specified.
     *
     * @param user the user to add the default authority to
     */
    private void addUserAuthorities(User user, UserCreateRequest userCreateRequest) {
        // Add default USER authority
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());
        user.getUserAuthorities().add(defaultUserAuthority);

        // Add custom authorities if specified
        if (userCreateRequest.authorities() != null && !userCreateRequest.authorities().isEmpty()) {
            Set<UserAuthority> customAuthorities = userCreateRequest.authorities().stream()
                    .map(name -> {
                        Authority authority = authorityRepository.findByName(name)
                                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                                        "Authority not found: " + name));
                        UserAuthority userAuthority = new UserAuthority();
                        userAuthority.setUser(user);
                        userAuthority.setAuthority(authority);
                        return userAuthority;
                    })
                    .collect(Collectors.toSet());
            user.getUserAuthorities().addAll(customAuthorities);
        }

        userAuthorityRepository.saveAll(user.getUserAuthorities());
    }
    private void addDefaultUserAuthority(User user) {
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());
    }
    private void addCustomAuthorities(User user, Set<String> authorityNames) {
        if (authorityNames == null || authorityNames.isEmpty()) {
            return;
        }

        Set<UserAuthority> customAuthorities = authorityNames.stream()
                .map(name -> {
                    Authority authority = authorityRepository
                            .findByName(name)
                            .orElseThrow(() -> new ResponseStatusException(
                                    HttpStatus.NOT_FOUND,
                                    "Authority has not been found"
                            ));
                    UserAuthority userAuthority = new UserAuthority();
                    userAuthority.setUser(user);
                    userAuthority.setAuthority(authority);
                    return userAuthority;
                })
                .collect(Collectors.toSet());

        user.getUserAuthorities().addAll(customAuthorities);
        userAuthorityRepository.saveAll(user.getUserAuthorities());
    }


    @Override
    public UserResponse findByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(userMapper::toUserResponse)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "User not found with email: " + email
                ));
    }

    @Override
    public void isNotAuthenticated(Authentication authentication) {

        if(authentication==null){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"user is not authenticated");
        }
    }

    @Override
    public UserPasswordResetResponse resetPassword(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        String newPassword = RandomTokenGenerator.generate(8);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        return new UserPasswordResetResponse(newPassword);
    }

    @Override
    public void enable(String username) {

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        user.setIsEnabled(true);
        userRepository.save(user);

    }

    @Override
    public void disable(String username) {

        log.info("Disabling user with username: {}", username);

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        user.setIsEnabled(false);
        userRepository.save(user);

    }

    @Override
    public void testMethod(String username) {

        log.info("Username: {}", username);

    }

    @Override
    public Page<UserResponse> findList(int pageNumber, int pageSize) {

        log.info("List<UserResponse> findList(int pageNumber={}, int pageSize={})", pageNumber, pageSize);

        Sort sortByCreatedDate = Sort.by(Sort.Direction.DESC, "createdDate");
        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize, sortByCreatedDate);

        // retrieve all users from db
        Page<User> users = userRepository.findAll(pageRequest);

        // map from user entities to user response list and return
        return users.map(userMapper::toUserResponse);

    }

    @Override
    public UserResponse findByUsername(String username) {

        log.info("Username: {}", username);

        // retrieve user by username from db
        User user = userRepository.findByUsernameAndIsEnabledTrue(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        return userMapper.toUserResponse(user);

    }

    @Override
    public void checkForPasswords(String password, String confirmPassword) {

        if (!password.equals(confirmPassword)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password doesn't match!");
        }

    }

    @Override
    public void checkTermsAndConditions(String value) {

        if (!value.equals("true") && !value.equals("false")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Illegal value!");
        } else if (value.equals("false")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Terms and Conditions must be accepted in order to register!");
        }

    }

    @Override
    public boolean existsByUsername(String username) {

        if (userRepository.existsByUsername(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists!");
        }
        return false;
    }

    @Override
    public boolean existsByEmail(String email) {
        // check if email already exists (validation)
        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists!");
        }
        return false;
    }

    @Override
    public void checkConfirmPasswords(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password doesn't match!");
        }
    }

    @Transactional
    @Override
    public void verifyEmail(User user) {
        user.setEmailVerified(true);

        String password = "Qwerty@2025Git";

        gitLabServiceFein.createUser(user.getUsername() , user.getEmail(), password);

        userRepository.save(user);
    }

    @Override
    public void checkForOldPassword(String username, String oldPassword) {

        User user = userRepository.findByUsernameAndIsEnabledTrue(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Wrong old password");
        }

    }

    // === OAuth2 Integration Methods ===

    /**
     * Creates a new user from GitLab OAuth2 authentication.
     * Generates a unique username and email based on GitLab information.
     *
     * @param oauth2User the OAuth2 user information from GitLab
     * @return UserResponse containing the created user's information
     */
    @Transactional
    @Override
    public UserResponse createGitLabUser(OAuth2User oauth2User) {
        String gitlabId = oauth2User.getAttribute("sub");
        String preferredUsername = oauth2User.getAttribute("preferred_username");
        String name = oauth2User.getAttribute("name");

        String username = preferredUsername + gitlabId + "gitcloudinator";
        String email = preferredUsername + gitlabId + "@git.cloudinator";

        log.info("Creating GitLab user with ID: {}", gitlabId);
        log.info("Using username: {} and email: {}", username, email);

        String password = "Qwerty@2025Git";

        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .username(gitlabId)
                .email(email)
                .profileImage(oauth2User.getAttribute("picture"))
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);

        gitLabServiceFein.createUser(gitlabId, email, password);
//        try {
//
//        } catch (Exception e) {
//            log.error("Failed to create GitLab service user: {}", e.getMessage());
//        }

        addDefaultUserAuthority(user);

        log.info("Successfully created GitLab user with ID: {}, email: {}", gitlabId, email);

        return userMapper.toUserResponse(user);
    }
    /**
     * Creates a new user from Google OAuth2 authentication.
     * Uses Google email as username for consistency.
     *
     * @param oauth2User the OAuth2 user information from Google
     * @return UserResponse containing the created user's information
     */
    @Transactional
    @Override
    public UserResponse createGoogleUser(OAuth2User oauth2User) {
        String googleId = oauth2User.getAttribute("sub");
        String email = oauth2User.getAttribute("email");
        String password = "Qwerty@2025Git";
        String trimmedIdentifier = googleId + email;
        String username = trimmedIdentifier.split("@")[0];

        log.info("Creating username user with ID: {}", username);
        log.info("Creating email user with ID: {}", email);

        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .username(username)
                .email(oauth2User.getAttribute("email"))
                .profileImage(oauth2User.getAttribute("picture"))
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);

        gitLabServiceFein.createUser(username, email, password);
//        try {
//            gitLabServiceFein.createUser(username, email, password);
//        } catch (Exception e) {
//            log.error("Failed to create GitLab service user: {}", e.getMessage());
//        }

        addDefaultUserAuthority(user);

        log.info("Created Google user with username: {}", googleId);

        return userMapper.toUserResponse(user);
    }
    /**
     * Creates a new user from GitHub OAuth2 authentication.
     * Generates a unique username using GitHub login and ID.
     *
     * @param oauth2User the OAuth2 user information from GitHub
     * @return UserResponse containing the created user's information
     */
    @Override
    @Transactional
    public UserResponse createGithubUser(OAuth2User oauth2User) {
        String githubId = oauth2User.getAttribute("id").toString();
        String githubLogin = oauth2User.getAttribute("login");
        Random random = new Random();
        int randomNumber = random.nextInt(1000);
        String username = githubLogin + githubId + "gitcloudinator";
        String email = githubLogin + randomNumber + "@git.cloudinator";

        String password = "Qwerty@2025Git";

        String finalUsername = githubLogin + "." + githubId;
        log.info("Creating Github user with ID: {}", oauth2User);
        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .username(githubId)
                .email(oauth2User.getAttribute("login") + "@github.com")
                .profileImage(oauth2User.getAttribute("avatar_url"))
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);
        try {
            gitLabServiceFein.createUser(githubId, email, password);
        } catch (Exception e) {
            log.error("Failed to create Github service user: {}", e.getMessage());
        }

        addDefaultUserAuthority(user);

        log.info("Creating Github user with ID: {}", oauth2User);
        log.info("Created GitHub user with username: {}", finalUsername);

        return userMapper.toUserResponse(user);
    }

    @Override
    public UserResponse getAuthenticatedUser(Authentication authentication) {

        if(authentication!=null){
            return findByUsername(authentication.getName());
        }
        return null;
    }

    @Override
    public int countUsers() {

        int count = userRepository.findAll().size();

        return count;
    }

    @Override
    public List<UserProfileResponse> getAllUserProfiles() {

        List<User> users = userRepository.findAll();

        return users.stream()
                .map(userMapper::toUserProfileResponse)
                .collect(Collectors.toList());
    }

    @Override
    public void deleteByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (Boolean.TRUE.equals(user.getIsEnabled())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cannot delete an enabled user");
        }

        PersonalToken personalToken = personalRepository.findByUser_Username(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Personal Token not found"));

        userRepository.delete(user);
        personalRepository.delete(personalToken);

//        try {
//            // Build the shell command
//            List<String> command = new ArrayList<>();
//            command.add("./delete_user.sh");
//            command.add(personalToken.getIdUser().toString());
//
//            // Configure the process builder
//            ProcessBuilder processBuilder = new ProcessBuilder(command);
//            processBuilder.redirectErrorStream(true);
//
//            // Start the process
//            Process process = processBuilder.start();
//
//            // Capture and log the script's output
//            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
//                String line;
//                System.out.println("Shell script output:");
//                while ((line = reader.readLine()) != null) {
//                    System.out.println(line);
//                }
//            }
//
//            // Wait for the process to complete and check the exit code
//            int exitCode = process.waitFor();
//            if (exitCode == 0) {
//                System.out.println("Shell script executed successfully.");
//            } else {
//                System.err.println("Shell script failed with exit code: " + exitCode);
//            }
//
//        } catch (Exception e) {
//            // Log any errors encountered during execution
//            System.err.println("An error occurred while executing the shell script:");
//            e.printStackTrace();
//        }
    }
}
