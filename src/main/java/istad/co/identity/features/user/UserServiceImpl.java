package istad.co.identity.features.user;

import istad.co.identity.domain.Authority;
import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
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

import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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

    @Override
    @Transactional
    public void createNewUser(UserCreateRequest userCreateRequest) {
        log.info("Creating new user with username: {}", userCreateRequest.username());

        // Validate unique constraints
        validateNewUser(userCreateRequest);

        try {
            // Create user
            User user = userMapper.fromUserCreationRequest(userCreateRequest);
            setupNewUser(user, userCreateRequest);

            // Save user
            user = userRepository.save(user);

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

    // Add method to map OAuth2 attributes if needed
    private UserResponse mapOAuth2UserToResponse(OAuth2User oauth2User) {
        User user = userRepository.findByEmail(oauth2User.getAttribute("email"))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "OAuth2 user not found"
                ));
        return userMapper.toUserResponse(user);
    }
    private String extractEmail(OAuth2User oAuth2User, OAuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> ((DefaultOidcUser) oAuth2User).getEmail();
            case GITHUB -> oAuth2User.getAttribute("login") + "@github.com";
        };
    }

    private String extractUsername(OAuth2User oAuth2User, OAuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> generateUsername(((DefaultOidcUser) oAuth2User).getEmail());
            case GITHUB -> oAuth2User.getAttribute("login");
        };
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

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        user.setIsEnabled(false);
        userRepository.save(user);

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

        gitLabServiceFein.createUser(user.getUsername() , user.getEmail(), user.getPassword());

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



    // Add a method to generate unique username
    private String generateUniqueUsername(String baseUsername, String provider) {
        String username = baseUsername + "." + provider.toLowerCase();

        // Check if username exists
        if (!userRepository.existsByUsername(username)) {
            return username;
        }

        // If exists, add number suffix until we find a unique one
        int counter = 1;
        String newUsername;
        do {
            newUsername = username + counter;
            counter++;
        } while (userRepository.existsByUsername(newUsername));

        return newUsername;
    }

//    @Transactional
//    @Override
//    public UserResponse createGitLabUser(OAuth2User oauth2User) {
//        String gitlabId = oauth2User.getAttribute("sub");
//        String email = oauth2User.getAttribute("email");
//        String name = oauth2User.getAttribute("name");
//        String preferredUsername = oauth2User.getAttribute("preferred_username");
//
//        log.info("Creating GitLab user with ID: {}", gitlabId);
//
//        User user = User.builder()
//                .uuid(UUID.randomUUID().toString())
//                .username(gitlabId)
//                .email(oauth2User.getAttribute("name") + "@gitlab.com")
//                .profileImage(oauth2User.getAttribute("picture"))
//                .emailVerified(true)
//                .accountNonExpired(true)
//                .accountNonLocked(true)
//                .credentialsNonExpired(true)
//                .isEnabled(true)
//                .build();
//
//        user = userRepository.save(user);
//        gitLabServiceFein.createUser(user.getUsername(), user.getEmail(), user.getPassword());
//
//        UserAuthority defaultUserAuthority = new UserAuthority();
//        defaultUserAuthority.setUser(user);
//        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());
//
//        user.setUserAuthorities(new HashSet<>());
//        user.getUserAuthorities().add(defaultUserAuthority);
//
//        userAuthorityRepository.saveAll(user.getUserAuthorities());
//
//        log.info("Successfully created GitLab user with ID: {}, email: {}", gitlabId, email);
//
//        return userMapper.toUserResponse(user);
//    }
@Transactional
@Override
public UserResponse createGitLabUser(OAuth2User oauth2User) {
    String gitlabId = oauth2User.getAttribute("sub");
    String preferredUsername = oauth2User.getAttribute("preferred_username");
    String name = oauth2User.getAttribute("name");
    Random random = new Random();
    int randomNumber = random.nextInt(1000); // Generates a random number between 0 and 999

    String username = preferredUsername + randomNumber + "gitcloudinator";
    String email = preferredUsername + randomNumber + "@git.cloudinator";

    log.info("Creating GitLab user with ID: {}", gitlabId);
    log.info("Using username: {} and email: {}", username, email);

    // Generate random password
    String password = "Qwerty@2025Git";

    User user = User.builder()
            .uuid(UUID.randomUUID().toString())
            .username(gitlabId)  // Use customized username
            .email(email)      // Use customized email
            .profileImage(oauth2User.getAttribute("picture"))
            .emailVerified(true)
            .accountNonExpired(true)
            .accountNonLocked(true)
            .credentialsNonExpired(true)
            .isEnabled(true)
            .build();

    user = userRepository.save(user);

    try {
        gitLabServiceFein.createUser(username, email, password);
    } catch (Exception e) {
        log.error("Failed to create GitLab service user: {}", e.getMessage());
    }

    // Add authorities
    UserAuthority defaultUserAuthority = new UserAuthority();
    defaultUserAuthority.setUser(user);
    defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

    user.setUserAuthorities(new HashSet<>());
    user.getUserAuthorities().add(defaultUserAuthority);

    userAuthorityRepository.saveAll(user.getUserAuthorities());

    log.info("Successfully created GitLab user with ID: {}, email: {}", gitlabId, email);

    return userMapper.toUserResponse(user);
}
    @Override
    public UserResponse createGoogleUser(DefaultOidcUser oidcUser) {
        return null;
    }

    @Transactional
    @Override
    public UserResponse createGoogleUser(OAuth2User oauth2User) {
        String googleId = oauth2User.getAttribute("sub");
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String password = "Qwerty@2025Git";
        String trimmedIdentifier = googleId+email;
        String username = trimmedIdentifier.split("@")[0];

        log.info("Creating username user with ID: {}", username);
        log.info("Creating email user with ID: {}", email);

        User user = User. builder()
                .uuid(UUID.randomUUID().toString())
                .username(email)  // Using Google ID as username like GitHub and GitLab
                .email(oauth2User.getAttribute("email"))
                .profileImage(oauth2User.getAttribute("picture"))
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);
        try {
            gitLabServiceFein.createUser(username, email, password);
        } catch (Exception e) {
            log.error("Failed to create GitLab service user: {}", e.getMessage());
        }
        // Set up default authority
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());

        log.info("Created Google user with username: {}", googleId);

        return userMapper.toUserResponse(user);
    }

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
            gitLabServiceFein.createUser(username, email, password);
        } catch (Exception e) {
            log.error("Failed to create Github service user: {}", e.getMessage());
        }

        // Set up default authority - USER
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());
        log.info("Creating Github user with ID: {}", oauth2User);

        // You might want to log the creation for debugging
        log.info("Created GitHub user with username: {}", finalUsername);

        return userMapper.toUserResponse(user);
    }
    // Helper method to add default authority
    private void addDefaultAuthority(User user) {
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());
    }

    // Helper method to generate base username from email
    private String generateUsername(String email) {
        return email.split("@")[0]
                .replaceAll("[^a-zA-Z0-9]", "")
                .toLowerCase();
    }
    @Override
    public UserResponse getAuthenticatedUser(Authentication authentication) {

        if(authentication!=null){
            return findByUsername(authentication.getName());
        }
        return null;
    }
}
