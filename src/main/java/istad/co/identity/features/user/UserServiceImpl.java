package istad.co.identity.features.user;

import istad.co.identity.domain.Authority;
import istad.co.identity.domain.User;
import istad.co.identity.domain.UserAuthority;
import istad.co.identity.features.administrator.AdministratorRepository;
import istad.co.identity.features.authority.AuthorityRepository;
import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserPasswordResetResponse;
import istad.co.identity.features.user.dto.UserResponse;
import istad.co.identity.mapper.UserMapper;
import istad.co.identity.security.repository.JpaRegisteredClientRepository;
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
    public void createNewUser(UserCreateRequest userCreateRequest) {


        this.existsByUsername(userCreateRequest.username());
        this.existsByEmail(userCreateRequest.email());

        User user = userMapper.fromUserCreationRequest(userCreateRequest);
        user.setUuid(UUID.randomUUID().toString());
        user.setPassword(passwordEncoder.encode(userCreateRequest.password()));
        user.setProfileImage("default.png");
        user.setEmailVerified(false);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        user.setIsEnabled(true);

        user = userRepository.save(user);

        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);
        checkConfirmPasswords(userCreateRequest.password(),userCreateRequest.confirmedPassword());
        checkTermsAndConditions(userCreateRequest.acceptTerms());

        if (userCreateRequest.authorities() != null) {
            final User finalUser = user;
            System.out.println(finalUser);
            Set<UserAuthority> customAuthorities = userCreateRequest
                    .authorities()
                    .stream()
                    .map(name -> {
                        Authority authority = authorityRepository
                                .findByName(name)
                                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Authority has not been found"));
                        UserAuthority userAuthority = new UserAuthority();
                        userAuthority.setUser(finalUser);
                        userAuthority.setAuthority(authority);
                        return userAuthority;
                    })
                    .collect(Collectors.toSet());
            user.getUserAuthorities().addAll(customAuthorities);
        }

        userAuthorityRepository.saveAll(user.getUserAuthorities());
        gitLabServiceFein.createUser(user.getUsername() , user.getEmail(), user.getPassword());

        emailVerificationTokenService.generate(user);
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
    public void existsByUsername(String username) {

        if (userRepository.existsByUsername(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists!");
        }
    }

    @Override
    public void existsByEmail(String email) {
        // check if email already exists (validation)
        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists!");
        }
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


    // Add a new method specifically for Google users
    @Transactional
    public UserResponse createGoogleUser(DefaultOidcUser oidcUser) {
        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .username(generateUsername(oidcUser.getEmail()))
                .email(oidcUser.getEmail())
//                .fullName(oidcUser.getFullName())
                .profileImage(oidcUser.getPicture()) // Use Google profile picture
//                .coverImage("users/cover.png")
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);

        // Set up default authority - USER
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());

        return userMapper.toUserResponse(user);
    }
    @Override
    public UserResponse createGithubUser(OAuth2User oAuth2User) {
        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .username(oAuth2User.getAttribute("login"))
                .email(oAuth2User.getAttribute("login") + "@github.com")
//                .fullName(oAuth2User.getAttribute("name"))
                .profileImage(oAuth2User.getAttribute("avatar_url")) // Use Google profile picture
//                .coverImage("users/cover.png")
                .emailVerified(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .isEnabled(true)
                .build();

        user = userRepository.save(user);

        // Set up default authority - USER
        UserAuthority defaultUserAuthority = new UserAuthority();
        defaultUserAuthority.setUser(user);
        defaultUserAuthority.setAuthority(authorityRepository.AUTH_USER());

        user.setUserAuthorities(new HashSet<>());
        user.getUserAuthorities().add(defaultUserAuthority);

        userAuthorityRepository.saveAll(user.getUserAuthorities());

        return userMapper.toUserResponse(user);
    }
    // Helper method to generate username from email
    private String generateUsername(String email) {
        // Remove domain part and special characters
        return email.split("@")[0]
                .replaceAll("[^a-zA-Z0-9]", "")
                .toLowerCase();
    }
}
