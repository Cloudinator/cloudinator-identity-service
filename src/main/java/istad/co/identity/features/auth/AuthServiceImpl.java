package istad.co.identity.features.auth;

import istad.co.identity.domain.Passcode;
import istad.co.identity.domain.User;
import istad.co.identity.features.auth.dto.*;

import istad.co.identity.features.emailverification.EmailVerificationTokenService;
import istad.co.identity.features.password.PasscodeRepository;
import istad.co.identity.features.password.PasscodeService;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.features.user.UserService;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserResponse;
import istad.co.identity.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;



@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService{
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;
    private final PasscodeRepository passcodeRepository;
    private final PasscodeService passcodeService;
    private final UserService userService;
    private final UserMapper userMapper;
    private final JavaMailSender javaMailSender;
    private final EmailVerificationTokenService emailVerificationTokenService;

    @Override
    public UserResponse register(RegisterRequest registerRequest) {

        UserCreateRequest userCreateRequest = userMapper.mapRegisterRequestToUserCreationRequest(registerRequest);

        userService.checkForPasswords(registerRequest.password(), registerRequest.confirmedPassword());

        userService.checkTermsAndConditions(registerRequest.acceptTerms());

        userService.createNewUser(userCreateRequest);

        return userService.findByUsername(registerRequest.username());
    }

    @Override
    public UserResponse findMe(Authentication authentication) {

        isNotAuthenticated(authentication);

        return userService.findByUsername(authentication.getName());
    }
    @Override
    public void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest) {

        userService.isNotAuthenticated(authentication);

        userService.checkConfirmPasswords(changePasswordRequest.password(), changePasswordRequest.confirmedPassword());

        userService.checkForOldPassword(authentication.getName(), changePasswordRequest.oldPassword());

        // retrieve user by username from db
        User user = userRepository.findByUsernameAndIsEnabledTrue(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));

        user.setPassword(passwordEncoder.encode(changePasswordRequest.password()));
        userRepository.save(user);

    }

//    @Override
//    public void changePassword(Authentication authentication, ChangePasswordRequest changePasswordRequest) {
//
//        userService.isNotAuthenticated(authentication);
//
//        userService.checkConfirmPasswords(changePasswordRequest.password(), changePasswordRequest.confirmedPassword());
//
//        userService.checkForOldPassword(authentication.getName(), changePasswordRequest.oldPassword());
//
//        // retrieve user by username from db
//        User user = userRepository.findByUsernameAndIsEnabledTrue(authentication.getName())
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User has not been found"));
//
//        user.setPassword(passwordEncoder.encode(changePasswordRequest.password()));
//        userRepository.save(user);
//
//    }

    @Override
    public void isNotAuthenticated(Authentication authentication) {

        if (authentication == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token is required");
        }

    }
    @Override
    public UserResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(loginRequest.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        return userMapper.toUserResponse(user);
    }

    @Override
    @Transactional
    public void forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        User user = userRepository.findByUsernameAndIsEnabledTrue(forgotPasswordRequest.username())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "User not found or not enabled"
                ));

        // Clean up any existing passcodes
        passcodeRepository.deleteByUser(user);

        // Generate and send new passcode
        passcodeService.generate(user);
    }
    @Override
    @Transactional
    public void changeForgotPassword(ChangeForgotPasswordRequest request) {
        // Find user
        User user = userRepository.findByUsernameAndIsEnabledTrue(request.username())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "User not found or not enabled"
                ));

        // Find and validate token
        Passcode passcode = passcodeRepository.findByToken(request.token())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Invalid verification token"
                ));

        // Validate token belongs to user
        if (!passcode.getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Token does not belong to this user"
            );
        }

        // Safe null check for isValidated
        Boolean isValidated = passcode.getIsValidated();
        if (isValidated == null || !isValidated) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Token has not been validated. Please verify your token first"
            );
        }

        // Validate password match
        if (!request.password().equals(request.confirmPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Passwords do not match"
            );
        }

        // Check expiration
        if (!passcodeService.isExpired(passcode)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Token has expired"
            );
        }

        // Update password and cleanup
        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);
        passcodeRepository.deleteByUser(user);
    }
//    @Override
//    public void changeForgotPassword(ChangeForgotPasswordRequest changeForgotPasswordRequest) {
//
//        // check if user attempts to verify exists or not
//        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(changeForgotPasswordRequest.username())
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with corresponding verification token"));
//
//        Passcode foundToken = passcodeRepository.findByToken(changeForgotPasswordRequest.token())
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Verification token is invalid"));
//
//        userService.checkConfirmPasswords(changeForgotPasswordRequest.password(), changeForgotPasswordRequest.confirmPassword());
//
//        if (passcodeService.isUsersToken(foundToken, foundUser)) {
//            if (passcodeService.isExpired(foundToken)) {
//                if(foundToken.getIsValidated()){
//                    foundUser.setPassword(passwordEncoder.encode(changeForgotPasswordRequest.password()));
//                    userRepository.save(foundUser);
//                    passcodeRepository.deleteByUser(foundUser);
//                }else{
//                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"The token has not been validated yet.");
//                }
//            }else{
//                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"The token expired");
//            }
//        }else{
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid token");
//        }
//
//    }


}
