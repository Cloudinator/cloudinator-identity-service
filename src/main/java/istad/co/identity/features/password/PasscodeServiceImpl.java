package istad.co.identity.features.password;

import istad.co.identity.domain.Passcode;
import istad.co.identity.domain.User;
import istad.co.identity.features.password.dto.PasscodeVerifyRequest;
import istad.co.identity.features.password.dto.PasscodeVerifyResendRequest;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.util.RandomUtil;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasscodeServiceImpl implements PasscodeService {

    private final UserRepository userRepository;
    private final PasscodeRepository passcodeRepository;
    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;

    /**
     * Find user by username or email with enabled status
     * @param usernameOrEmail username or email to search
     * @return User object
     */
    private User findUserByUsernameOrEmail(String usernameOrEmail) {
        // First try username
        Optional<User> userByUsername = userRepository.findByUsernameAndIsEnabledTrue(usernameOrEmail);
        if (userByUsername.isPresent()) {
            return userByUsername.get();
        }

        // Then try email
        Optional<User> userByEmail = userRepository.findByEmail(usernameOrEmail);
        if (userByEmail.isPresent() && userByEmail.get().getIsEnabled()) {
            return userByEmail.get();
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                "User not found or not enabled");
    }

    @Override
    @Transactional
    public void verify(PasscodeVerifyRequest passcodeVerifyRequest) {
        // check if user attempts to verify exists or not
        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(passcodeVerifyRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "User not found with corresponding verification token"));

        Passcode foundToken = passcodeRepository.findByToken(passcodeVerifyRequest.token())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Verification token is invalid"));

        if (this.isUsersToken(foundToken, foundUser)) {
            if (this.isExpired(foundToken)) {
                // Explicitly set isValidated to true
                foundToken.setIsValidated(true);
                log.info("Token validated: {}", foundToken);
                passcodeRepository.save(foundToken);
                return;
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Verification token has expired");
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Token does not belong to this user");
    }

//    @Override
//    @Transactional
//    public void resend(PasscodeVerifyResendRequest passcodeVerifyResendRequest) {
//        User foundUser = findUserByUsernameOrEmail(passcodeVerifyResendRequest.usernameOrEmail());
//
//        // Clean up old tokens
//        passcodeRepository.deleteByUser(foundUser);
//
//        // Generate new token
//        generate(foundUser);
//
//        log.info("Resent verification code to user: {}", foundUser.getUsername());
//    }
@Override
@Transactional
public String resend(PasscodeVerifyResendRequest passcodeVerifyResendRequest) {
    User foundUser = findUserByUsernameOrEmail(passcodeVerifyResendRequest.usernameOrEmail());

    // Clean up old tokens
    passcodeRepository.deleteByUser(foundUser);

    // Generate new token
    generate(foundUser);

    log.info("Resent verification code to user: {}", foundUser.getUsername());

    // Return the username
    return foundUser.getUsername();
}
    @Override
    @Transactional
    public void generate(User user) {
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(2);

        Passcode passcodeVerification = new Passcode();
        passcodeVerification.setToken(RandomUtil.generate6Digits());
        passcodeVerification.setExpiryDateTime(expiration);
        passcodeVerification.setUser(user);
        passcodeVerification.setIsValidated(false);

        passcodeRepository.save(passcodeVerification);

        sendVerificationEmail(user, passcodeVerification.getToken());
    }

    private void sendVerificationEmail(User user, String token) {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);

            Context context = new Context();
            context.setVariable("verificationCode", token);
            context.setVariable("username", user.getUsername());

            log.info("Generated verification code for user: {}", user.getUsername());

            String emailContent = templateEngine.process("email/passcode.html", context);

            mimeMessageHelper.setTo(user.getEmail());
            mimeMessageHelper.setSubject("Password Reset Verification Code");
            mimeMessageHelper.setText(emailContent, true);

            javaMailSender.send(mimeMessage);
            log.info("Sent verification email to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send email: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to send verification email");
        }
    }

    @Override
    public boolean isUsersToken(Passcode token, User user) {
        return Objects.equals(user.getId(), token.getUser().getId());
    }

    @Override
    public boolean isExpired(Passcode token) {
        return !token.getExpiryDateTime().isBefore(LocalDateTime.now());
    }
}
