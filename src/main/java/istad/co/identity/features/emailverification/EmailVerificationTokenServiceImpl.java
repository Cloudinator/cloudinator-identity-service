package istad.co.identity.features.emailverification;

import istad.co.identity.domain.User;
import istad.co.identity.domain.VerificationToken;
import istad.co.identity.features.emailverification.dto.EmailVerifyRequest;
import istad.co.identity.features.user.GitLabServiceFein;
import istad.co.identity.features.user.UserRepository;
import istad.co.identity.util.RandomUtil;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.time.LocalTime;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationTokenServiceImpl implements EmailVerificationTokenService {

    private final VerificationTokenRepository emailVerificationTokenRepository;
    private final UserRepository userRepository;
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine templateEngine;
    private final GitLabServiceFein gitLabServiceFein;

    @Override
    public void verify(EmailVerifyRequest emailVerifyRequest) {

        // check if user attempts to verify exists or not
        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(emailVerifyRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with corresponding verification token"));

        VerificationToken foundToken = emailVerificationTokenRepository.getByToken(emailVerifyRequest.token())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Verification token is invalid"));

        String password = "Qwerty@2025";

        if (this.isUsersToken(foundToken, foundUser)) {
            if (this.isExpired(foundToken)) {
                gitLabServiceFein.createUser(foundUser.getUsername(), foundUser.getEmail(), password);
                foundUser.setEmailVerified(true);
                userRepository.save(foundUser);
                emailVerificationTokenRepository.deleteByUser(foundUser);
                return;
            }
        }

        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification token has expired");
    }

    @Override
    public void resend(String username) {

        // check if user attempts to verify exists or not
        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Unsuccessfully creation of confirmation link!"));

        emailVerificationTokenRepository.deleteByUser(foundUser);
        generate(foundUser);
    }

    @Override
    public boolean isUsersToken(VerificationToken token, User user) {
        return Objects.equals(user.getId(), token.getUser().getId());
    }

    @Override
    public void generate(User user) {

        LocalTime expiration = LocalTime.now().plusMinutes(1);

        VerificationToken emailVerificationToken = new VerificationToken();

        emailVerificationToken.setToken(RandomUtil.generate6Digits());
        emailVerificationToken.setExpiration(expiration);
        emailVerificationToken.setUser(user);

        emailVerificationTokenRepository.save(emailVerificationToken);

        // after saved information into database, mail will be started to send
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);

        // Prepare Thymeleaf context
        Context context = new Context();
        context.setVariable("verificationCode", emailVerificationToken.getToken());

        log.info("Verification Code: {}", emailVerificationToken.getToken());


        // Render the email content using the Thymeleaf template
        String emailContent = templateEngine.process("email/verification-code.html", context);
        log.info("Rendered email content: {}", emailContent);
        log.info("Context Variables: {}",context);

        try {
            mimeMessageHelper.setTo(user.getEmail());
            mimeMessageHelper.setSubject("Account Verification");
            mimeMessageHelper.setText(emailContent,true);
            javaMailSender.send(mimeMessage);
        } catch (MessagingException e) {
            log.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong");
        }
    }

    @Override
    public boolean isExpired(VerificationToken token) {
        return !token.getExpiration().isBefore(LocalTime.now());
    }

}