package istad.co.identity.features.password;//package com.khotixs.identity_service.feature.forgotpasswordreset;


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
import org.springframework.web.server.ResponseStatusException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasscodeServiceImpl implements PasscodeService {

    private final UserRepository userRepository;

    private final PasscodeRepository passcodeRepository;

    private final JavaMailSender javaMailSender;

    private final TemplateEngine templateEngine;

    @Override
    public void verify(PasscodeVerifyRequest passcodeVerifyRequest) {

        // check if user attempts to verify exists or not
        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(passcodeVerifyRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with corresponding verification token"));

        Passcode foundToken = passcodeRepository.findByToken(passcodeVerifyRequest.token())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Verification token is invalid"));

        if (this.isUsersToken(foundToken, foundUser)) {
            if (this.isExpired(foundToken)) {

                foundToken.setIsValidated(true);
                log.info("Token change: {}", foundToken);
                passcodeRepository.save(foundToken);

                return;
            }
        }

        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification token has expired");
    }

    @Override
    public void resend(PasscodeVerifyResendRequest passcodeVerifyResendRequest) {

/// check if user attempts to verify exists or not
        User foundUser = userRepository.findByUsernameAndIsEnabledTrue(passcodeVerifyResendRequest.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Unsuccessfully creation of confirmation link!"));

        passcodeRepository.deleteByUser(foundUser);

        generate(foundUser);
    }


    @Override
    public void generate(User user) {

        LocalDateTime expiration = LocalDateTime.now().plusMinutes(2);

        Passcode passcodeVerification = new Passcode();

        passcodeVerification.setToken(RandomUtil.generate6Digits());
        passcodeVerification.setExpiryDateTime(expiration);
        passcodeVerification.setUser(user);

        passcodeRepository.save(passcodeVerification);

        // after saved information into database, mail will be started to send
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);

        // Prepare Thymeleaf context
        Context context = new Context();
        context.setVariable("verificationCode", passcodeVerification.getToken());

        log.info("Verification Code: {}", passcodeVerification.getToken());


        // Render the email content using the Thymeleaf template
        String emailContent = templateEngine.process("email/verification-code.html", context);
        log.info("Rendered email content: {}", emailContent);
        log.info("Context Variables: {}", context);

        try {
            mimeMessageHelper.setTo(user.getEmail());
            mimeMessageHelper.setSubject("Account Verification");
            mimeMessageHelper.setText(emailContent, true);
            javaMailSender.send(mimeMessage);
        } catch (MessagingException e) {
            log.error(e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong");
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
