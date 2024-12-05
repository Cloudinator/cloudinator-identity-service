package istad.co.identity.features.emailverification;

import istad.co.identity.base.BasedMessage;
import istad.co.identity.features.emailverification.dto.EmailResendTokenRequest;
import istad.co.identity.features.emailverification.dto.EmailVerifyRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/email-verification")
@RequiredArgsConstructor
public class EmailVerificationTokenController {

    private final EmailVerificationTokenService emailVerificationTokenService;

    @PostMapping
    BasedMessage verify(@Valid @RequestBody EmailVerifyRequest emailVerifyRequest) {
        emailVerificationTokenService.verify(emailVerifyRequest);
        return new BasedMessage("Email has been verified successfully");
    }


    @PostMapping("/token")
    BasedMessage resendToken(@Valid @RequestBody EmailResendTokenRequest emailResendTokenRequest) {
        emailVerificationTokenService.resend(emailResendTokenRequest.username());
        return new BasedMessage("New confirmation link has been sent, check your emails");
    }

}
