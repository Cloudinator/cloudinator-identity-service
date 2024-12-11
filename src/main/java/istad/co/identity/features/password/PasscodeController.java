package istad.co.identity.features.password;//package com.khotixs.identity_service.feature.forgotpasswordreset;

import istad.co.identity.base.BasedMessage;
import istad.co.identity.features.password.PasscodeService;
import istad.co.identity.features.password.dto.PasscodeVerifyRequest;
import istad.co.identity.features.password.dto.PasscodeVerifyResendRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/passcode-verification")
@RequiredArgsConstructor
public class PasscodeController {

    private final PasscodeService passcodeResetService;

    @PostMapping
    BasedMessage verify(@Valid @RequestBody PasscodeVerifyRequest passcodeVerifyRequest) {
        passcodeResetService.verify(passcodeVerifyRequest);
        return new BasedMessage("passcode has been verified successfully");
    }


    @PostMapping("/token")
    BasedMessage resendToken(@Valid @RequestBody PasscodeVerifyResendRequest passcodeVerifyResendRequest) {
        passcodeResetService.resend(passcodeVerifyResendRequest);
        return new BasedMessage("New confirmation link has been sent, check your emails");
    }
}