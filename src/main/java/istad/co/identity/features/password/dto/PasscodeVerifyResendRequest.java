package istad.co.identity.features.password.dto;

import jakarta.validation.constraints.NotBlank;

public record PasscodeVerifyResendRequest(
        @NotBlank(message = "Username is required")
        String username
) {
}