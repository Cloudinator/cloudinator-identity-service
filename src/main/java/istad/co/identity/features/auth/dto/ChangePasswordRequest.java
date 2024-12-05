package istad.co.identity.features.auth.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotEmpty(message = "Old password is required")
        @Size(min = 6, message = "Old password must be at least 5 characters long")
        @Size(max = 32, message = "Old password can not be longer than 32 characters")
        String oldPassword,

        @NotEmpty(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 5 characters long")
        @Size(max = 32, message = "Password can not be longer than 32 characters")
        String password,

        @NotEmpty(message = "Password confirmation is required")
        @Size(min = 6, message = "Confirmation password must be at least 6 characters long")
        @Size(max = 32, message = "Confirmation password can not be longer than 32 characters")
        String confirmedPassword
) {
}
