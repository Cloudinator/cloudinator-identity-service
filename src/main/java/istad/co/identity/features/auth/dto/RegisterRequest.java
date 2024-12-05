package istad.co.identity.features.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @NotEmpty(message = "Username is required")
        @Size(min = 5, message = "Username must be at least 5 characters long")
        @Size(max = 32, message = "Username can not be longer than 32 characters")
        String username,

        @NotEmpty(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 5 characters long")
        @Size(max = 32, message = "Password can not be longer than 32 characters")
        String password,


        @NotEmpty(message = "Password confirmation is required")
        @Size(min = 6, message = "Confirmation password must be at least 6 characters long")
        @Size(max = 32, message = "Confirmation password can not be longer than 32 characters")
        String confirmedPassword,

        @NotEmpty(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotEmpty(message = "Accepting Terms and Conditions is required")
        @Size(min = 4, max = 5, message = "Value must be either true or false")
        String acceptTerms
) {
}
