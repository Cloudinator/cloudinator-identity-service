package istad.co.identity.features.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.util.List;

@Builder
public record UserCreateRequest(
        @NotEmpty(message = "Username is required")
        @Size(min = 5, message = "Username must be at least 5 characters long")
        @Size(max = 32, message = "Username can not be longer than 32 characters")
        String username,

        @NotEmpty(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 5 characters long")
        @Size(max = 32, message = "Password can not be longer than 32 characters")
        String password,

        @NotEmpty(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,

        @NotEmpty(message = "Authority is required at least one")
        List<@NotBlank(message = "Authority name is required") String> authorities
) {
}
