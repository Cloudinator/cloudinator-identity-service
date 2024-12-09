package istad.co.identity.features.auth.dto;

public record ChangeForgotPasswordRequest(

        String username,
        String token,
        String password,
        String confirmPassword
) {
}