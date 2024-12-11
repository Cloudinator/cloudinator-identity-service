package istad.co.identity.features.emailverification.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record EmailResendTokenRequest(
        @NotBlank(message = "Username is required")
        String username
) {
}
