package istad.co.identity.features.user.dto;

import lombok.Builder;

@Builder
public record UserPasswordResetResponse(
        String password
) {
}
