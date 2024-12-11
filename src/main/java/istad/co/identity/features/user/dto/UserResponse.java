package istad.co.identity.features.user.dto;

import istad.co.identity.domain.User;
import lombok.Builder;

@Builder
public record UserResponse(
        String username,
        String email,
        String profileImage
) {
}
