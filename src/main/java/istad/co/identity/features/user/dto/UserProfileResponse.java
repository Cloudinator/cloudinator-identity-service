package istad.co.identity.features.user.dto;

import java.util.Set;

public record UserProfileResponse(
        String username,
        String email,
        String profileImage
) {
}
