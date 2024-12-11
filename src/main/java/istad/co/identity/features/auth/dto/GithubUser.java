package istad.co.identity.features.auth.dto;

import lombok.Builder;

@Builder
public record GithubUser(String login, String email) {
}
