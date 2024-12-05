package istad.co.identity.mapper;

import istad.co.identity.domain.User;
import istad.co.identity.features.auth.dto.GithubUser;
import istad.co.identity.features.auth.dto.RegisterRequest;
import istad.co.identity.features.user.dto.UserCreateRequest;
import istad.co.identity.features.user.dto.UserResponse;
import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserResponse toUserResponse(User user);

    List<UserResponse> toUserResponseList(List<User> users);

    User fromUserCreationRequest(UserCreateRequest userCreateRequest);

//    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
//    void mapUserBasicInfoRequestToUser(UserBasicInfoRequest userBasicInfoRequest, @MappingTarget User user);

    UserCreateRequest mapRegisterRequestToUserCreationRequest(RegisterRequest registerRequest);

    UserCreateRequest mapGithubUserToUserCreationRequest(GithubUser githubUser);

}
