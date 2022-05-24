package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    @Autowired
    private UserRepository userRepository;

    //구글로 부터 받은 userRequest 후처리 되는 함수
    // userRequest : 코드가 아닌 액세스 토큰 + 사용자 프로필 정보
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //registrationId로 어떤 OAuth로 로그인 했는지 확인 가능
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());

        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글 로그인 버튼 클릭 -> 구글 로그인 창 -> code를 리턴(OAuth-Client라이브러리) -> Access Token 요청
        //여기까지 userRequest
        //userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필 받아준다.
        System.out.println("getAttributes() = " + oAuth2User.getAttributes());

        //회원 가입을 강제로 진행해볼 예정
        String provider = userRequest.getClientRegistration().getClientId();//google
        String providerId = (String)oAuth2User.getAttribute("sub");//provider ID
        String username = provider + "_"+providerId; //google_1097428561829...(중복될 일이 없다)
        String password = bCryptPasswordEncoder.encode("겟인데어");//큰 의미가 없다.
        String email = (String) oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null){
            System.out.println("구글 로그인이 최초입니다");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("구글 로그인을 이미 한적이 있습니다. 당신은 자동 회원가입이 되어 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
