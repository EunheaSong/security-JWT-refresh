package com.example.securityjwt.security.provider;

import com.example.securityjwt.security.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.annotation.Resource;

@RequiredArgsConstructor
public class FormLoginAuthProvider implements AuthenticationProvider {
    // 로그인 요청이 들어오면, FormLoginFilter를 거치고, 여기로온다.
    @Resource(name="userDetailsServiceImpl")
    private UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder passwordEncoder;

//    public FormLoginAuthProvider(BCryptPasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        // FormLoginFilter 에서 생성된 토큰으로부터 아이디와 비밀번호를 추출한다.
        String username = token.getName();
        String password = (String) token.getCredentials();
        //추출한 정보를 가지고 UserDetailsService를 통해, DB에 해당 정보와 일치하는 사용자가 있는지 조회한다.

        // 추출한 아이디와 같은 사용자가 있으면, 패스워드 확인으로 넘어가고, 없다면 UsernameNotFoundException 예외가 발생.
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);
        // 추출한 패스워드가 , DB에서 찾은 사용자의 패스워드와 일치하는지 검증!
        // 패스워드는 복호화가 되어있기 때문에, 우리는 어떤 형식인지 알 수 없으므로 passwordEncoder를 이용해서 검증해준다.
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException(userDetails.getUsername() + "Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
