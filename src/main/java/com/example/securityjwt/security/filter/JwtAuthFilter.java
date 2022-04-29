package com.example.securityjwt.security.filter;


import com.example.securityjwt.security.jwt.HeaderTokenExtractor;
import com.example.securityjwt.security.jwt.JwtPreProcessingToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthFilter extends AbstractAuthenticationProcessingFilter {

    private final HeaderTokenExtractor extractor;

    public JwtAuthFilter(
            RequestMatcher requiresAuthenticationRequestMatcher,
            HeaderTokenExtractor extractor
    ) {
        super(requiresAuthenticationRequestMatcher);

        this.extractor = extractor;
    }


    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException, IOException {

        // JWT 값을 담아주는 변수 TokenPayload
        //요청헤더에 있는 Authorization 값을 조회하여 tokenPayload 에 담아준다.
        //클라이언트와 " Authorization : 토큰값 " 이렇게 저장이 되서 넘기기로 약속해야함.
        String tokenPayload = request.getHeader("Authorization");
        System.out.println("JwtAuthFilter tokenPayload = " + tokenPayload);
        if (tokenPayload == null) {
//            response.sendRedirect("/user/loginView"); -> 토큰이 없다면 , 로그인페이지로 강제 이동.
//            return null;
            //토큰 값이 없다면, 예외 발생.
            throw new IllegalArgumentException("토큰이 없습니다.");
        }

        JwtPreProcessingToken jwtToken = new JwtPreProcessingToken(
                extractor.extract(tokenPayload, request));
        return super
                .getAuthenticationManager()
                .authenticate(jwtToken);
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException {
        /*
         *  SecurityContext 사용자 Token 저장소를 생성합니다.
         *  SecurityContext 에 사용자의 인증된 Token 값을 저장합니다.
         */

//        String jwtHeader = request.getHeader("Authorization");

        //SecurityContext에 현재 사용자가 들고온 토큰 값을 저장하고, 토큰 확인이 필요한 요청이 들어오면,
        //저장해두었던 토큰을 조회하여, 요청과 함께들어온 토큰값과 비교해준다.
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);

        // FilterChain chain 해당 필터가 실행 후 다른 필터도 실행할 수 있도록 연결실켜주는 메서드
        chain.doFilter(
                request,
                response
        );
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed
    ) throws IOException, ServletException {
        /*
         *	로그인을 한 상태에서 Token값을 주고받는 상황에서 잘못된 Token값이라면
         *	인증이 성공하지 못한 단계 이기 때문에 잘못된 Token값을 제거합니다.
         *	모든 인증받은 Context 값이 삭제 됩니다.
         */
        SecurityContextHolder.clearContext();

        super.unsuccessfulAuthentication(
                request,
                response,
                failed
        );
    }
}
