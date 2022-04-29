package com.example.securityjwt.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Optional;

import static com.example.securityjwt.security.jwt.JwtTokenUtils.*;

@Component
public class JwtDecoder {


    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public String decodeUsername(String token) {
        DecodedJWT decodedJWT = isValidToken(token) //아래에 있는 isValidToken 실행해서 알고리즘 검증 시작.
                .orElseThrow(() -> new IllegalArgumentException("유효한 토큰이 아닙니다."));

        //알고리즘 검증이 완료가 되면, (통과가 되면) 유효기간 검증을 해준다.
        Date expiredDate = decodedJWT
                .getClaim(CLAIM_EXPIRED_DATE)
                .asDate();

        Date now = new Date();
        if (expiredDate.before(now)) {
            throw new IllegalArgumentException("유효한 토큰이 아닙니다.");
        }

        String username = decodedJWT
                .getClaim(CLAIM_USER_NAME)
                .asString();

        return username;
    }

    private Optional<DecodedJWT> isValidToken(String token) {
        DecodedJWT jwt = null;

        try {
            // 들어온 토큰에 대해서 알고리즘 검증을 해준다.
            Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
            JWTVerifier verifier = JWT
                    .require(algorithm)
                    .build();

            jwt = verifier.verify(token);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return Optional.ofNullable(jwt);
    }
}
