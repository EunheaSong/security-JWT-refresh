package com.example.securityjwt;

import com.example.securityjwt.domain.User;
import com.example.securityjwt.domain.UserDto;
import com.example.securityjwt.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserRepository userRepository;

    @PostMapping("/user/join")
    public String join (UserDto userDto){
        User user = new User(userDto);
        userRepository.save(user);
        return "회원가입 완료";
    }



}
