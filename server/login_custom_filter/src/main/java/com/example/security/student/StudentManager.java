package com.example.security.student;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;


@Component
public class StudentManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String, Student> studentDB = new HashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        StudentAuthenticationToken token = (StudentAuthenticationToken) authentication;
        if(studentDB.containsKey(token.getCredentials())){
            Student student = studentDB.get(token.getCredentials());
            return StudentAuthenticationToken.builder()
                    .principal(student)
                    .details(student.getUsername())
                    .authenticated(true)
                    .authorities(student.getRole())
                    .build();
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == StudentAuthenticationToken.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Set<GrantedAuthority> hSetRole = new HashSet<GrantedAuthority>();
        hSetRole.add(new SimpleGrantedAuthority("ROLE_STUDENT"));

        Set<Student> hSetStudent = new HashSet<Student>();
        hSetStudent.add(new Student("student01", "학생1", hSetRole));
        hSetStudent.add(new Student("student02", "학생2", hSetRole));
        hSetStudent.add(new Student("student03", "학생3", hSetRole));

        hSetStudent.forEach(s->
            studentDB.put(s.getId(), s)
        );
    }
}
