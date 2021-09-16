package com.example.security.teacher;

import com.example.security.student.Student;
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
public class TeacherManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String, Teacher> teacherDB = new HashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        TeacherAuthenticationToken token = (TeacherAuthenticationToken) authentication;
        if(teacherDB.containsKey(token.getCredentials())){
            Teacher teacher = teacherDB.get(token.getCredentials());
            return TeacherAuthenticationToken.builder()
                    .principal(teacher)
                    .details(teacher.getUsername())
                    .authenticated(true)
                    .build();
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == TeacherAuthenticationToken.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Set<GrantedAuthority> setRole = new HashSet<GrantedAuthority>();
        setRole.add(new SimpleGrantedAuthority("ROLE_TEACHER"));

        Set<Teacher> hSetTeacher = new HashSet<Teacher>();
        hSetTeacher.add(new Teacher("teacher", "선생님", setRole));

        hSetTeacher.forEach(s-> teacherDB.put(s.getId(), s)
        );
    }
}
