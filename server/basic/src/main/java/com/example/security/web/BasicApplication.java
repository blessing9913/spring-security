package com.example.security.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BasicApplication {

    public static void main(String[] args) {

        //Person person = Person.builder().name("test").build();
        //System.out.println(person);

        SpringApplication.run(BasicApplication.class, args);
    }
}
