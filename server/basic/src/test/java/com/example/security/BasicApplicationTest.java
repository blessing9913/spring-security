package com.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class BasicApplicationTest {

    @DisplayName("1. 테스트")
    @Test
    void test_1(){

        assertEquals("test", "test");
    }


}