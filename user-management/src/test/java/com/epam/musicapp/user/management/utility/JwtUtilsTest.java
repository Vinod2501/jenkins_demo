package com.epam.musicapp.user.management.utility;

import com.epam.musicapp.user.management.exception.JsonConversionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

 class JwtUtilsTest {
    @InjectMocks
    private JwtUtil jwtUtil;

     @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
         String jwtSecret = "5D+OIp6AcYSVtjNE+aFkwqq1taisdFD4jqwKsBI/LUk=";
         ReflectionTestUtils.setField(jwtUtil, "jwtSecret", jwtSecret);
    }

    @Test
     void testGenerateTokenUsingUserDetails() {
        String username = "username";
        Long userId = 1L;

        String token = jwtUtil.generateTokenUsingUserDetails(username, userId);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
    }

    @Test
     void testAsJsonString_ValidObject() {
        String testObject = "testObject";

        String jsonString = JwtUtil.asJsonString(testObject);

        assertEquals("\"testObject\"", jsonString);
    }

    @Test
     void testAsJsonString_InvalidObject() {
        Object testObject = new Object() {
            @Override
            public String toString() {
                throw new RuntimeException("Test exception");
            }
        };

        assertThrows(JsonConversionException.class, () -> JwtUtil.asJsonString(testObject));
    }
}

