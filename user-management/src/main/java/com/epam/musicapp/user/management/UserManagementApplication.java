package com.epam.musicapp.user.management;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static com.epam.musicapp.user.management.constants.UserConstants.AES_TRANSFORMATION;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
@EnableJpaAuditing
public class UserManagementApplication {
	private static final Logger LOGGER = LogManager.getLogger(UserManagementApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(UserManagementApplication.class, args);
		String secretKey = "secret key 12356";
		String plainTextPassword = "secret@123";

		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] encrypted = cipher.doFinal(plainTextPassword.getBytes());
			String encryptedPassword = Base64.encodeBase64String(encrypted);

			LOGGER.info(encryptedPassword);
		} catch (Exception e) {
			LOGGER.error( e.getMessage());
		}
	}
	}


