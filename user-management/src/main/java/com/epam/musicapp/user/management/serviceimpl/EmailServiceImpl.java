package com.epam.musicapp.user.management.serviceimpl;

import com.epam.musicapp.user.management.entity.User;
import com.epam.musicapp.user.management.service.EmailService;
import com.epam.musicapp.user.management.utility.JwtUtil;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Service;

import static com.epam.musicapp.user.management.constants.UserConstants.*;


@Service
public class EmailServiceImpl implements EmailService{

    private final JavaMailSender javaMailSender;
    private final JwtUtil jwtUtil;

    public EmailServiceImpl(JavaMailSender javaMailSender, JwtUtil jwtUtil) {
        this.javaMailSender = javaMailSender;
        this.jwtUtil = jwtUtil;
    }

    public void sendVerificationEmail(User user) {
        MimeMessagePreparator message = mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);
            helper.setTo(user.getUserEmail());
            helper.setSubject(SUBJECT);
            String content = generateVerificationContent(user);
            helper.setText(content, true);
        };
        javaMailSender.send(message);
    }

    private String generateVerificationContent(User user) {
        String jwtToken = jwtUtil.generateToken(user.getUserEmail());
        return constructHtmlContent(user.getUserName(), jwtToken);
    }

    private String constructHtmlContent(String userName, String jwtToken) {
        return "<p>Hello, "+ userName +"</p>"
                + "<p>Thank you for registering with Music App. To complete your registration, please click on the link below:</p>"
                + "<a href=\"http://localhost:8080/verify.html?token=" + jwtToken + "\">Verify Here</a>"
                + "<br><p>Thank you!</p>";
    }

}
