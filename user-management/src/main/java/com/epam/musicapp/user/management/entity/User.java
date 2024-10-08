package com.epam.musicapp.user.management.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@EqualsAndHashCode(callSuper = true)
@Entity
@NoArgsConstructor
@Data
@AllArgsConstructor
@Builder
@Table(name="ma_user")
public class User extends AuditModel {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="user_id")
    private Long userId;

    @Column(name="user_name", unique=true, length=10)
    private String userName;

    @Column(name="user_email", unique=true)
    private String userEmail;

    @Column(name="password")
    private String userPassword;

    @Column(name="verification_status")
    private String verificationStatus;
    @Column(name = "token", length = 512)
    private String token;
    @Column(name = "token_issued_at")
    private LocalDateTime tokenIssuedAt;

    public User(Long userId, String userName, String userEmail, String userPassword, String verificationStatus) {
        this.userId = userId;
        this.userName = userName;
        this.userEmail = userEmail;
        this.userPassword = userPassword;
        this.verificationStatus = verificationStatus;
    }
}
