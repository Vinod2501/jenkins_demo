package com.epam.musicapp.user.management.serviceimpl;

import org.springframework.data.domain.AuditorAware;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {

    private static final ThreadLocal<String> auditor = new ThreadLocal<>();

    public static void setAuditor(String username) {
        auditor.set(username);
    }

    @Override
    public Optional<String> getCurrentAuditor() {
        return Optional.ofNullable(auditor.get());
    }
}