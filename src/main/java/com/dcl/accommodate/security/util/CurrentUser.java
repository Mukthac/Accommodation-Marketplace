package com.dcl.accommodate.security.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.swing.text.html.Option;
import java.util.Optional;
import java.util.UUID;

public class CurrentUser {

    public static Optional<Authentication> getAuthentication() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());
    }

    public static Optional<UUID> getCurrentUserId() {
        return getAuthentication()
                .map(auth -> {
                    String userId = auth.getName();
                    return userId != null
                            ? UUID.fromString(userId)
                            : null;
                });
    }

    public static void setAuthentication(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
