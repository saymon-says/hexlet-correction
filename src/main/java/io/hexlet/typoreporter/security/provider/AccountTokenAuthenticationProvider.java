package io.hexlet.typoreporter.security.provider;

import io.hexlet.typoreporter.security.authentication.AccountAuthenticationToken;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AccountTokenAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder BCryptPasswordEncoder;

    private final UserDetailsService service;

    public AccountTokenAuthenticationProvider(@Qualifier("passwordEncoder") PasswordEncoder bCryptPasswordEncoder,
                                              @Qualifier("accountDetailsService") UserDetailsService service) {
        BCryptPasswordEncoder = bCryptPasswordEncoder;
        this.service = service;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var username = authentication.getName();
        final var account = service.loadUserByUsername(username);
        final var token = authentication.getCredentials().toString();
        if (BCryptPasswordEncoder.matches(token, account.getPassword())) {
            return new AccountAuthenticationToken(username, token, account.getAuthorities());
        }
        throw new BadCredentialsException("BadCredentialsException");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccountAuthenticationToken.class.equals(authentication);

    }
}
