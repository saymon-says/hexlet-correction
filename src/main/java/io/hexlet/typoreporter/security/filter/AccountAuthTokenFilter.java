package io.hexlet.typoreporter.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AccountAuthTokenFilter extends UsernamePasswordAuthenticationFilter {



}
