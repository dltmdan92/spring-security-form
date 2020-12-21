package com.seungmoo.springsecurityform.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StopWatch;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Custom Filter를 만들어보자.
 * (단순 로깅해주는 그런 Filter임)
 */
public class LoggingFilter extends GenericFilterBean {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        StopWatch stopWatch = new StopWatch();
        // task명에 RequestURI를 넣어 줌으로써 RequestURI별 성능 체크를 해볼 수 있다.
        stopWatch.start(((HttpServletRequest) servletRequest).getRequestURI());

        // 이거 꼭 해줘야 filterChain에서 request가 다음 filter로 넘어가거나 handler로 간다.
        filterChain.doFilter(servletRequest, servletResponse);

        stopWatch.stop();
        logger.info(stopWatch.prettyPrint());
    }
}
