package hello.login.web.filter;

import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class LoginCheckFilter implements Filter {

    //인증필터를 적용해도 홈, 회원가입, 로그인 화면, css같은 리소스에는 접근할 수 있어야 함.
    //화이트 리스트 경로는 인증과 무관하게 항상 허용
    private static final String[] whitelist = {"/", "/members/add", "/login", "/logout", "/css/*"};

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            log.info("인증 체크 필터 시작 {}", requestURI);

            //미인증 사용자는 로그인 화면으로 리다이렉트하고, 로그인 이후에는 기존에 요청한 경로로 리다이렉트
            if (isLoginCheckPath(requestURI)) {
                log.info("인증 체크 로직 실행 {}", requestURI);
                HttpSession session = httpRequest.getSession(false);
                if (session == null || session.getAttribute(SessionConst.LOGIN_MEMBER) == null) {
                    log.info("미인증 사용자 요청 {}", requestURI);
                    //로그인으로 redirect
                    httpResponse.sendRedirect("/login?redirectURL=" + requestURI);

                    //미인증 사용자는 다음으로 진행하지 않고 끝.->필터를 더 진행하지 않는다.
                    //이후 필터, 서블릿, 컨트롤러가 더 호출되지 않음. redirect를 사용했기 때문에 redirect가 응답으로 적용되고 요청이 끝난다.
                    return;
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            throw e; //예외 로깅 가능하지만, 톰캣까지 예외를 보내주어야 함
        } finally {
            log.info("인증 체크 필터 종료 {}", requestURI);
        }
    }

    /**
     * 화이트 리스트의 경우 인증 체크X
     */
    private boolean isLoginCheckPath(String requestURI) {
        return !PatternMatchUtils.simpleMatch(whitelist, requestURI);
    }

}
