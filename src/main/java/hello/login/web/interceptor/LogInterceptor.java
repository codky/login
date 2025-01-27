package hello.login.web.interceptor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

@Slf4j
public class LogInterceptor implements HandlerInterceptor {

    public static final String LOG_ID = "logId";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestURI = request.getRequestURI();

        //요청 로그를 구분하기 위한 uuid 생성
        String uuid = UUID.randomUUID().toString();
        //preHandle에서 지정한 값을 postHandle, afterCompletion에서 사용하려면 담아야함
        //LogInterceptor도 싱글톤처럼 사용되기 때문에 멤버변수를 사용하면 위험함.
        request.setAttribute(LOG_ID, uuid);

        //@RequestMapping: HandlerMethod
        //정적 리소스: ResourceHttpRequestHandler->@Controller가 아니라 /resources/static과 같은 정적리소스가 호출되는 경우
        if (handler instanceof HandlerMethod) {
            //핸들러 정보는 어떤 핸들러 매핑을 사용하는가에 따라 달라짐.
            //스프링을 사용하면 일반적으로 @Controller, @RequestMapping을 활용한 핸들러 매핑을 사용하고
            //이 경우엔 핸들러 정보로 HandlerMethod가 넘어옴
            HandlerMethod hm = (HandlerMethod) handler; //호출할 컨트롤러 메서드의 모든 정보가 포함되어 있다.
        }

        log.info("REQUEST [{}][{}][{}]", uuid, requestURI, handler);
        return true; //true면 정상호출->다음 인터셉터나 컨트롤러를 호출, false면 진행X
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse
            response, Object handler, ModelAndView modelAndView) throws Exception {
        log.info("postHandle [{}]", modelAndView);
    }
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse
            response, Object handler, Exception ex) throws Exception {
        String requestURI = request.getRequestURI();
        String logId = (String)request.getAttribute(LOG_ID);

        //종료 로그를 postHandle이 아니라 afterCompletion에서 실행하는 이유는
        //예외가 발생한 경우 postHandle은 호출되지 않음. afterCompletion은 호출을 보장함.
        log.info("RESPONSE [{}][{}]", logId, requestURI);
        if (ex != null) {
            log.error("afterCompletion error!!", ex);
        }
    }
}
