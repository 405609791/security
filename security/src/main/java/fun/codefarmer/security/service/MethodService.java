package fun.codefarmer.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 *  测试 方法安全
 * @ @ClassName MethodService
 * @ Descriotion TODO
 * @ Author admin
 * @ Date 2020/2/8 14:41
 **/
@Service
public class MethodService {

    /**
     * 注解中 也可时hasAnyRole
     * @return
     */
    @PreAuthorize("hasRole('admin')")
    public String admin() {
        return "hello admin method security";
    }

    @Secured("ROLE_user")
    public String user() {
        return "hello user method security";
    }
    @PreAuthorize("hasAnyRole('admin','user')")
    public String hello() {
        return "hello hello @PreAuthorize('hasAnyRole('admin','user')')";
    }
}
