package fun.codefarmer.security.controller;

import fun.codefarmer.security.service.MethodService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ @ClassName HelloController
 * @ Descriotion TODO
 * @ Author admin
 * @ Date 2020/1/18 19:36
 **/
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "hello security!";
    }

    @GetMapping("/admin/hello")
    public String Admin() {
        return "hello admin";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "hello User";
    }

    @GetMapping("/login")
    public String login() {
        return "please login";
    }

    /**
     * 下面时测试方法安全的。不同的角色访问不同角色接口
     */
    @Autowired
    MethodService methodService;

    @GetMapping("/hellomethodadmin")
    public String helloMethod() {
        return methodService.admin();
    }

    @GetMapping("/hellomethoduser")
    public String helloMethodUser() {
        return methodService.user();
    }

    @GetMapping("/hellomethodhello")
    public String helloMethodHello() {
        return methodService.hello();
    }
}
