package fun.codefarmer.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class SecurityApplicationTests {

    @Test
    void contextLoads() {
        for (int i = 0; i < 10; i++) {
            //下面时密码加密的工具：securi 时加密后的 ，可运行查看
            // $2a$10$pooi.K1N79hyYowdQPSj4OPnY5UffewLdZCXuwDO33fL/kyxyT2Am
            // $2a$10$yspF5eujFbCZg8edZTEYZ.v9tfrPRoloi0f9L88HWpSbo.GxepDym
            BCryptPasswordEncoder s = new BCryptPasswordEncoder();
            String securi = s.encode("123");
            System.out.println(securi);
        }
    }

}
