package hello.login.domain.member;

import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class Member {

    private Long id;

    @NotEmpty
    private String loginId; //로그인아이디
    @NotEmpty
    private String name; //사용자이름
    @NotEmpty
    private String password;
}
