package demo;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    public List<UserRecord> search(HttpServletRequest request) {
        String keyword = request.getParameter("keyword");
        String orderBy = request.getParameter("orderBy");
        return userService.search(keyword, orderBy);
    }
}
