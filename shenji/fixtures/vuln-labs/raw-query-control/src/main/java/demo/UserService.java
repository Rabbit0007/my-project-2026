package demo;

import java.util.List;

public class UserService {
    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public List<UserRecord> search(String keyword, String orderBy) {
        return userMapper.search(keyword, orderBy);
    }
}
