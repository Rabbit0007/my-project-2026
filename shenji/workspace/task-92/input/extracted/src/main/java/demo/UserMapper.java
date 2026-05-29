package demo;

import java.util.List;

public interface UserMapper {
    List<UserRecord> search(String keyword, String orderBy);
}

record UserRecord(long id, String name) {}
