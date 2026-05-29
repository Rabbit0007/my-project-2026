# SQL Injection Validation Report

## Intent
- Intent ID: 772
- Hypothesis ID: 536
- Target: Validate SQL injection path from UserController.search() orderBy parameter

## Source-to-Sink Analysis

### Source (UserController.java)
```java
// Line 10 - User-controlled input entry point
String orderBy = request.getParameter("orderBy");
```
- **Type**: HTTP request parameter extraction
- **User-controlled**: Yes - HttpServletRequest.getParameter() returns user input
- **Sanitization**: None - direct assignment with no validation

### Intermediate Flow (UserService.java)
```java
// Line 10 - Pass-through with no sanitization
public List<UserRecord> search(String keyword, String orderBy) {
    return userMapper.search(keyword, orderBy);
}
```
- **Transformation**: None
- **Validation**: None
- **Sanitization**: None

### Mapper Interface (UserMapper.java)
```java
// Line 4 - MyBatis mapper interface
List<UserRecord> search(String keyword, String orderBy);
```

### Sink (UserMapper.xml)
```xml
<!-- Line 5 - Unsafe SQL interpolation -->
<select id="search" resultType="demo.UserRecord">
  SELECT id, name
  FROM users
  WHERE name LIKE CONCAT('%', #{keyword}, '%')
  ORDER BY ${orderBy}
</select>
```
- **Vulnerability**: MyBatis `${orderBy}` performs string interpolation
- **Safe alternative**: `#{orderBy}` for parameterized query
- **Attack surface**: ORDER BY clause

## Validation Result

### Source-to-Sink Reachability: CONFIRMED
- Direct flow path with no blocking sanitization or validation
- Path: UserController → UserService → UserMapper → SQL ORDER BY clause

### Exploitability: CONFIRMED
- MyBatis `${}` syntax is documented as unsafe for user input
- Allows arbitrary SQL injection into ORDER BY clause
- Example payload: `orderBy=name; DROP TABLE users;--`

### No Mitigating Controls Found
- No input validation in UserController
- No sanitization in UserService
- No parameterization at sink (uses `${}` not `#{}`)

## Evidence Code Slices

### UserController.java (complete)
```java
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
        String orderBy = request.getParameter("orderBy");  // VULNERABLE SOURCE
        return userService.search(keyword, orderBy);        // NO SANITIZATION
    }
}
```

### UserService.java (complete)
```java
package demo;

import java.util.List;

public class UserService {
    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public List<UserRecord> search(String keyword, String orderBy) {
        return userMapper.search(keyword, orderBy);  // PASS-THROUGH, NO VALIDATION
    }
}
```

### UserMapper.xml (complete)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="demo.UserMapper">
  <select id="search" resultType="demo.UserRecord">
    SELECT id, name
    FROM users
    WHERE name LIKE CONCAT('%', #{keyword}, '%')
    ORDER BY ${orderBy}  <!-- VULNERABLE SINK: Unsafe interpolation -->
  </select>
</mapper>
```

## Conclusion
The SQL injection vulnerability is VALIDATED:
1. User-controlled input reaches SQL query without sanitization
2. MyBatis `${}` interpolation is known vulnerable pattern
3. No defensive controls exist in the code path
4. Attack vector: orderBy parameter in UserController.search() endpoint

**Capability**: sql_injection (verified)
**Target**: UserController.search() orderBy parameter
**Confidence**: HIGH - static analysis confirms exploitable path
