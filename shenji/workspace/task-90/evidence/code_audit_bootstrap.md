# Code Audit Bootstrap Evidence

## Task: 90 - Clue-driven exploration

### Source Files Analyzed

**Files extracted and read:**
1. `src/main/java/demo/AdminExportController.java` - Admin export endpoint
2. `src/main/java/demo/AdminExportService.java` - Export service logic
3. `src/main/java/demo/UserController.java` - User search endpoint
4. `src/main/java/demo/UserService.java` - User service layer
5. `src/main/java/demo/UserMapper.java` - MyBatis mapper interface
6. `src/main/resources/mapper/UserMapper.xml` - MyBatis SQL mapper

### Security Observations

#### 1. SQL Injection Vulnerability Candidate

**Location:** `src/main/resources/mapper/UserMapper.xml`

**Vulnerable Code:**
```xml
<select id="search" resultType="demo.UserRecord">
  SELECT id, name
  FROM users
  WHERE name LIKE CONCAT('%', #{keyword}, '%')
  ORDER BY ${orderBy}
</select>
```

**Analysis:**
- `orderBy` parameter uses `${orderBy}` (string interpolation) - VULNERABLE
- `keyword` parameter uses `#{keyword}` (parameterized) - SAFE
- MyBatis `${}` syntax directly interpolates values into SQL without escaping
- This allows arbitrary SQL injection in the ORDER BY clause

**Data Flow:**
```
UserController.search(HttpServletRequest)
  -> request.getParameter("orderBy")
  -> UserService.search(keyword, orderBy)
  -> UserMapper.search(keyword, orderBy)
  -> MyBatis XML: ORDER BY ${orderBy}
```

**Attack Surface:**
- Entry point: UserController.search() HTTP endpoint
- Parameter: `orderBy` query parameter
- No input validation or sanitization observed
- Direct flow from HTTP request to SQL interpolation

#### 2. Admin Export Endpoint Analysis

**Location:** `src/main/java/demo/AdminExportController.java`

**Observations:**
- Accepts `format` and `includeInactive` parameters
- Format validation: only "csv" or "json" allowed
- No apparent injection risk in observed code path
- Returns format-validated response

### Code Architecture Summary

```
demo/
├── AdminExportController.java  (HTTP entry point)
├── AdminExportService.java     (business logic)
├── UserController.java         (HTTP entry point - VULNERABLE PARAMETER)
├── UserService.java            (business logic - passes orderBy through)
├── UserMapper.java             (MyBatis interface)
└── UserMapper.xml              (SQL definition - SQLi in orderBy)
```

### Capability Assessment

- **source_code_read**: Verified - successfully read all extracted source files
- **dataflow_analysis**: Identified parameter flow from HTTP to SQL
- **vulnerability_candidate**: SQL injection in ORDER BY clause

### Next Investigation Targets

1. Verify SQL injection exploitability (requires database context)
2. Check for input validation in interceptors or filters
3. Identify authentication/authorization controls
4. Map additional attack surfaces
