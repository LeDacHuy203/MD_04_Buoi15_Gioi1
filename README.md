# TỔNG HỢP TOÀN BỘ BÀI TẬP BUỔI 15 (BÀI 1, BÀI 2, BÀI 3)

---

## 1. Cấu Trúc Toàn Bộ Dự Án

```
buoi15/
├── Identity_Service_Postman_Collection.json   # Postman Collection trọn bộ Bài 1, Bài 2 & Bài 3
├── settings.gradle
├── README.md
├── identity-service/                          # [Bài 1] Cấp phát Access & Refresh Token (Cổng 8080)
│   ├── build.gradle
│   └── src/main/java/com/example/identityservice/
│       ├── config/JwtUtil.java                # Cấp JWT HS256 (15m, sub, role, jti)
│       ├── config/SecurityConfig.java         # CSRF disable, Stateless, permitAll /api/auth/**
│       ├── config/DataInitializer.java        # Seed tài khoản: student1, instructor1 (pass: 123456)
│       ├── entity/User.java                   # Bảng users trong PostgreSQL
│       ├── entity/RefreshToken.java           # Bảng refresh_tokens trong PostgreSQL (7 ngày)
│       └── controller/AuthController.java     # POST /api/auth/login, /register, /refresh
├── gateway-service/                           # [Bài 2] API Gateway Trạm gác biên phòng (Cổng 8888)
│   ├── build.gradle
│   └── src/main/java/com/example/gatewayservice/
│       ├── GatewayServiceApplication.java
│       ├── util/JwtUtil.java                  # Dùng chung Secret Key với Identity Service
│       └── filter/JwtAuthenticationGlobalFilter.java # Global Filter chặn 401 & gắn Header X-User-Role
└── course-service/                            # [Bài 3] Phân quyền RBAC tại Resource Server (Cổng 8082)
    ├── build.gradle
    └── src/main/java/com/example/courseservice/
        ├── model/Course.java
        ├── security/HeaderAuthenticationFilter.java # Đọc quyền từ Header X-User-Role (không cần JWT lib)
        ├── security/SecurityConfig.java       # EnableMethodSecurity, gán filter, xử lý 403 Forbidden
        └── controller/CourseController.java   # @PreAuthorize hasAuthority('STUDENT' / 'INSTRUCTOR')
```

---

## 2. Chi Tiết Triển Khai [Bài tập 3] - Phân Quyền RBAC Tại Course-Service

| Yêu cầu đề bài | Chi tiết triển khai | File mã nguồn |
| :--- | :--- | :--- |
| **Service & Database** | `Course-Service`, **KHÔNG** dùng Database, lưu danh sách bằng `Java List tĩnh` | [CourseController.java](file:///c:/Users/ldh2k/Desktop/RIKKEI/BTVN%202/MD4/Buoi15/buoi15/course-service/src/main/java/com/example/courseservice/controller/CourseController.java) |
| **Dependencies** | `spring-boot-starter-web`, `spring-boot-starter-security` | [build.gradle](file:///c:/Users/ldh2k/Desktop/RIKKEI/BTVN%202/MD4/Buoi15/buoi15/course-service/build.gradle) |
| **Đọc quyền từ Header** | `HeaderAuthenticationFilter` đọc trực tiếp quyền từ Header `X-User-Role` do Gateway truyền xuống mà **KHÔNG cần thư viện giải mã JWT** | [HeaderAuthenticationFilter.java](file:///c:/Users/ldh2k/Desktop/RIKKEI/BTVN%202/MD4/Buoi15/buoi15/course-service/src/main/java/com/example/courseservice/security/HeaderAuthenticationFilter.java) |
| **Cấu hình Security** | `@EnableMethodSecurity(prePostEnabled = true)`, chặn 403 Forbidden khi không đủ quyền | [SecurityConfig.java](file:///c:/Users/ldh2k/Desktop/RIKKEI/BTVN%202/MD4/Buoi15/buoi15/course-service/src/main/java/com/example/courseservice/security/SecurityConfig.java) |
| **API `GET /api/courses`** | `@PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")` | `CourseController.java` |
| **API `POST /api/courses`** | `@PreAuthorize("hasAuthority('INSTRUCTOR')")` (Sinh viên gọi bị **403 Forbidden**) | `CourseController.java` |

---

## 3. Kết Quả Kiểm Thử [Bài 3] với Postman / cURL

### Kịch bản 1: Sinh viên (STUDENT) gọi POST `/api/courses` ➡️ Nhận kết quả 403 Forbidden
- **Request qua Gateway (Cổng 8888)**:
  ```http
  POST http://localhost:8888/api/courses
  Authorization: Bearer <STUDENT_ACCESS_TOKEN>
  Content-Type: application/json

  {
    "title": "Khóa học do Sinh viên thử tạo",
    "instructor": "Sinh viên"
  }
  ```
- **Response nhận được (403 Forbidden)**:
  ```json
  {
    "status": 403,
    "error": "Forbidden",
    "message": "Bạn không có quyền thực hiện hành động này (Access Denied)!"
  }
  ```

### Kịch bản 2: Giảng viên (INSTRUCTOR) gọi POST `/api/courses` ➡️ Cho phép (201 Created)
- **Request qua Gateway (Cổng 8888)**:
  ```http
  POST http://localhost:8888/api/courses
  Authorization: Bearer <INSTRUCTOR_ACCESS_TOKEN>
  Content-Type: application/json

  {
    "title": "Thiết kế hệ thống Microservices & RBAC",
    "instructor": "Giảng viên A"
  }
  ```
- **Response nhận được (201 Created)**:
  ```json
  {
    "id": 4,
    "title": "Thiết kế hệ thống Microservices & RBAC",
    "instructor": "Giảng viên A"
  }
  ```

### Kịch bản 3: Cả STUDENT và INSTRUCTOR gọi GET `/api/courses` ➡️ 200 OK
- **Response**: Trả về danh sách khóa học hiện tại (bao gồm cả các khóa học mới được Giảng viên tạo thêm trong danh sách Java List tĩnh).
