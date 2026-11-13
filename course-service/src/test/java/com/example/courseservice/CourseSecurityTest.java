package com.example.courseservice;

import com.example.courseservice.controller.CourseController;
import com.example.courseservice.security.HeaderAuthenticationFilter;
import com.example.courseservice.security.SecurityConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CourseController.class)
@Import({SecurityConfig.class, HeaderAuthenticationFilter.class})
class CourseSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /api/courses với Role STUDENT -> 200 OK")
    void testGetCourses_WithStudentRole_Success() throws Exception {
        mockMvc.perform(get("/api/courses")
                        .header("X-User-Role", "STUDENT")
                        .header("X-User-Name", "student1"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /api/courses với Role INSTRUCTOR -> 200 OK")
    void testGetCourses_WithInstructorRole_Success() throws Exception {
        mockMvc.perform(get("/api/courses")
                        .header("X-User-Role", "INSTRUCTOR")
                        .header("X-User-Name", "instructor1"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /api/courses với Role STUDENT -> 403 Forbidden (Chặn vì không có quyền INSTRUCTOR)")
    void testCreateCourse_WithStudentRole_Forbidden() throws Exception {
        String body = """
                {
                    "title": "Học Spring Cloud",
                    "instructor": "Nguyễn Văn A"
                }
                """;

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Role", "STUDENT")
                        .header("X-User-Name", "student1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    @DisplayName("POST /api/courses với Role INSTRUCTOR -> 201 Created (Cho phép)")
    void testCreateCourse_WithInstructorRole_Success() throws Exception {
        String body = """
                {
                    "title": "Thiết kế hệ thống Microservices",
                    "instructor": "Thầy Giáo X"
                }
                """;

        mockMvc.perform(post("/api/courses")
                        .header("X-User-Role", "INSTRUCTOR")
                        .header("X-User-Name", "instructor1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("Thiết kế hệ thống Microservices"));
    }

    @Test
    @DisplayName("Truy cập KHÔNG có Header X-User-Role -> 401 Unauthorized")
    void testAccess_WithoutHeader_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/courses"))
                .andExpect(status().isUnauthorized());
    }
}
