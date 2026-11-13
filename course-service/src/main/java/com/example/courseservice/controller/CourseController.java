package com.example.courseservice.controller;

import com.example.courseservice.dto.CreateCourseRequest;
import com.example.courseservice.model.Course;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@RestController
@RequestMapping("/api/courses")
public class CourseController {

    // Danh sách tĩnh (in-memory) mô phỏng lưu trữ không dùng Database
    private static final List<Course> COURSE_LIST = new CopyOnWriteArrayList<>(List.of(
            new Course(1L, "Lập trình Java Backend nâng cao", "Nguyễn Văn A"),
            new Course(2L, "Kiến trúc Microservices với Spring Cloud", "Trần Thị B"),
            new Course(3L, "Bảo mật hệ thống với OAuth2 & JWT", "Lê Hoàng C")
    ));

    /**
     * API Xem danh sách khóa học
     * Phân quyền: Cả STUDENT và INSTRUCTOR đều được phép xem
     */
    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public ResponseEntity<List<Course>> getAllCourses() {
        log.info("--> [CourseController] Xem danh sách khóa học thành công!");
        return ResponseEntity.ok(COURSE_LIST);
    }

    /**
     * API Tạo khóa học mới
     * Phân quyền: CHỈ INSTRUCTOR mới được phép tạo, STUDENT bị 403 Forbidden
     */
    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public ResponseEntity<Course> createCourse(@RequestBody CreateCourseRequest request) {
        log.info("--> [CourseController] Giảng viên tạo mới khóa học: {}", request.getTitle());

        Course newCourse = Course.builder()
                .id((long) (COURSE_LIST.size() + 1))
                .title(request.getTitle())
                .instructor(request.getInstructor())
                .build();

        COURSE_LIST.add(newCourse);
        return ResponseEntity.status(HttpStatus.CREATED).body(newCourse);
    }
}
