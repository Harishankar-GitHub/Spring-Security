package com.springsecurity.student;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class Student
{
    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId, String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }
}
