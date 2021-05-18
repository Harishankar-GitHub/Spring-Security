package com.springsecurity.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;
import java.util.Set;

import static com.springsecurity.security.UserPermissions.*;

@AllArgsConstructor
@Getter
public enum UserRoles
{
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ,
                            COURSE_WRITE,
                            STUDENT_READ,
                            STUDENT_WRITE));
    
    private final Set<UserPermissions> permissions;
}
