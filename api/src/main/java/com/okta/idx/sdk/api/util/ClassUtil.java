package com.okta.idx.sdk.api.util;

import java.lang.reflect.Field;

public class ClassUtil {

    public static void setInternalState(Object target, String fieldName, Object value) {
        Class<?> clazz = target.getClass();
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (SecurityException | NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
            throw new RuntimeException("Unable to set internal state on a private field. [...]", e);
        }
    }
}
