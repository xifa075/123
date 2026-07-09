package burp;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
/** Single compatibility boundary for reflective access to the original monolithic extension. */
public final class BurpExtensionAccess {
    private static final ConcurrentMap<String, Method> METHODS = new ConcurrentHashMap<String, Method>();
    private static final ConcurrentMap<String, Field> FIELDS = new ConcurrentHashMap<String, Field>();
    private BurpExtensionAccess() { }

    public static Object invokePrivate(BurpExtender extender, String name, Class<?>[] types, Object[] args)
            throws Exception {
        if (extender == null) throw new IllegalArgumentException("extender is null");
        Method method = findMethod(extender.getClass(), name, types);
        try {
            return method.invoke(extender, args);
        } catch (InvocationTargetException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw wrapped;
        }
    }

    public static Object readField(BurpExtender extender, String name) throws Exception {
        if (extender == null) return null;
        Field field = findField(extender.getClass(), name);
        return field.get(extender);
    }

    /** Writes a legacy field only from an EDT-owned adapter; callers must preserve thread ownership. */
    public static void writeField(Object instance, String name, Object value) throws Exception {
        if (instance == null) throw new IllegalArgumentException("instance is null");
        Field field = findField(instance.getClass(), name);
        field.set(instance, value);
    }

    public static String readStringField(Object instance, String name) {
        if (instance == null) return "";
        try {
            Field field = findField(instance.getClass(), name);
            Object value = field.get(instance);
            return value == null ? "" : String.valueOf(value);
        } catch (Exception ignored) {
            return "";
        }
    }

    public static boolean readBooleanField(Object instance, String name) {
        if (instance == null) return false;
        try {
            Field field = findField(instance.getClass(), name);
            Object value = field.get(instance);
            return value instanceof Boolean && ((Boolean) value).booleanValue();
        } catch (Exception ignored) {
            return false;
        }
    }

    public static int readIntField(Object instance, String name, int fallback) {
        if (instance == null) return fallback;
        try {
            Field field = findField(instance.getClass(), name);
            Object value = field.get(instance);
            return value instanceof Number ? ((Number) value).intValue() : fallback;
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static Method findMethod(Class<?> type, String name, Class<?>[] parameterTypes)
            throws NoSuchMethodException {
        String key = type.getName() + "#" + name + java.util.Arrays.toString(parameterTypes);
        Method cached = METHODS.get(key);
        if (cached != null) return cached;
        Class<?> cursor = type;
        while (cursor != null) {
            try {
                Method method = cursor.getDeclaredMethod(name, parameterTypes);
                method.setAccessible(true);
                Method existing = METHODS.putIfAbsent(key, method);
                return existing == null ? method : existing;
            } catch (NoSuchMethodException ignored) { cursor = cursor.getSuperclass(); }
        }
        throw new NoSuchMethodException(key);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        String key = type.getName() + "#" + name;
        Field cached = FIELDS.get(key);
        if (cached != null) return cached;
        Class<?> cursor = type;
        while (cursor != null) {
            try {
                Field field = cursor.getDeclaredField(name);
                field.setAccessible(true);
                Field existing = FIELDS.putIfAbsent(key, field);
                return existing == null ? field : existing;
            } catch (NoSuchFieldException ignored) { cursor = cursor.getSuperclass(); }
        }
        throw new NoSuchFieldException(key);
    }
}
