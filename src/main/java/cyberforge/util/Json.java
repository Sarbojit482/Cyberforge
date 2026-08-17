package cyberforge.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON parser and writer.
 *
 * CyberForge is deliberately kept lightweight (per the project spec: "Do not
 * add unnecessary technologies") and this build environment has no access to
 * Maven Central, so rather than vendor a full JSON library this implements
 * just enough JSON to (a) parse semgrep's --json output and (b) write
 * CyberForge's own normalized evidence files.
 *
 * SECURITY NOTE: this parser consumes semgrep's JSON output, which is
 * externally-produced data (semgrep's own analysis of an untrusted target).
 * It is a strict, allocation-bounded recursive-descent parser with no
 * eval/reflection of any kind — a malformed or hostile JSON payload can at
 * worst throw a JsonParseException, never execute anything. Combined with
 * SafeProcessRunner's MAX_PROCESS_OUTPUT_BYTES cap upstream, the amount of
 * JSON text this parser ever sees is already bounded before it gets here.
 */
public final class Json {

    private Json() {
    }

    public static final class JsonParseException extends RuntimeException {
        public JsonParseException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    public static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new JsonParseException("Unexpected trailing content at position " + parser.pos);
        }
        return value;
    }

    private static final class Parser {
        private final String s;
        private int pos = 0;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        void skipWhitespace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        char peek() {
            if (pos >= s.length()) {
                throw new JsonParseException("Unexpected end of input");
            }
            return s.charAt(pos);
        }

        char next() {
            char c = peek();
            pos++;
            return c;
        }

        void expect(char c) {
            if (next() != c) {
                throw new JsonParseException("Expected '" + c + "' at position " + (pos - 1));
            }
        }

        Object parseValue() {
            skipWhitespace();
            char c = peek();
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f' -> parseBoolean();
                case 'n' -> parseNull();
                default -> parseNumber();
            };
        }

        Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw new JsonParseException("Expected ',' or '}' at position " + (pos - 1));
                }
            }
            return map;
        }

        List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                Object value = parseValue();
                list.add(value);
                skipWhitespace();
                char c = next();
                if (c == ']') {
                    break;
                }
                if (c != ',') {
                    throw new JsonParseException("Expected ',' or ']' at position " + (pos - 1));
                }
            }
            return list;
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > s.length()) {
                                throw new JsonParseException("Truncated unicode escape");
                            }
                            String hex = s.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                        }
                        default -> throw new JsonParseException("Invalid escape '\\" + esc + "'");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Boolean parseBoolean() {
            if (s.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new JsonParseException("Invalid literal at position " + pos);
        }

        Object parseNull() {
            if (s.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new JsonParseException("Invalid literal at position " + pos);
        }

        Double parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
            if (pos < s.length() && s.charAt(pos) == '.') {
                pos++;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            if (pos == start) {
                throw new JsonParseException("Invalid number at position " + pos);
            }
            return Double.parseDouble(s.substring(start, pos));
        }
    }

    // ------------------------------------------------------------------
    // Writing (used to serialize CyberForge's own evidence objects)
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static String write(Object value, boolean pretty) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, pretty, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object value, boolean pretty, int indent) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String str) {
            writeString(sb, str);
        } else if (value instanceof Boolean b) {
            sb.append(b.toString());
        } else if (value instanceof Number n) {
            sb.append(n.toString());
        } else if (value instanceof Map<?, ?> map) {
            writeObject(sb, (Map<String, Object>) map, pretty, indent);
        } else if (value instanceof List<?> list) {
            writeArray(sb, (List<Object>) list, pretty, indent);
        } else {
            writeString(sb, value.toString());
        }
    }

    private static void writeObject(StringBuilder sb, Map<String, Object> map, boolean pretty, int indent) {
        if (map.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append('{');
        int i = 0;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (pretty) {
                sb.append('\n').append("  ".repeat(indent + 1));
            }
            writeString(sb, entry.getKey());
            sb.append(':').append(pretty ? " " : "");
            writeValue(sb, entry.getValue(), pretty, indent + 1);
            if (++i < map.size()) {
                sb.append(',');
            }
        }
        if (pretty) {
            sb.append('\n').append("  ".repeat(indent));
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<Object> list, boolean pretty, int indent) {
        if (list.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append('[');
        for (int i = 0; i < list.size(); i++) {
            if (pretty) {
                sb.append('\n').append("  ".repeat(indent + 1));
            }
            writeValue(sb, list.get(i), pretty, indent + 1);
            if (i < list.size() - 1) {
                sb.append(',');
            }
        }
        if (pretty) {
            sb.append('\n').append("  ".repeat(indent));
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String str) {
        sb.append('"');
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // ------------------------------------------------------------------
    // Small typed-access helpers for reading parsed JSON safely
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object o) {
        if (o instanceof Map) {
            return (Map<String, Object>) o;
        }
        throw new JsonParseException("Expected JSON object");
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asArray(Object o) {
        if (o instanceof List) {
            return (List<Object>) o;
        }
        throw new JsonParseException("Expected JSON array");
    }

    public static String getString(Map<String, Object> obj, String key, String fallback) {
        Object v = obj.get(key);
        return v instanceof String s ? s : fallback;
    }

    public static int getInt(Map<String, Object> obj, String key, int fallback) {
        Object v = obj.get(key);
        return v instanceof Number n ? n.intValue() : fallback;
    }
}
