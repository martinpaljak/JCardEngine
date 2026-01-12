/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pro.javacard.engine.faulty;

import java.util.LinkedHashMap;
import java.util.Map;

public record FaultyConfig(
        Map<Integer, Map<String, Map<Integer, String>>> step,
        Map<String, Map<String, Map<Integer, String>>> apdu) {

    public FaultyConfig {
        step = step == null ? Map.of() : Map.copyOf(step);
        apdu = apdu == null ? Map.of() : Map.copyOf(apdu);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final Map<Integer, Map<String, Map<Integer, String>>> steps = new LinkedHashMap<>();
        private final Map<String, Map<String, Map<Integer, String>>> apdus = new LinkedHashMap<>();

        public Builder faultyAt(int step, String className, int line) {
            return faultyAt(step, className, line, "skip");
        }

        public Builder faultyAt(int step, Class<?> clazz, int line) {
            return faultyAt(step, clazz.getName(), line, "skip");
        }

        public Builder faultyAt(int step, String className, int line, String type) {
            steps.computeIfAbsent(step, k -> new LinkedHashMap<>())
                    .computeIfAbsent(className, k -> new LinkedHashMap<>())
                    .put(line, type);
            return this;
        }

        public Builder faultyAt(int step, Class<?> clazz, int line, String type) {
            return faultyAt(step, clazz.getName(), line, type);
        }

        public Builder faultyAt(String apduPattern, String className, int line) {
            return faultyAt(apduPattern, className, line, "skip");
        }

        public Builder faultyAt(String apduPattern, Class<?> clazz, int line) {
            return faultyAt(apduPattern, clazz.getName(), line, "skip");
        }

        public Builder faultyAt(String apduPattern, String className, int line, String type) {
            apdus.computeIfAbsent(apduPattern, k -> new LinkedHashMap<>())
                    .computeIfAbsent(className, k -> new LinkedHashMap<>())
                    .put(line, type);
            return this;
        }

        public Builder faultyAt(String apduPattern, Class<?> clazz, int line, String type) {
            return faultyAt(apduPattern, clazz.getName(), line, type);
        }

        public FaultyConfig build() {
            return new FaultyConfig(steps, apdus);
        }
    }

    public Map<String, Map<Integer, String>> getFaults(int stepNumber, byte[] apduBytes) {
        Map<String, Map<Integer, String>> result = new LinkedHashMap<>();

        // Match by step number
        if (step.containsKey(stepNumber)) {
            mergeFaults(result, step.get(stepNumber));
        }

        // Match by APDU pattern
        for (var entry : apdu.entrySet()) {
            if (matchesApduPattern(entry.getKey(), apduBytes)) {
                mergeFaults(result, entry.getValue());
            }
        }

        return result;
    }

    private void mergeFaults(Map<String, Map<Integer, String>> target, Map<String, Map<Integer, String>> source) {
        for (var classEntry : source.entrySet()) {
            target.merge(classEntry.getKey(), new LinkedHashMap<>(classEntry.getValue()),
                    (existing, incoming) -> {
                        existing.putAll(incoming);
                        return existing;
                    });
        }
    }

    private boolean matchesApduPattern(String pattern, byte[] apduBytes) {
        var regex = pattern.toUpperCase().replace("X", ".") + ".*";
        var hex = new StringBuilder();
        for (var b : apduBytes) {
            hex.append(String.format("%02X", b & 0xFF));
        }
        return hex.toString().matches(regex);
    }
}
