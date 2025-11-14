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

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.LinkedHashMap;
import java.util.Map;

public record FaultConfig(@JsonValue Map<Integer, Map<String, Map<Integer, String>>> interactions) {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final Map<Integer, Map<String, Map<Integer, String>>> interactions = new LinkedHashMap<>();

        public InteractionBuilder interaction(int number) {
            return new InteractionBuilder(this, number);
        }

        public FaultConfig build() {
            return new FaultConfig(Map.copyOf(interactions));
        }

        void addInteraction(int number, Map<String, Map<Integer, String>> faults) {
            interactions.put(number, faults);
        }
    }

    public static class InteractionBuilder {
        private final Builder parent;
        private final int interactionNumber;
        private final Map<String, Map<Integer, String>> faults = new LinkedHashMap<>();

        InteractionBuilder(Builder parent, int interactionNumber) {
            this.parent = parent;
            this.interactionNumber = interactionNumber;
        }

        public ClassBuilder fault(String className) {
            return new ClassBuilder(this, className);
        }

        public Builder end() {
            parent.addInteraction(interactionNumber, Map.copyOf(faults));
            return parent;
        }

        void addFault(String className, Map<Integer, String> lines) {
            faults.put(className, lines);
        }
    }

    public static class ClassBuilder {
        private final InteractionBuilder parent;
        private final String className;
        private final Map<Integer, String> lines = new LinkedHashMap<>();

        ClassBuilder(InteractionBuilder parent, String className) {
            this.parent = parent;
            this.className = className;
        }

        public ClassBuilder at(int line, String type) {
            lines.put(line, type);
            return this;
        }

        public InteractionBuilder endFault() {
            parent.addFault(className, Map.copyOf(lines));
            return parent;
        }
    }
}
