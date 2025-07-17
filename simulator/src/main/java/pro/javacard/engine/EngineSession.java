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
package pro.javacard.engine;

import com.licel.jcardsim.base.CardInterface;

// Helps to isolate session towards a shared simulator. Lock is held while the object is not closed.
public interface EngineSession extends CardInterface, AutoCloseable {

    // Reset boolean controls runtime reset
    void close(boolean reset);

    boolean isClosed();

    @Override
    default void close() {
        close(false);
    }

    String getProtocol();
}
