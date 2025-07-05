package pro.javacard.engine.core;

// Helps to isolate session towards a shared simulator. Lock is held while the object is not closed.
public interface EngineSession extends CardInterface, AutoCloseable {

    // Reset boolean controls runtime reset
    void close(boolean reset);

    boolean isClosed();

    @Override
    default void close() {
        close(false);
    }
}
