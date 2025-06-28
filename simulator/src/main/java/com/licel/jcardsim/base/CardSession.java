package com.licel.jcardsim.base;

// Helps to isolate session towards a shared simulator. Lock is held while the object is not closed.
public interface CardSession extends CardInterface, AutoCloseable {

    void close(boolean reset);

    @Override
    default void close() {
        close(false);
    }
}
