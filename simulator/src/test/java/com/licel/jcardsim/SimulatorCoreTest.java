package com.licel.jcardsim;

import com.licel.jcardsim.base.Simulator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SimulatorCoreTest {
    // These tests don't create an explicit Simulator instance
    // but the core reuires a Simulator.current() instance to exist
    // for transient memory (mostly), so set one up.

    static Simulator sim;

    @BeforeAll
    static void implicitSimulator() {
        sim = new Simulator();
    }
}
