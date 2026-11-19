package com.mcpscanner.checks.catalog.nosqlinjection;

import java.util.List;

record Separation(Technique technique, Probe miss, Probe broadening, Probe falsifier) {

    boolean separates() {
        return broadening.differsFrom(miss) && falsifier.matches(miss);
    }

    List<Probe> probes() {
        return List.of(miss, broadening, falsifier);
    }
}
