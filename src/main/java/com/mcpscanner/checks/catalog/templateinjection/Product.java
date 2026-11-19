package com.mcpscanner.checks.catalog.templateinjection;

import java.security.SecureRandom;

record Product(long left, long right) {

    private static final SecureRandom RANDOM = new SecureRandom();

    static Product random() {
        return new Product(10_000 + RANDOM.nextInt(90_000), 1_000 + RANDOM.nextInt(9_000));
    }

    String expression() {
        return left + "*" + right;
    }

    String value() {
        return Long.toString(left * right);
    }
}
