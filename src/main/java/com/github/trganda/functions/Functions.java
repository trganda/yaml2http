package com.github.trganda.functions;

public abstract class Functions {

    public static String randomInt(int min, int max) {
        int randomVal = (int)(Math.random() * (max - min) + min);
        return String.valueOf(randomVal);
    }
}
