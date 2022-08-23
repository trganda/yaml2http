package com.github.trganda.util;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class NormalTest {

    @Test
    public void runTest() {
        // array input
        byte playersArray[]
                = { 13 };

        byte[] value = new byte[2];

        // printing input elements for comparison
        System.out.println("Array input: "
                + Arrays.toString(playersArray));

        // converting array into Collection
        // with asList() function
        List playersList = Collections.singletonList(value);
        List<Byte> values = new ArrayList<Byte>();
        values.addAll(playersList);
        values.addAll(playersList);

        // print converted elements
        System.out.println("Converted elements: "
                + playersList);
    }
}
