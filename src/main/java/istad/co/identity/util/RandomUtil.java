package istad.co.identity.util;

import java.util.Random;

public class RandomUtil {

    public static String generate6Digits() {

        // It will generate 6 digit random Number.
        // from 0 to 999999
        Random random = new Random();
        int number = random.nextInt(999999);

        // this will convert any number sequence into 6 character.
        return String.format("%06d", number);
    }

}
