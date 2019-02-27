package ee.bitweb.springframework.security.estonianid.authentication;

import org.springframework.util.ObjectUtils;

import java.util.Calendar;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdCredentialsValidator {

    public static boolean validate(SmartIdAuthenticationSession.CountryCode countryCode, String userIdCode) {
        if (ObjectUtils.isEmpty(countryCode) || ObjectUtils.isEmpty(userIdCode)) {
            return false;
        }

        switch (countryCode) {
            case EE:
            case LT:
                return validateEEOrLTIdCode(userIdCode);
            case LV:
                return validateLVIdCode(userIdCode);
            default:
                return false;
        }
    }

    private static boolean validateEEOrLTIdCode(String userIdCode) {
        if (!userIdCode.matches("^[0-9]{11}$")) {
            return false;
        }

        int genderAndCentury = Integer.parseInt(userIdCode.substring(0, 1));
        int birthYear = Integer.parseInt(userIdCode.substring(1, 3));
        int birthMonth = Integer.parseInt(userIdCode.substring(3, 5));
        int birthDay = Integer.parseInt(userIdCode.substring(5, 7));
        int century = genderAndCentury % 2 == 0 ? 17 + genderAndCentury / 2 : 17 + (genderAndCentury + 1) / 2;

        birthYear = 100 * century + birthYear;

        if (!validateDateComponents(birthYear, birthMonth, birthDay, true)) {
            return false;
        }

        return validateCheckSumForEEOrLTIdCode(userIdCode);
    }

    private static boolean validateLVIdCode(String userIdCode) {
        if (!userIdCode.matches("^[0-9]{6}[-]?[0-9]{5}$")) {
            return false;
        }
        userIdCode = userIdCode.replaceAll("\\D", "");

        int birthDay = Integer.parseInt(userIdCode.substring(0, 2));
        int birthMonth = Integer.parseInt(userIdCode.substring(2, 4));
        int birthYear = Integer.parseInt(userIdCode.substring(4, 6));

        birthYear = birthYear + 1800 + 100 * Integer.parseInt(userIdCode.substring(6, 7));

        if (!validateDateComponents(birthYear, birthMonth, birthDay, true)) {
            return false;
        }

        return validateCheckSumForLVIdCode(userIdCode);
    }

    private static boolean validateDateComponents(int year, int month, int day, boolean compareToCurrent) {
        if (String.valueOf(year).length() > 4 || String.valueOf(month).length() > 2 || String.valueOf(day).length() > 2) {
            return false;
        }

        if (year < 1000 || year > 9999 || month <= 0 || month > 12) {
            return false;
        }

        int[] monthLimits = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        if (year % 400 == 0 || year % 100 != 0 && year % 4 == 0) {
            monthLimits[1] = 29;
        }

        if (day <= 0 || day > monthLimits[month - 1]) {
            return false;
        }

        if (compareToCurrent) {
            Calendar calendar = Calendar.getInstance();
            int currentYear = calendar.get(Calendar.YEAR);
            int currentMonth = calendar.get(Calendar.MONTH) + 1;
            int currentDay = calendar.get(Calendar.DAY_OF_MONTH);

            return currentYear > year || year == currentYear && currentMonth > month
                    || year == currentYear && month == currentMonth && currentDay == day;
        }

        return true;
    }

    private static boolean validateCheckSumForEEOrLTIdCode(String userIdCode) {
        int[] weights = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 1 };

        int checkSum = getCheckSum(weights, SmartIdAuthenticationSession.CountryCode.EE, userIdCode);
        if (checkSum != 10) {
            return checkSum == Integer.parseInt(userIdCode.substring(10, 11));
        }

        weights = new int[]{ 3, 4, 5, 6, 7, 8, 9, 1, 2, 3 };
        checkSum = getCheckSum(weights, SmartIdAuthenticationSession.CountryCode.EE, userIdCode);

        if (checkSum == 10) {
            return checkSum == Integer.parseInt(userIdCode.substring(10, 11));
        }
        return true;
    }

    private static boolean validateCheckSumForLVIdCode(String userIdCode) {
        int[] weights = { 10, 5, 8, 4, 2, 1, 6, 3, 7, 9 };

        return getCheckSum(weights, SmartIdAuthenticationSession.CountryCode.LV, userIdCode) == Integer.parseInt(userIdCode.substring(10, 11));
    }

    private static int getCheckSum(int[] weights, SmartIdAuthenticationSession.CountryCode countryCode, String userIdCode) {
        int checkSum = 0;

        for (int i = 0; i < 10; i++) {
            checkSum += Integer.parseInt(String.valueOf(userIdCode.charAt(i))) * weights[i];
        }
        if (countryCode == SmartIdAuthenticationSession.CountryCode.LV) {
            return (checkSum + 1) % 11 % 10;
        } else {
            return checkSum % 11;
        }
    }
}
