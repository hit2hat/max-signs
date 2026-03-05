import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class MaxSignValidator {
    public static void main(String[] args) {
        // Вводные параметры
        String BOT_TOKEN = "f9LHodD0cOLD_ApRU7VcubN6ikQAy1al9LBels-EUgMpvNHlntZWquZbCJorJFjNiFHT6DXbC5Glp28-2Se5";
        String USER_LINK = "https://vk.com#WebAppData=chat%3D%257B%2522id%2522%253A108168337%252C%2522type%2522%253A%2522DIALOG%2522%257D%26ip%3D95.86.234.240%26user%3D%257B%2522id%2522%253A29935%252C%2522first_name%2522%253A%2522%25D0%25A1%25D1%2582%25D0%25B5%25D0%25BF%25D0%25B0%25D0%25BD%2522%252C%2522last_name%2522%253A%2522%25D0%259D%25D0%25BE%25D0%25B2%25D0%25BE%25D0%25B6%25D0%25B8%25D0%25BB%25D0%25BE%25D0%25B2%2522%252C%2522username%2522%253Anull%252C%2522language_code%2522%253A%2522ru%2522%252C%2522photo_url%2522%253A%2522https%253A%252F%252Fi.oneme.ru%252Fi%253Fr%253DBTGBPUwtwgYUeoFhO7rESmr8ATjjXssAxpA3VdtMXiJeDAzkqFCP2xlqrHg-KZC82Dg%2522%257D%26query_id%3D4c0ab423-342b-4e45-aea4-2747dbc500cd%26auth_date%3D1771409719%26hash%3Dd6d6887fcfef039d9b640fb55eaebda1ea348758a12e129292b90e790a362847&WebAppPlatform=web&WebAppVersion=26.2.8";

        try {
            // Извлекаем параметры платформы из хеша
            String fragment = URI.create(USER_LINK).getRawFragment();
            Map<String, String> fragmentParams = parseQueryString(fragment);
            String appData = fragmentParams.getOrDefault("WebAppData", "");
            String platform = fragmentParams.getOrDefault("WebAppPlatform", "");
            String appVersion = fragmentParams.getOrDefault("WebAppVersion", "");

            // Проверяем валидность WebAppData
            System.out.println(validateAppData(appData, BOT_TOKEN));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean validateAppData(String appData, String botToken) throws NoSuchAlgorithmException, InvalidKeyException {
        if (appData == null || appData.isEmpty()) {
            return false;
        }

        // Преобразуем appData из key1=value1&key2=value2 в [["key", "value"], ["key2", "value2"]]
        List<String[]> params = new ArrayList<>();
        String[] pairs = appData.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = pair.substring(0, idx);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                params.add(new String[]{key, value});
            }
        }

        // Находим оригинальный хеш
        String originalHash = null;
        for (String[] param : params) {
            if ("hash".equals(param[0])) {
                originalHash = param[1];
                break;
            }
        }

        // Если хеша нет, валидация невозможна
        if (originalHash == null) {
            return false;
        }

        // Сортируем параметры по алфавиту (a -> z)
        params.sort(Comparator.comparing(a -> a[0]));

        // Формируем строку для подписи с разделителем \n, обязательно исключаем hash из этой строки
        String launchParams = params.stream()
                .filter(x -> !"hash".equals(x[0]))
                .map(x -> x[0] + "=" + x[1])
                .collect(Collectors.joining("\n"));

        // Создаем специальный ключ для проверки подписи (secret_key)
        // Для этого надо подписать ваш токен бота с помощью HMAC-SHA256 используя строку "WebAppData"
        byte[] secretKeyBytes = hmacSha256("WebAppData".getBytes(StandardCharsets.UTF_8), botToken.getBytes(StandardCharsets.UTF_8));

        // Создаем подпись параметров с помощью HMAC-SHA256 используя вычисленный ключ secret_key
        byte[] signature = hmacSha256(secretKeyBytes, launchParams.getBytes(StandardCharsets.UTF_8));

        // Переводим подпись из массива байтов в hex-формат
        String hash = bytesToHex(signature);

        // Сравниваем с полученным хешем, если не совпадают — данные подменили
        return hash.equalsIgnoreCase(originalHash);
    }

    private static byte[] hmacSha256(byte[] key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(message);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static Map<String, String> parseQueryString(String query) {
        Map<String, String> queryPairs = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return queryPairs;

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");

            String key = (idx > 0)
                ? URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8)
                : URLDecoder.decode(pair, StandardCharsets.UTF_8);

            String value = (idx > 0 && pair.length() > idx + 1)
                ? URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8)
                : "";

            if (queryPairs.containsKey(key)) {
                throw new IllegalArgumentException("Duplicate parameter found: " + key);
            }

            queryPairs.put(key, value);
        }

        return queryPairs;
    }
}
