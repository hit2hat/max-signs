package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Вводные данные
const BotToken = "f9LHodD0cOLD_ApRU7VcubN6ikQAy1al9LBels-EUgMpvNHlntZWquZbCJorJFjNiFHT6DXbC5Glp28-2Se5"
const UserLink = `https://vk.com#WebAppData=chat%3D%257B%2522id%2522%253A108168337%252C%2522type%2522%253A%2522DIALOG%2522%257D%26ip%3D95.86.234.240%26user%3D%257B%2522id%2522%253A29935%252C%2522first_name%2522%253A%2522%25D0%25A1%25D1%2582%25D0%25B5%25D0%25BF%25D0%25B0%25D0%25BD%2522%252C%2522last_name%2522%253A%2522%25D0%259D%25D0%25BE%25D0%25B2%25D0%25BE%25D0%25B6%25D0%25B8%25D0%25BB%25D0%25BE%25D0%25B2%2522%252C%2522username%2522%253Anull%252C%2522language_code%2522%253A%2522ru%2522%252C%2522photo_url%2522%253A%2522https%253A%252F%252Fi.oneme.ru%252Fi%253Fr%253DBTGBPUwtwgYUeoFhO7rESmr8ATjjXssAxpA3VdtMXiJeDAzkqFCP2xlqrHg-KZC82Dg%2522%257D%26query_id%3D4c0ab423-342b-4e45-aea4-2747dbc500cd%26auth_date%3D1771409719%26hash%3Dd6d6887fcfef039d9b640fb55eaebda1ea348758a12e129292b90e790a362847&WebAppPlatform=web&WebAppVersion=26.2.8`

func main() {
	// Ищем фрагмент в строке (данные после #)
	parts := strings.SplitN(UserLink, "#", 2)
	if len(parts) < 2 {
		panic("Invalid URL: no hash fragment found")
	}
	fragment := parts[1]

	// Разбираем параметры фрагмента вручную
	var appDataEncoded string
	fragmentParams := strings.Split(fragment, "&")
	for _, p := range fragmentParams {
        if strings.HasPrefix(p, "WebAppData=") {
            // Если значение уже было записано, значит это дубликат
            if appDataEncoded != "" {
                panic("Duplicate WebAppData parameter found")
            }
            appDataEncoded = strings.TrimPrefix(p, "WebAppData=")
        }
    }

    if appDataEncoded == "" {
        panic("WebAppData parameter not found")
    }

	// Декодируем само значение WebAppData
	appData, err := url.QueryUnescape(appDataEncoded)
	if err != nil {
		panic(err)
	}

	// Запускаем проверку
	isValid, err := ValidateAppData(appData, BotToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Print(isValid)
}

type paramPair struct {
	key   string
	value string
}

func ValidateAppData(initData, botToken string) (bool, error) {
	// Разбиваем строку по "&" на пары ключ=значение
	pairs := strings.Split(initData, "&")
	var params []paramPair
	var originalHash string

    // Перебираем параметры
	for _, pair := range pairs {
        kv := strings.SplitN(pair, "=", 2)
        if len(kv) != 2 {
            continue
        }

        key := kv[0]
        val := kv[1]

        if key == "hash" {
            // Если originalHash уже заполнен, значит встретили второй такой ключ
            if originalHash != "" {
                return false, fmt.Errorf("duplicate hash parameter found")
            }
            originalHash = val
            continue
        }

        // Производим url-декодирование
        decodedVal, err := url.QueryUnescape(val)
        if err != nil {
            return false, fmt.Errorf("failed to decode val: %v", err)
        }

        params = append(params, paramPair{key: key, value: decodedVal})
    }

    // Если hash не был найдет, то проверить подпись не получится
	if originalHash == "" {
		return false, fmt.Errorf("hash not found in initData")
	}

	// Сортируем параметры по алфавиту ключа (a -> z)
	sort.Slice(params, func(i, j int) bool {
		return params[i].key < params[j].key
	})

	// Формируем строку
	var launchParamsList []string
	for _, p := range params {
		launchParamsList = append(launchParamsList, fmt.Sprintf("%s=%s", p.key, p.value))
	}
	launchParams := strings.Join(launchParamsList, "\n")

	// Создаем специальный ключ для проверки подписи (secret_key)
    // Для этого надо подписать ваш токен бота с помощью HMAC-SHA256 используя строку "WebAppData"
	h1 := hmac.New(sha256.New, []byte("WebAppData"))
	h1.Write([]byte(botToken))
	secretKey := h1.Sum(nil)

	// Создаем подпись параметров с помощью HMAC-SHA256 используя вычисленный ключ secret_key
	h2 := hmac.New(sha256.New, secretKey)
	h2.Write([]byte(launchParams))
	signature := h2.Sum(nil)

	// c. Переводим в hex
	hash := hex.EncodeToString(signature)

	// 5. Сравниваем
	return hmac.Equal([]byte(hash), []byte(originalHash)), nil
}