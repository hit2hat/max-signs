// Вводные параметры
const BOT_TOKEN = 'f9LHodD0cOLD_ApRU7VcubN6ikQAy1al9LBels-EUgMpvNHlntZWquZbCJorJFjNiFHT6DXbC5Glp28-2Se5';
const USER_LINK = `https://vk.com#WebAppData=chat%3D%257B%2522id%2522%253A108168337%252C%2522type%2522%253A%2522DIALOG%2522%257D%26ip%3D95.86.234.240%26user%3D%257B%2522id%2522%253A29935%252C%2522first_name%2522%253A%2522%25D0%25A1%25D1%2582%25D0%25B5%25D0%25BF%25D0%25B0%25D0%25BD%2522%252C%2522last_name%2522%253A%2522%25D0%259D%25D0%25BE%25D0%25B2%25D0%25BE%25D0%25B6%25D0%25B8%25D0%25BB%25D0%25BE%25D0%25B2%2522%252C%2522username%2522%253Anull%252C%2522language_code%2522%253A%2522ru%2522%252C%2522photo_url%2522%253A%2522https%253A%252F%252Fi.oneme.ru%252Fi%253Fr%253DBTGBPUwtwgYUeoFhO7rESmr8ATjjXssAxpA3VdtMXiJeDAzkqFCP2xlqrHg-KZC82Dg%2522%257D%26query_id%3D4c0ab423-342b-4e45-aea4-2747dbc500cd%26auth_date%3D1771409719%26hash%3Dd6d6887fcfef039d9b640fb55eaebda1ea348758a12e129292b90e790a362847&WebAppPlatform=web&WebAppVersion=26.2.8`;

// Извлекаем параметры платформы из хеша
const hashParams = new URLSearchParams(new URL(USER_LINK).hash.slice(1));
const appData: string = hashParams.get('WebAppData') || '';
const platform: string = hashParams.get('WebAppPlatform') || '';
const appVersion: string = hashParams.get('WebAppVersion') || '';

const validateAppData = async (appData: string, botToken: string): Promise<boolean> => {
    // Преобразуем appData из key1=value1&key2=value2 в [["key", "value"], ["key2", "value2"]]
    const params: string[][] = appData.split('&').map((x) => x.split('='));

    // Если hash встречается два раза - это непредсказуемое поведение, нам следует прервать проверку
    if (params.filter((x) => x[0] === 'hash').length !== 1) {
        return false;
    }

    // Запоминаем хеш, который пришел вместе с параметрами
    const originalHash = params.find((x) => x[0] === 'hash');

    // Если хеш отсутствует, то сразу выдаем false, так как проверить подпись не получится
    if (!originalHash || typeof originalHash[1] !== 'string') {
        return false;
    }

    // Производим url-декодирование значений параметров
    for (const param of params) {
        param[1] = decodeURIComponent(param[1]);
    }

    // Сортируем параметры по названию ключа a -> z
    params.sort((a, b) => a[0].localeCompare(b[0]));

    // Формируем строку для подписи с разделителем \n, обязательно исключаем hash из этой строки
    const launchParams = params
        .filter((x) => x[0] !== 'hash')
        .map((x) => `${x[0]}=${x[1]}`)
        .join('\n');

    // Преобразуем строку для подписи и токен бота в массивы байтов
    const encoder = new TextEncoder();
    const botTokenBytes = encoder.encode(botToken);
    const launchParamsBytes = encoder.encode(launchParams);

    // Создаем специальный ключ для проверки подписи (secret_key)
    // Для этого надо подписать ваш токен бота с помощью HMAC-SHA256 используя строку "WebAppData"
    const launchParamsKeyBytes = await crypto.subtle.sign(
        'HMAC',
        await crypto.subtle.importKey(
            'raw',
            encoder.encode('WebAppData'),
            {
                name: 'HMAC',
                hash: {
                    name: 'SHA-256',
                },
            },
            false,
            ['sign'],
        ),
        botTokenBytes,
    );

    // Создаем подпись параметров с помощью HMAC-SHA256 используя вычисленный ключ secret_key
    const signature = await crypto.subtle.sign(
        'HMAC',
        await crypto.subtle.importKey(
            'raw',
            launchParamsKeyBytes,
            {
                name: 'HMAC',
                hash: {
                    name: 'SHA-256',
                },
            },
            false,
            ['sign'],
        ),
        launchParamsBytes,
    );

    // Переводим подпись из массива байтов в hex-формат
    // Здесь специально показан полифил, который не зависит от платформы
    // Если вы используете свежий рантайм, можно использовать `const hash = (new Uint8Array(signature)).toHex();`
    const hash = Array.from(new Uint8Array(signature))
        .map(b => ('00' + b.toString(16))
        .slice(-2))
        .join('');

    // Сравниваем с полученным хешем, если не совпадают — данные подменили
    return hash === originalHash[1];
};

console.log(await validateAppData(appData, BOT_TOKEN));
