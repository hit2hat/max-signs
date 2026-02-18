import hmac
import hashlib
from urllib.parse import urlparse, parse_qsl, unquote
from operator import itemgetter

# Вводные параметры
BOT_TOKEN = 'f9LHodD0cOLD_ApRU7VcubN6ikQAy1al9LBels-EUgMpvNHlntZWquZbCJorJFjNiFHT6DXbC5Glp28-2Se5'
USER_LINK = 'https://vk.com#WebAppData=chat%3D%257B%2522id%2522%253A108168337%252C%2522type%2522%253A%2522DIALOG%2522%257D%26ip%3D95.86.234.240%26user%3D%257B%2522id%2522%253A29935%252C%2522first_name%2522%253A%2522%25D0%25A1%25D1%2582%25D0%25B5%25D0%25BF%25D0%25B0%25D0%25BD%2522%252C%2522last_name%2522%253A%2522%25D0%259D%25D0%25BE%25D0%25B2%25D0%25BE%25D0%25B6%25D0%25B8%25D0%25BB%25D0%25BE%25D0%25B2%2522%252C%2522username%2522%253Anull%252C%2522language_code%2522%253A%2522ru%2522%252C%2522photo_url%2522%253A%2522https%253A%252F%252Fi.oneme.ru%252Fi%253Fr%253DBTGBPUwtwgYUeoFhO7rESmr8ATjjXssAxpA3VdtMXiJeDAzkqFCP2xlqrHg-KZC82Dg%2522%257D%26query_id%3D4c0ab423-342b-4e45-aea4-2747dbc500cd%26auth_date%3D1771409719%26hash%3Dd6d6887fcfef039d9b640fb55eaebda1ea348758a12e129292b90e790a362847&WebAppPlatform=web&WebAppVersion=26.2.8'

# Извлекаем параметры платформы из хеша URL
fragment_dict = dict(parse_qsl(urlparse(USER_LINK).fragment))
app_data = fragment_dict.get('WebAppData', '')
platform = fragment_dict.get('WebAppPlatform', '')
app_version = fragment_dict.get('WebAppVersion', '')

def validate_app_data(app_data: str, bot_token: str) -> bool:
    """
    Проверяет валидность данных Mini App с использованием HMAC-SHA256.
    """
    # Парсим строку данных (key1=value1&key2=value2...) в список кортежей.
    # parse_qsl автоматически делает url-декодирование значений.
    params = parse_qsl(app_data, keep_blank_values=True)

    # Ищем параметр hash и удаляем его из списка параметров для проверки
    original_hash = next((value for key, value in params if key == 'hash'), None)

    # Если хеш отсутствует, то сразу выдаем false, так как проверить подпись не получится
    if not original_hash:
        return False

    # Формируем список параметров без hash, сортируем по ключу (a -> z)
    params_to_sign = sorted([(k, v) for k, v in params if k != 'hash'], key=itemgetter(0))

    # Формируем строку для подписи с разделителем \n, обязательно исключаем hash из этой строки
    launch_params = '\n'.join(f'{k}={v}' for k, v in params_to_sign)

    # 1. Создаем специальный ключ для проверки подписи (secret_key)
    # Для этого надо подписать ваш токен бота с помощью HMAC-SHA256 используя строку "WebAppData"
    secret_key = hmac.new(
        key=b"WebAppData",
        msg=bot_token.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()

    # 2. Вычисляем подпись WebAppData
    # Создаем подпись параметров с помощью HMAC-SHA256 используя вычисленный ключ secret_key
    hash = hmac.new(
        key=secret_key,
        msg=launch_params.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    # Сравниваем полученный хеш с пришедшим, если не совпадают — данные подменили
    return hmac.compare_digest(hash, original_hash)

print(validate_app_data(app_data, BOT_TOKEN))
