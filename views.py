from django.shortcuts import render

# Create your views here.

import user from models.py

def get_xcsrf(request):
    data = {
        'X-CSRFToken': get_token(request)
    }
    return JsonResponse(data, safe=False, status=200)

def generate_token(user, salt: str):

    if salt == 'api_access':
        payload = {
            'id_user': user.pk_user
        }
    elif salt == 'activation':
        payload = {
            'id_user': user.pk_user,
            'email': user.email
        }

    elif salt == 'passwd_reset':
        payload = {
            'id_user': user.pk_user,
            'passwd': user.passwd
        }

    
    elif salt == 'email_change':
        payload = {
            'id_user': user.pk_user,
            'old_mail': user.email,
        }

    else:
        # Если соль неизвестна, сразу возвращаем None (защита от падения)
        return None
    signer = TimestampSigner(salt=salt)
    return signer.sign_object(payload, compress=True) # флаг compress=True включает сжатие и криптографическое ШИФРОВАНИЕ данных, полностью скрывая их


def get_user(token: str, salt: str):

    if salt == 'api_access':
        max_age = 900  # 15 минут
    elif salt == 'activation':
        max_age = 86400  # 1 день
    elif salt == 'passwd_reset':
        max_age = 3600 # 1 час
    elif salt == 'email_reset':
        max_age = 3600 # 1 час
    else:
        return None

    signer = TimestampSigner(salt=salt)
    try:
        payload = signer.unsign_object(token, max_age=max_age)
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None

    #Извлекаем ID пользователя из успешно расшифрованного payload
    id_user = payload.get('id_user')
    if not id_user:
        return None

    #Ищем пользователя в базе данных
    user = User.objects.filter(pk_user=id_user).first()
    if not user:
        return None

    #Дополнительные специфичные проверки для разных сценариев
    if salt == 'api_access':
        # Для обычного доступа достаточно, чтобы юзер просто существовал и был активен
        if not user.is_active:
            return None
        return user

    elif salt == 'activation':
        # Проверяем, что email в токене совпадает с email пользователя
        token_email = payload.get('email')
        if user.email != token_email:
            return None
        return user

    elif salt == 'passwd_reset':
        # Проверяем, что email в токене совпадает с email пользователя
        token_passwd = payload.get('passwd')
        if user.passwd != token_passwd:
            return None
        return user
    
    elif salt == 'email_change':
        # Проверяем, что email в токене совпадает с email пользователя
        token_email_change = payload.get('email')
        if user.email != token_email_change:
            return None
        return user

    return None

def main(request):
    template = 'index.html'
    context = {}
    return render(request, template, context)