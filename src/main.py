from enc import Person, CURVE

Alice = Person(name="Alice")
Bob = Person(name="Bob")
users = [Alice,Bob]

def find_user(user: str) -> Person | None:
    for u in users:
        if u.name.lower() == user.strip().lower():
            return u
    return None



def menu_generate_keys() -> None:
    print("\n[Генерация ключей ECC]")
    name = input("Имя пользователя: ")
    user = find_user(name)
    if user is None:
        print(f"Ошибка! Пользователь '{name}' не найден")
        return
    user.key_gens()
    print(f"[{user.name}] приватный ключ: {user.p_k_ECC}")
    print(f"[{user.name}] публчиный ключ: ({user.pub_k_ECC.x}, {user.pub_k_ECC.y})")


def menu_compute_sh() -> None:
    print("\n[Вычисление общего секрета]")
    if Alice.pub_k_ECC is None or Bob.pub_k_ECC is None:
        print("Ошибка! Сначала сгенерируйте ключи у обоих")
        return
    Alice.sh_sec_k(Bob.pub_k_ECC)
    Bob.sh_sec_k(Alice.pub_k_ECC)

    if Alice.sc_k_ECC != Bob.sc_k_ECC:
        print("Ошибка!")
        return
    print("Общий секрет вычислен успешно")
    print(f"  Секретная точка: ({Alice.sc_k_ECC.x}, {Alice.sc_k_ECC.y})")
    print(f"  AES-ключ: {Alice.k_AES}")

def menu_show_keys() -> None:
    print("\n[Текущие ключи]")
    for u in users:
        print(f"--- {u.name} ---")
        print(f"  приватный:      {u.p_k_ECC}")
        if u.pub_k_ECC is not None:
            print(f"  публичный:      ({u.pub_k_ECC.x}, {u.pub_k_ECC.y})")
        else:
            print("  публичный:      -")
        if u.sc_k_ECC is not None:
            print(f"  ({Alice.sc_k_ECC.x}, {Alice.sc_k_ECC.y})")
        print(f"  AES-ключ: {Alice.k_AES}")

def menu_encrypt() -> None:
    print("\n[Зашифровать сообщение]")
    name = input("От кого (Alice/Bob): ")
    sender = find_user(name)
    if sender is None:
        print(f"Ошибка! Пользователь '{name}' не найден")
        return
    if sender.k_AES is None:
        print(f"Ошибка! У {sender.name} нет AES-ключа! ")
        return
    text = input("Сообщение: ")
    blob = sender.encrypt_message(text)
    print(f"Зашифровано ({len(blob)} байт):")
    print(f"  {blob}")


def menu_decrypt() -> None:
    print("\n[Расшифровать сообщение]")
    name = input("Кто расшифровывает (Alice/Bob): ")
    receiver = find_user(name)
    if receiver is None:
        print(f"Ошибка! Пользователь '{name}' не найден")
        return
    if receiver.k_AES is None:
        print(f"Ошибка! У {receiver.name} нет AES-ключа")
        return
    source = next((u for u in users if u is not receiver and u.crypt_message), None)
    if source is None:
        print("Ошибка! Никто ещё не отправлял шифротекст")
        return
    try:
        plain = receiver.decrypt_message(source.crypt_message)
    except Exception as e:
        print(f"Ошибка расшифровки: {e}")
        return

    print(f"Шифротекст от {source.name} __ расшифровал {receiver.name}:")
    print(f"  {plain}")


def print_menu():
    print("\n" + "=" * 46)
    print(f"  Кривая: {CURVE.name}")
    print("=" * 46)
    print("  1. Сгенерировать ключи ECC")
    print("  2. Вычислить общий секрет")
    print("  3. Показать текущие ключи")
    print("  4. Зашифровать сообщение")
    print("  5. Расшифровать сообщение")
    print("  0. Выход")
    print("=" * 46)


def main():
    while True:
        print_menu()
        choice = input("Выбор: ").strip()

        if choice == "1":
            menu_generate_keys()
        elif choice == "2":
            menu_compute_sh()
        elif choice == "3":
            menu_show_keys()
        elif choice == "4":
            menu_encrypt()
        elif choice == "5":
            menu_decrypt()
        elif choice == "0":
            print("Выход.")
            break
        else:
            print("Неверный пункт меню. Попробуйте снова.")

main()
