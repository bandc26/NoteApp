from collections import Counter

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using the Caesar cipher."""
    result = []

    for ch in text:
        if ch.isupper():
            result.append(
                chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
            )
        elif ch.islower():
            result.append(
                chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
            )
        else:
            result.append(ch)

    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt a Caesar cipher by reversing the shift."""
    return caesar_encrypt(text, -shift)


def frequency_analysis(ciphertext: str) -> Counter:
    """Count the frequency of each letter in the ciphertext."""
    letters = [
        ch.lower()
        for ch in ciphertext
        if ch.isalpha()
    ]

    return Counter(letters)


def crack_caesar_by_frequency(ciphertext: str) -> tuple[int, str]:
    """
    Crack a Caesar cipher using frequency analysis.

    We assume that the most frequent letter in the ciphertext
    corresponds to the letter 'e' in English.
    """
    frequencies = frequency_analysis(ciphertext)

    if not frequencies:
        print("No alphabet characters in ciphertext!")
        return 0, ciphertext

    print("Letter frequencies:")
    for letter, count in frequencies.most_common():
        print(f"{letter}: {count}")

    most_common_letter = frequencies.most_common(1)[0][0]

    guessed_shift = (
        ord(most_common_letter) - ord('e')
    ) % 26

    plaintext = caesar_decrypt(ciphertext, guessed_shift)

    print("\nMost common letter:", most_common_letter)
    print("Guessed key:", guessed_shift)

    print("\nDecrypted message:")
    print(plaintext)

    return guessed_shift, plaintext


if __name__ == "__main__":
    original_message = (
        "This is a secret message for the computer security lab. "
        "The Caesar cipher is simple and easy to break using "
        "frequency analysis because common English letters reveal "
        "the structure of the encrypted message."
    )

    secret_key = 7

    ciphertext = caesar_encrypt(original_message, secret_key)

    print("Original message:")
    print(original_message)

    print("\nCaesar ciphertext:")
    print(ciphertext)

    print("\nCracking without knowing the key...")

    guessed_key, cracked_message = crack_caesar_by_frequency(
        ciphertext
    )

    print("\nOriginal key:", secret_key)
    print("Guessed key:", guessed_key)

    if cracked_message == original_message:
        print("\nSUCCESS: Caesar cipher cracked successfully!")
    else:
        print("\nThe frequency analysis did not recover the exact plaintext.")