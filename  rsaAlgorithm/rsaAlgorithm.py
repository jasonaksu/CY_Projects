import random
from sympy import randprime
from math import gcd
import time


def find_mod_inverse(n, modulus):
    """
    This function finds the modular inverse of a number under modulo modulus.
    This function is used in RSA algorithm to find the multiplicative inverse in modular arithmetic.

    :param n: int. The number to find the inverse of.
    :param modulus: int. The modulus value.
    :return: The modular inverse of n under modulus.
    """
    original_modulus, x0, x1 = modulus, 0, 1
    while n > 1:
        # Compute quotient
        quotient = n // modulus
        # Update modulus and n
        modulus, n = n % modulus, modulus
        # Update x0 and x1
        x0, x1 = x1 - quotient * x0, x0

    # Ensure the result is positive
    return x1 + original_modulus if x1 < 0 else x1


def generate_rsa_keys(bit_size):
    """
    This function generates RSA public and private keys of the specified bit size.

    :param bit_size: int. The bit size for the prime numbers.
    :return: tuple. The public key, private key, and the time taken to generate keys.
    """
    # Record start time for key generation
    start_time = time.time()

    # Generate two distinct large prime numbers
    prime_1 = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    prime_2 = randprime(2 ** (bit_size - 1), 2 ** bit_size)

    # Compute the modulus n
    modulus_n = prime_1 * prime_2
    # Calculate Euler's totient function
    totient_phi = (prime_1 - 1) * (prime_2 - 1)

    # Choose public exponent e such that 1 < e < phi and gcd(e, phi) = 1
    public_exp_e = random.randrange(2, totient_phi - 1)
    while gcd(public_exp_e, totient_phi) != 1:
        public_exp_e = random.randrange(2, totient_phi - 1)

    # Compute the private exponent d, the modular inverse of e mod phi
    private_exp_d = find_mod_inverse(public_exp_e, totient_phi)

    # Record the end time for key generation
    end_time = time.time()
    # Calculate time taken
    key_generation_time = end_time - start_time
    print("Key generation time is: ", key_generation_time)

    # Return the public key, private key, and generation time
    return (public_exp_e, modulus_n), (private_exp_d, modulus_n), key_generation_time


def encrypt(plaintext, public_key):
    """
    This function encrypts the plaintext using the public key.

    :param plaintext: str. The message to be encrypted.
    :param public_key: tuple. The public key (e, n).
    :return: tuple. The encrypted message as a list of integers and the time taken to encrypt.
    """
    # Record the start time for encryption
    start_time = time.time()
    # Unpack the public key into exponent e and modulus n
    public_exp_e, modulus_n = public_key
    # Encrypt the message
    ciphertext = [pow(ord(char), public_exp_e, modulus_n) for char in plaintext]
    # Record the end time for encryption
    end_time = time.time()
    # Print the encryption time
    print("Encryption time is: ", end_time - start_time)
    # Return the encrypted message and time.
    return ciphertext, end_time - start_time


def decrypt(ciphertext, private_key):
    """
    This function decrypts the ciphertext using the private key.

    :param ciphertext: list. The encrypted message as a list of integers.
    :param private_key: tuple. The private key (d, n).
    :return: tuple. The decrypted message as a string and the time taken to decrypt.
    """
    # Record the start time for decryption
    start_time = time.time()
    # Unpack the private key into exponent d and modulus n
    private_exp_d, modulus_n = private_key
    # Decrypt the message
    plaintext = [chr(pow(char, private_exp_d, modulus_n)) for char in ciphertext]
    # Record the end time for decryption
    end_time = time.time()
    # Print the decryption time
    print("Decryption time is: ", end_time - start_time)
    # Return the decrypted message as a string and time
    return ''.join(plaintext), end_time - start_time


def main():
    """
    Main function to generate RSA keys, encrypt and decrypt messages based on user input.
    """
    # Prompt user to get bit size for key generation
    bit_size = int(input("Please enter the bit size (e.g., 8, 16, 32 or higher): "))
    # Generate the RSA keys and generation time
    public_key, private_key, key_generation_time = generate_rsa_keys(bit_size)

    # Display RSA Keys and time taken
    print(f"Your public key is: {public_key}")
    print(f"Your private key is: {private_key}")
    print(f"Key generation time is: {key_generation_time:.4f} seconds")

    while True:
        # Get user choice
        user_choice = input("Would you like to encrypt, decrypt, or exit? (e/d/x): ").lower().strip()
        if user_choice == "e":
            message = input("Enter the message (plaintext) to encrypt or type 'x' to exit: ").strip()
            # Exit the program if user enters 'x'
            if message.lower() == 'x':
                print("Exiting the program.")
                break
            else:
                # Encrypt the message
                ciphertext, encryption_time = encrypt(message, public_key)
                # Print the encrypted message and time taken
                print(f"Encrypted message: {ciphertext}")
                print(f"Encryption time is: {encryption_time:.4f} seconds")
        # Prompt user to enter ciphertext if they want to decrypt
        elif user_choice == "d":
            ciphertext_input = input(
                "Enter the message (ciphertext) to decrypt (e.g., [1234, 2345, 3456]) or type 'x' to exit: ").strip()
            # Exit the program if user enters 'x'
            if ciphertext_input.lower() == 'x':
                print("Exiting the program.")
                break
            else:
                try:
                    # Convert ciphertext to list of integers
                    ciphertext = eval(ciphertext_input)
                    # Decrypt the message
                    plaintext, decryption_time = decrypt(ciphertext, private_key)
                    # Print the decrypted message and time taken
                    print(f"Decrypted message: {plaintext}")
                    print(f"Decryption time is: {decryption_time:.4f} seconds")
                except (SyntaxError, ValueError):
                    print("Invalid ciphertext format. Please try again.")
        # Exit the program if choose "x"
        elif user_choice == "x":
            print("Exiting the program.")
            break
        else:
            # Invalid choice message
            print("Invalid choice. Please choose 'encrypt (e)', 'decrypt (d)', or 'exit (x)'.")


if __name__ == "__main__":
    main()
