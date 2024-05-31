#!/usr/bin/python3

import zlib
import zipfile  # For working with zip files.
import time  # For timing operations.
import sys  # To access system-specific parameters and functions.


def password_found(password, count, start_time):
    """
    Prints the password found message including total attempts and cracking speed.
    """
    end_time = time.time()
    time_consumed = end_time - start_time
    print(f"[------- Password Found ---------] --> {password}")
    print(f"Passwords attempted: {count}")
    print(f"Time taken: {time_consumed:.2f} seconds")
    print(f"At {count / time_consumed:.2f} tries per second")


def main():
    """
    Attempts to crack the password of a zip file using a dictionary attack.
    Requires two command-line arguments:
    - Path to the zip file to be cracked.
    - Path to the dictionary file containing potential passwords.
    """
    # Check if the correct number of arguments are passed.
    # (script name, zip file, dictionary file.)
    if len(sys.argv) < 3:
        print("Usage: <script> zipfile dictionary")
        return

    # The first argument path to the zip file.
    zfile = sys.argv[1]
    # The second argument path to the dictionary file.
    dfile = sys.argv[2]

    try:
        filezip = zipfile.ZipFile(zfile)
    except FileNotFoundError:
        # Error handling in the case file can not be found.
        print("File not found. Double check the file paths.")
        return
    except zipfile.BadZipFile:
        # Error handling for corrupted file.
        print("Zipfile Corrupted.")
        return

    # Initialize a counter for the number of attempts made
    count = 0
    # Record the starting time.
    start_time = time.time()

    # Using 'with' statement for file handling
    with open(dfile, 'r') as passfile:
        # Iterate through each password in the dictionary file
        for line in passfile:
            # Do not include the new line character.
            password = line.strip("\n")
            # Convert the password into bytes
            codedpass = bytes(password, 'utf-8')
            # Increment the password attempt counter.
            count += 1

            # If password fails, print every 20000 attempts to display progress.
            if count % 20000 == 0:
                print(f" ** {count} Passwords Attempted **" + password)

            try:
                # Extract the zip file using the password.
                filezip.extractall(pwd=codedpass)
            except (RuntimeError, zlib.error, zipfile.BadZipFile):
                # Skip printing for each failed attempt to improve speed
                continue
            else:
                # Password found print the outputs.
                password_found(password, count, start_time)
                # Break the loop.
                break

        else:
            print(f"[-] Password not found. Attempted: {count}")


if __name__ == "__main__":
    main()
