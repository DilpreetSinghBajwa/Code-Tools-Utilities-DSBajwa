"""Password Cracker Based on Brute Force
Pyhton3
"""
import itertools, hashlib
import string


def input_hash():
    while True:
        print("This is Password Cracker Tool based on Brute Force attack")
        print('Press "1" to crack "md5" hash password---------:')
        print('Press "2" to crack "sha1" hash password---------:')
        print('Press "3" to crack "sha224" hash password---------:')
        print('Press "4" to crack "sha256" hash password---------:')
        print('Press "5" to crack "sha384" hash password---------:')
        print('Press "6" to crack "sha512" hash password---------:')
        print('Press "7" to "Quit"---------:')
        choice = input("Enter Choice: 1 or 2 or 3 or 4 or 5 or 6 or 7:  ")
        print(choice)
        if choice == "1":
            hash_password = input("Enter md5 hash: ")
            break
        elif choice == "2":
            hash_password = input("Enter sha1 hash: ")
            break
        elif choice == "3":
            hash_password = input("Enter sha224 hash: ")
            break
        elif choice == "4":
            hash_password = input("Enter sha256 hash: ")
            break
        elif choice == "5":
            hash_password = input("Enter sha384 hash: ")
            break
        elif choice == "6":
            hash_password = input("Enter sha512 hash: ")
            break
        elif choice == "7":
            quit()

    return hash_password, choice


def password_cracker():
    flag = 0
    pass_hash, algorithm = input_hash()
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_-+=~`"
    print(chars)
    attempts = 0
    for password_length in range(1, 9):
        for guess in itertools.product(chars, repeat=password_length):
            #print(guess)
            attempts += 1
            guess = ''.join(guess)
            print(guess)
            enc_word = guess.encode('utf-8')
            if algorithm == "1":
                digest = hashlib.md5(enc_word.strip()).hexdigest()
            elif algorithm == "2":
                digest = hashlib.sha1(enc_word.strip()).hexdigest()
            elif algorithm == "3":
                digest = hashlib.sha224(enc_word.strip()).hexdigest()
            elif algorithm == "4":
                digest = hashlib.sha256(enc_word.strip()).hexdigest()
            elif algorithm == "5":
                digest = hashlib.sha384(enc_word.strip()).hexdigest()
            elif algorithm == "6":
                digest = hashlib.sha512(enc_word.strip()).hexdigest()

            #print(guess, attempts)

            # if guess == real:
            #    return 'password is {}. found in {} guesses.'.format(guess, attempts)

            if digest == pass_hash:
                print(f"Given password hash =  {pass_hash}")
                print("Digest Calculated = " + digest)
                print("Total no. of attempts= : " + str(attempts))
                print("Congratulations Hash Matched------- PASSWORD FOUND")
                print(f"Password is:  {guess} ")
                flag = 1
                break

        if flag == 1:
            break
    if flag == 0:
        print("Sorry, Password Not Found")


password_cracker()