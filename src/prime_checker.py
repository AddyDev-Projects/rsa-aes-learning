
"""

prime_checker.py


A custom prime number generator what generates a prime number candidate and checks if it is prime
and repeats the process untill we get a prime number.



"""




import secrets

import random

def _generate_possible_prime(bits: int=1024) -> int:

    num = secrets.randbits(bits)

    num |= (1 << bits - 1)

    num |= 1

    return num



def _check_prime(num: int, t: int = 40):

    if num < 2:

        return False
    
    elif num % 2 == 0:

        return num == 2
    


    d = num - 1

    r = 0

    while d % 2 == 0:

        d //= 2

        r += 1

    for _ in range(t):

        a = random.randint(2, num - 1)

        x = pow(a, d, num)

        if x == 1 or x == num - 1:

            continue

        for _ in range(r - 1):

            x = pow(x, 2, num)

            if x == num - 1:

                break

        else:

            return False

    return True


def generate_prime(bits: int = 1024) -> int:

    """
    
    Generates a prime number of a specified size.


    Process:

        1. Generate a candidate prime number.

        2. Check if it is prime by the Miller - Rabin prime test.

        3. If it is prime, return the value otherwise generate a new prime candidate.


    Args:

        bits (int): The number of bits in the prime number.

    
    Returns:

        int: The prime number.

    
    
    """



    while True:

        num = _generate_possible_prime()

        if _check_prime(num):

            return num

    

    