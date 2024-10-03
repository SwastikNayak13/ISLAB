import hashlib
import random
import string
import time

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def compute_hash(algorithm, data):
    """Compute the hash of the given data using the specified algorithm."""
    if algorithm == 'md5':
        hash_object = hashlib.md5()
    elif algorithm == 'sha1':
        hash_object = hashlib.sha1()
    elif algorithm == 'sha256':
        hash_object = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash algorithm.")

    hash_object.update(data.encode())
    return hash_object.hexdigest()

def analyze_hash_performance(num_strings=100, string_length=10):
    """Analyze the performance of MD5, SHA-1, and SHA-256 hashing techniques."""
    datasets = []
    timing_results = { 'md5': [], 'sha1': [], 'sha256': [] }
    collision_results = { 'md5': set(), 'sha1': set(), 'sha256': set() }

    # Generate random strings and compute hashes
    for _ in range(num_strings):
        random_string = generate_random_string(string_length)
        datasets.append(random_string)

        # Compute MD5
        start_time = time.time()
        md5_hash = compute_hash('md5', random_string)
        elapsed_time = time.time() - start_time
        timing_results['md5'].append(elapsed_time)
        collision_results['md5'].add(md5_hash)

        # Compute SHA-1
        start_time = time.time()
        sha1_hash = compute_hash('sha1', random_string)
        elapsed_time = time.time() - start_time
        timing_results['sha1'].append(elapsed_time)
        collision_results['sha1'].add(sha1_hash)

        # Compute SHA-256
        start_time = time.time()
        sha256_hash = compute_hash('sha256', random_string)
        elapsed_time = time.time() - start_time
        timing_results['sha256'].append(elapsed_time)
        collision_results['sha256'].add(sha256_hash)

    # Analyze and print results
    for algorithm in ['md5', 'sha1', 'sha256']:
        total_time = sum(timing_results[algorithm])
        avg_time = total_time / num_strings
        collisions = num_strings - len(collision_results[algorithm])
        print(f"{algorithm.upper()} - Total Time: {total_time:.6f}s, "
              f"Average Time: {avg_time:.6f}s, Collisions: {collisions}")

if __name__ == "__main__":
    analyze_hash_performance(num_strings=100, string_length=10)

'''Explanation of the Code

    Function Definitions:
        generate_random_string(length): Generates a random string of a specified length.
        compute_hash(algorithm, data): Computes the hash of the input data using the specified algorithm (MD5, SHA-1, or SHA-256).
        analyze_hash_performance(num_strings, string_length): Main function to generate random strings, compute hashes, measure computation time, and detect collisions.

    Hashing Algorithms:
        The code uses the built-in hashlib library to compute the hash values for the strings using MD5, SHA-1, and SHA-256.

    Collision Detection:
        Collisions are detected by storing the computed hash values in a set. If the length of the set is less than the total number of strings, it indicates that collisions occurred.

    Results:
        The script prints the total time taken, average time for each hashing algorithm, and the number of collisions detected.

Running the Experiment

    Simply run the script, and it will generate 100 random strings of length 10, compute the hash values for each hashing technique, and print the performance metrics.'''