import hashlib

def crack_sha1_hash(hash, use_salts = False):
    try:
        # Open file with known PWs
        known_pws = open("top-10000-passwords.txt")
        # Salts File is opened as its own variable so it can be safely closed
        salts_file = open("known-salts.txt")
        known_salts = (salts_file.read()).split("\n")
        salts_file.close()
        for pw in known_pws:
            # Remove \n characters and whitespace from each line
            pw = pw.rstrip()
            if use_salts:
                if compare_salted_hash_to_pw(hash,known_salts,pw):
                    # Return cracked PW on successful comparison
                    return pw
                else:
                    # If the PW doesn't match continue the loop
                    continue
            else:
                if compare_hash_to_pw(hash,pw):
                    return pw
                else:
                    # If the PW doesn't match continue the loop
                    continue
        return "PASSWORD NOT IN DATABASE"
    except OSError as error:
        print(f"{error} \n")
    finally:
        # Ensure we close open files
        if not salts_file.closed:
            salts_file.close()
        known_pws.close()

# Return True if we found a match to the hash, false if no match found
def compare_hash_to_pw(hash:str, pw:str):
    # Enconde the PW to an acceptable string
    hash_obj = hashlib.sha1(pw.encode('ascii'))
    pw_hash = hash_obj.hexdigest()
    return hash == pw_hash

# Return True if we found a match to the hash, false if no match found
def compare_salted_hash_to_pw(hash:str,salts:list,pw:str):
    for salt in salts:
        salted_pw_pre = salt + pw
        salted_pw_append = pw + salt
        # Enconde the PWs to an acceptable string
        salted_pw_hash_pre = hashlib.sha1(salted_pw_pre.encode("ascii")).hexdigest()
        salted_pw_hash_append = hashlib.sha1(salted_pw_append.encode("ascii")).hexdigest()
        # Check salts appened to PW or prepended to PW
        if salted_pw_hash_append == hash:
            return True
        elif salted_pw_hash_pre == hash:
            return True
        else:
            continue
    return False