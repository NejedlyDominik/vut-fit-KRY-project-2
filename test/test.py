import sys
import string
import random
import HashTools
import subprocess


def random_strs(length=450, number=5):
    for _ in range(number):
        yield ''.join(random.choices( string.ascii_uppercase+ string.ascii_lowercase + string.digits, k=length))


def test_hash(msg_len, msg_count, secret_key=None, verify=False):
    for i, rnd_str in enumerate(random_strs(msg_len, msg_count)):
        magic = HashTools.new(algorithm="sha256")

        if secret_key is None:
            magic.update(bytes(rnd_str, "ascii"))
            res = subprocess.run(["./kry", "-c"], input=rnd_str, capture_output=True, text=True)
        else:
            magic.update(bytes(secret_key + rnd_str, "ascii"))

            if verify:
                res = subprocess.run(["./kry", "-v", "-k", secret_key, "-m", magic.hexdigest()], input=rnd_str, capture_output=True, text=True)

                if res.returncode == 0:
                    print(i, "SUCC", "Return code: ", res.returncode, res.stderr.strip())
                else:
                    print(i, "FAIL", "Return code: ", res.returncode, res.stderr.strip())

                print("------------------")
            else:
                res = subprocess.run(["./kry", "-s", "-k", secret_key], input=rnd_str, capture_output=True, text=True)
        
        if not verify:
            if magic.hexdigest() == res.stdout.strip():
                print(i, "SAME")
                print("Return code:", res.returncode, res.stderr.strip())
            else:
                print(i, "DIFF")
                print("ref:", magic.hexdigest())
                print("kry:", res.stdout.strip())
                    
            print("------------------")


def attack(msg_len, msg_count, appendix, secret_key):
    for i, rnd_str in enumerate(random_strs(msg_len, msg_count)):
        secret = bytes(secret_key, 'ascii')
        original_data = bytes(rnd_str, 'ascii')
        sig = HashTools.new(algorithm="sha256", raw=secret+original_data).hexdigest()

        append_data = bytes(appendix, "ascii")
        magic = HashTools.new("sha256")
        new_data, new_sig = magic.extension(
            secret_length=len(secret_key), original_data=original_data,
            append_data=append_data, signature=sig
            )
    
        res = subprocess.run(["./kry", "-e", "-n", f"{len(secret_key)}", "-a", appendix, "-m", sig], input=rnd_str, capture_output=True, text=True)

        ref_msg = str(new_data)[2:-1]
        adjust_msg = ref_msg[:msg_len + 4]
        counter = 0
        pad_end = len(ref_msg) - len(appendix)
        escape = False

        for j in range(msg_len + 4, pad_end):
            if counter == 0:
                if not escape:
                    if ref_msg[j] == '\\' and j + 3 < pad_end and ref_msg[j + 1] == 'x' and ref_msg[j + 2] in "0123456789abcdefABCDEF" and ref_msg[j + 3] in "0123456789abcdefABCDEF":
                        adjust_msg += ref_msg[j:j + 4]
                    elif ref_msg[j] != '\\':
                        adjust_msg += "\\x" + f"{hex(ord(ref_msg[j]))}"[2:]
                        continue
                    elif j + 1 < pad_end:
                        if ref_msg[j + 1] == 't':
                            adjust_msg += "\\x{:02x}".format(ord("\t"))
                            escape = True
                            continue
                        elif ref_msg[j + 1] == 'r':
                            adjust_msg += "\\x{:02x}".format(ord("\r"))
                            escape = True
                            continue
                        elif ref_msg[j + 1] == 'n':
                            adjust_msg += "\\x{:02x}".format(ord("\n"))
                            escape = True
                            continue
                        elif ref_msg[j + 1] == '\\':
                            adjust_msg += "\\x{:02x}".format(ord("\\"))
                            escape = True
                            continue
                else:
                    escape = False
                    continue

            counter += 1
            counter %= 4

        adjust_msg += appendix
            
        if f"{new_sig}\n{adjust_msg}" == res.stdout.strip():
            print(i, "SAME")
            print("Return code:", res.returncode, res.stderr.strip())
        else:
            print(i, "DIFF")
            print("init hash:", sig)
            print("ref:", f"{new_sig}\n{adjust_msg}")
            print("kry:", res.stdout.strip())
        print("------------------")

if __name__ == "__main__":
    test = 'hi'
    min_msg_len = 200
    max_msg_len = 210
    step = 1
    msg_count = 1
    key_length = 153
    appendix_len = 87
    
    argc = len(sys.argv)
    
    for i in range(1, argc):
        if i == 1:
            test = sys.argv[i]
        elif i == 2:
            min_msg_len = int(sys.argv[i])
        elif i == 3:
            max_msg_len = int(sys.argv[i])
        elif i == 4:
            step = int(sys.argv[i])
        elif i == 5:
            msg_count = int(sys.argv[i])
        elif i == 6:
            key_length = int(sys.argv[i])
        elif i == 7:
            appendix_len = int(sys.argv[i])

    appendix = next(random_strs(appendix_len, 1))

    if test == 'h':
        print("Hash")
        test_hash(max_msg_len, msg_count)
    elif test == 'hi':
        print("Hash")
        for msg_len in range(min_msg_len, max_msg_len, step):
            print("==================")
            print("msg length: ", msg_len)
            print("==================")
            test_hash(msg_len, msg_count)
    elif test == 'm':
        print("Mac")
        secret_key = next(random_strs(key_length, 1))
        test_hash(max_msg_len, msg_count, secret_key)
    elif test == 'mi':
        print("Mac")
        for msg_len in range(min_msg_len, max_msg_len, step):
            secret_key = next(random_strs(key_length, 1))
            print("==================")
            print("msg length: ", msg_len)
            print("==================")
            test_hash(msg_len, msg_count, secret_key)
    elif test == 'v':
        print("Verification")
        secret_key = next(random_strs(key_length, 1))
        test_hash(max_msg_len, msg_count, secret_key, True)
    elif test == 'vi':
        print("Verification")
        for msg_len in range(min_msg_len, max_msg_len, step):
            secret_key = next(random_strs(key_length, 1))
            print("==================")
            print("msg length: ", msg_len)
            print("==================")
            test_hash(msg_len, msg_count, secret_key, True)
    elif test == 'a':
        print("Attack")
        secret_key = next(random_strs(key_length, 1))
        attack(max_msg_len, msg_count, appendix, secret_key)
    elif test == 'ai':
        print("Attack")
        for msg_len in range(min_msg_len, max_msg_len, step):
            secret_key = next(random_strs(key_length, 1))
            print("==================")
            print("msg length: ", msg_len)
            print("==================")
            attack(msg_len, msg_count, appendix, secret_key)
