#!/usr/bin/env python3
import fileinput
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

from aes_gcm import AES_GCM, InvalidTagException

current_test_parameters = {}
current_test = {}
success_count = 0
fail_count = 0

def process(line):
    global current_test
    global success_count
    global fail_count
    sline = line.strip()
    if sline.startswith("["):
        data = sline[1:-1]
        key, value = data.split("=", 1)
        current_test_parameters[key.strip()] = int(value)
    elif (sline == "" and not current_test) or line.startswith("#"):
        return
    elif sline == "" and 'count' in current_test.keys():
        errors = []
        if 'PT' not in current_test.keys():
            current_test['PT'] = ''
        test_gcm = AES_GCM(int(current_test['Key'],16))
        test_aad = b'' if (len(current_test['AAD']) == 0) else long_to_bytes(int(current_test['AAD'], 16))
        test_tag = b'' if (len(current_test['Tag']) == 0) else int(current_test['Tag'], 16)
        test_crypttext = b'' if (len(current_test['CT']) == 0) else long_to_bytes(int(current_test['CT'], 16))
        test_plaintext = b'' if (len(current_test['PT']) == 0) else long_to_bytes(int(current_test['PT'], 16))
        test_iv = int(current_test['IV'], 16)
        tag_len = int(int(current_test_parameters['Taglen']) / 8)
        try:
            computed_crypttext, computed_tag = test_gcm.encrypt(
                test_iv,
                test_plaintext,
                test_aad,
                tag_len)
        except ValueError as e:
            errors.append(e)
        if computed_tag != test_tag:
            errors.append("Tag mismatch after encryption")
        computed_plaintext = b''
        try:
            computed_plaintext = test_gcm.decrypt(
                test_iv,
                test_crypttext,
                test_tag,
                test_aad,
                tag_len)
            if computed_plaintext != test_plaintext:
                errors.append("Plaintext mismatch")
        except InvalidTagException:
            errors.append("Tag mismatch while decrypting")
        test_passed = current_test['fail'] == (len(errors) > 0)
        if not test_passed:
            fail_count += 1
            print("\n\nFailed test %s" % current_test['count'])
            print("Parameters:")
            print(current_test_parameters)
            print("Test case:")
            print(current_test)
            print(errors)
            print("Crypttext")
            print(" Test:     %s" % test_crypttext)
            print(" Computed: %s" % computed_crypttext)
            print("Plaintext")
            print(" Test:     %s" % test_plaintext)
            print(" Computed: %s" % computed_plaintext)
            print("Tags")
            print(" Test:     %s" % hex(test_tag))
            print(" Computed: %s" % hex(computed_tag))
            print("Failed: %s | Success: %s" % (fail_count, success_count))
        else:
            success_count += 1
        current_test = None
    elif line.startswith("Count ="):
        current_test = {
            'count': int(line.split("=", 1)[1]),
            'fail': False
        }
    elif " = " in line:
        name, value = line.split(" = ", 1)
        current_test[name.strip()] = value.strip()
    elif sline == "FAIL":
        current_test['fail'] = True
    else:
        print("unknown line: %s" % line)

print("Parsing")

total = 0
last = 0
for line in fileinput.input():
    process(line)
    total = success_count + fail_count
    if (total % 20) == 0 and last != total:
        print("Failed: %s | Success: %s" % (fail_count, success_count))
        last = total

print("Success: %s" % success_count)
print("Failed: %s" % fail_count)
