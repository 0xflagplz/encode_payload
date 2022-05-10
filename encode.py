import sys, os, random, string


def encrypt(originalFile, key):
    if os.path.exists(originalFile) == False:
        print("payload doesnt exist")
        exit
    payload_len = os.path.getsize(originalFile)
    if payload_len > 9500:
        print("error payload is too large")
        exit 
    #add NOP sled for ez target
    # open the payload and save
    with open(originalFile, 'rb') as pay_content:
        save = pay_content.read()
    t = "temp_infile" 
# add huge nope sled to beggining of new file
    with open(t, 'wb') as pay_content:
        pay_content.write(b"\x90"*5382)
        pay_content.write(save)
    file = open(t, 'rb')
# copy input to variable pay_content
    pay_content = file.read()
    file.close()
# delete that unwanted slave file
    os.system("rm {}".format(t))
    e = []
#encrypt using our key 
    for b in range(len(pay_content)):
        singlebyte = pay_content[b]
        for i in range(len(key)):
            singlebyte = singlebyte ^ ord(key[i])
        e.append("{:02x}".format(singlebyte))
#output in format we require
    o = "unsigned char payload[] = {"
    count = 0
    for x in e:
        if count < len(e)-1:
            o += "0x{},".format(x)
        else:
            o += "0x{}".format(x)
        count += 1
    o += "};"
    print(o)

print("Output:\n\n\n")
encrypt(sys.argv[1] , 'UsugleidIWJWHWQJYsjdhrbe3yujwhhbvdwHST2Ukwu')
print("============================")
