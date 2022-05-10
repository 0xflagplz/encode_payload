int unobfus(unsigned char payload[])
{
    std::string key;
    // use the same key as in payload
    key = "UsugleidIWJWHWQJYsjdhrbe3yujwhhbvdwHST2Ukwu";
    for (int i = 0; i < payload_len; i++)
    {
        char d = payload[i];
        for (int z = 0; z < key.length(); z++)
        {
            d = d ^ (int)key[z];
        }
        sense[i] = d;
    }
    return 0;
}