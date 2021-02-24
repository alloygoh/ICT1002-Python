from AttackNode import AttackNode
from analyse import requestGeoData

def get_user(index,ip,Logs):
    usern = ""
    y = 1
    while usern == "":
        try: #x[9] might not exist
            x = Logs[index - y].split()
            if x[9] != "USER":
                y += 1
            else:
                if ip not in x[8]: #check if the log line is not related to same ip
                    y += 1
                    continue
                else:
                    usern = x[10]
                    return usern
        except:
            y += 1 #line does not contain "USER", carry on search
            continue
def process_ftp(filepath):
    f = open("resource/FileZilla Server.log", "rb")           #Reading the File (binary cause char formatting issue)
    log = f.readlines()
    encoding = 'utf-8'
    strlogs = []                                               #placeholder for binary to str conversion
    Logs = []                                                  #str version of list
    timestamp = []                                             #store timestamp
    user = []                                                  #store user
    ip = []                                                    #store ip address
    errortype = []                                             #store msg type
    for lines in log:                                          #converting from read binary to read utf-8
        try:
            strlogs.append(lines.decode(encoding))
        except:
            continue

    for lines in strlogs:                                      #Filtering out junk info
        if lines.startswith("("):
            Logs.append(lines)

    for index, lines in enumerate(Logs):                        #enumerated so the index can retrieve username
        splitted = lines.split()
        if splitted[5] == "(not":                               #not logged
            try:
                if splitted[9] == "500":                        #invalid syntax error code - garbage unicode spam
                    timestamp.append(splitted[1] + ' ' + splitted[2] + ' ' + splitted[3])       #timestamp
                    user.append("UNSPECIFIED")                                                  #user
                    ipaddr = splitted[8].split(")")                                             #change ipp addr from
                    ip.append(ipaddr[0][1:])                                                    #(xx.xx.xx.xx)> to xx format
                    errortype.append("Suspicious Unicode input")                                #error type

                if splitted[9] == "530" and splitted[10] == "Login":                            #failed logins                                             #fail login has user
                    timestamp.append(splitted[1] + ' ' + splitted[2] + ' ' + splitted[3])       #3 lines before
                    ipaddr = splitted[8].split(")")
                    ip.append(ipaddr[0][1:])
                    user.append(get_user(index,ip[-1],Logs))
                    errortype.append("Login Attempt (Failed)")

                if ('NOOP' in splitted):                                                        #NOOP command can be sent by clients during idle time in order to keep connection alive
                    timestamp.append(splitted[1] + ' ' + splitted[2] + ' ' + splitted[3])
                    user.append("UNSPECIFIED")
                    ipaddr = splitted[8].split(")")
                    ip.append(ipaddr[0][1:])
                    errortype.append("Suspicious NOOP command - Connection keep-alive attempt")

                if ('CONNECT' in splitted or 'HOST' in splitted):                               #Invalid connection commands, possible RCE
                    timestamp.append(splitted[1] + ' ' + splitted[2] + ' ' + splitted[3])
                    user.append("UNSPECIFIED")
                    ipaddr = splitted[8].split(")")
                    ip.append(ipaddr[0][1:])
                    errortype.append("Suspicious CONNECT command - Possible RCE attack")

            except:                                                                             #there are lines wif no [9]
                continue

        elif splitted[7] == "230":  # logged in, user at 5, ip at 6, 7, id msg 230              #successful login
            timestamp.append(splitted[1] + ' ' + splitted[2] + ' ' + splitted[3])
            user.append(splitted[5])
            ipaddr = splitted[6].split(")")
            ip.append(ipaddr[0][1:])
            errortype.append("Login Attempt (Success)")

    #Setting up Attack Nodes
    AttackNodes = []
    unique_ip = sorted(set(ip))
    userList = []

    #REMOVE LOCAL ADDRESSES
    ipToRemove = []
    unique_ip.remove('127.0.0.1')
    for ip1 in unique_ip:
        if (ip1[0:7] == '192.168'):
            ipToRemove.append(ip1)
    for ip2 in ipToRemove:
        unique_ip.remove(ip2)

    #GETTING TARGETS
    for ipaddr in unique_ip:
        try:
            country,geo,_,_,_ = requestGeoData(ipaddr)
        except:
            country,geo,_,_,_ = 'placeholder','placeholder','','','' #in case unable to connect to ipinfo.io
        for i in range(len(ip)):
            if (ip[i] == ipaddr):
                if (user[i] not in userList):
                   userList.append(user[i]) #GETTING UNIQUE USERS PER IP
        #if ("UNSPECIFIED" in userList):
        #    userList.remove("UNSPECIFIED") #IRRELEVANT TO CHECK FOR BRUTEFORCE
       #print(f"{ipaddr}: {userList}")

        countList = []
        for i in userList:
            count = 0
            for j in range(len(user)):
                if (i == user[j] and ipaddr == ip[j]): #GETTING COUNT OF EACH USER
                    count += 1
            countList.append(count)
        #print(f"{userList} {countList}")

        errorList = [] #Error dict for AttackNode
        for i in range(len(errortype)):
            if (ipaddr == ip[i]):
                errorList.append(errortype[i])
        errorDict = {'success':0, 'fail':0, 'unicode':0, 'noop':0, 'connect':0}
        for error in errorList:
            if (error == "Login Attempt (Success)"):
                errorDict['success'] += 1
            elif (error == "Login Attempt (Failed)"):
                errorDict['fail'] += 1
            elif (error == "Suspicious Unicode input"):
                errorDict['unicode'] += 1
            elif (error == "Suspicious NOOP command - Connection keep-alive attempt"):
                errorDict['noop'] += 1
            else:
                errorDict['connect'] += 1
        #print(errorDict,end='')

        targets = {userList[i]:countList[i] for i in range(len(userList))}
        invalid_targets = []

        AttackNodes.append(AttackNode(ipaddr,country,geo,targets,invalid_targets,errorDict))
        userList.clear()
        errorList.clear()

    for n in AttackNodes:
        # run and apply sigs
        n.run_sigs(ftp=True)
    
    AttackNodes = [ n for n in AttackNodes if bool(n.attacks)]
    return AttackNodes

    #export_format = {'Timestamp': timestamp, 'User': user, "Ip Address":ip,
    #                 'Log Type': errortype}     #export to dataframe
    #export = pd.DataFrame(export_format)
    #export.to_csv("output.csv",index=False) #export to csv format.