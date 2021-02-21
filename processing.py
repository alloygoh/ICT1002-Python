# lib imports
import pandas as pd
from collections import Counter
# custom imports
from AttackNode import AttackNode
from analyse import requestGeoData


def process_ssh(filepath):
    f = open(filepath, "r")           #Reading the File
    logs = f.readlines()
    failure = []                        #Lists
    invalid = []
    port = []
    user = []
    ip = []
    invalid_users = []

    for lines in logs:                  #Getting Failed Attempts
        if "Failed" in lines:
            failure.append(lines)

    for lines in failure:               #Filtering Invalid User Attempts
        splitted = lines.split()        #Invalid flag at 5
        if splitted[5] == "invalid":    #user at 7 ip at 9 and port at 11 for invalid
            current_user = splitted[7]
            user.append(current_user)
            ip.append(splitted[9])
            port.append(splitted[11])
            invalid.append("Yes")
            if current_user not in invalid_users:
                invalid_users.append(current_user)
        else:                            #User is at index 5, ip at 7, port number at 9 for non invalid
            user.append(splitted[5])
            ip.append(splitted[7])
            port.append(splitted[9])
            invalid.append("No")

    AttackNodes = []
    ip_unique = set(ip)
    for i in ip_unique:
        # find first and last index
        first_seen = ip.index(i)
        last_seen = len(ip) - 1 - ip[::-1].index(i)
        targets_list = dict(Counter(user[first_seen:last_seen+1]))

        # find out which usernames not valid
        invalid_targets_list = [x for x in targets_list if x in invalid_users]

        # ignore redundant
        country,geo,_,_,_ = requestGeoData(i)
        AttackNodes.append(AttackNode(i,country,geo,targets_list,invalid_targets_list))

    return AttackNodes
    #export_format = {'User': user, 'IP Address': ip, "Port Number":port, 'Is Invalid User':invalid}     #export to dataframe
    #export = pd.DataFrame(export_format)
    #export.to_csv("output.csv",index=False) #export to csv format.
