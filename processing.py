import numpy as np
import pandas as pd
import re

f = open("sshd.log", "r")           #Reading the File
logs = f.readlines()
failure = []                        #Lists
invalid = []
port = []
user = []
ip = []

for lines in logs:                  #Getting Failed Attempts
    if "Failed" in lines:
        failure.append(lines)

for lines in failure:               #Filtering Invalid User Attempts
    splitted = lines.split()        #Invalid flag at 5
    if splitted[5] == "invalid":    #user at 7 ip at 9 and port at 11 for invalid
        user.append(splitted[7])
        ip.append(splitted[9])
        port.append(splitted[11])
        invalid.append("Yes")
    else:                            #User is at index 5, ip at 7, port number at 9 for non invalid
        user.append(splitted[5])
        ip.append(splitted[7])
        port.append(splitted[9])
        invalid.append("No")

export_format = {'User': user, 'IP Address': ip, "Port Number":port, 'Is Invalid User':invalid}     #export to dataframe
export = pd.DataFrame(export_format)
export.to_csv("output.csv",index=False) #export to csv format.