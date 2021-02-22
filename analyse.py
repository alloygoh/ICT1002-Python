import re
import json
from urllib.request import urlopen
import pandas as pd
import os.path

ipList, orgL, cityL, countryL, regionL = [],[],[],[],[]

def requestGeoData(ip_addr):
    try:
        print('trying: ' + ip_addr)
        response = urlopen('http://ipinfo.io/' + ip_addr + '/json')
    except:
        print('unable to connect to ipinfo.io')
        print('Trying ipwhois.app')
        try:
            response = urlopen('https://ipwhois.app/json/' + ip_addr)
        except:
            print('unable to connect to both')
            return False
    
    data = json.load(response)
    org = data['org']
    city = data['city']
    country = data['country']
    region = data['region']
    # lat,long
    try:
        geo = data['loc'].split(',')
    except:
        geo = [data['latitude'],data['longitude']]
    return country,geo,region,city,org

def exportData(filename):
    if (os.path.isfile(filename+'.csv')):
        while True:
            warn = input('\nWarning: A file with the same filename exists. Overwrite the file? [Y/N]: ').lower()
            if (warn == 'y'):
                break
            elif (warn == 'n'):
                return False
            else:
                print('Invalid input!')
    
    if not (ipList or cityL or regionL or countryL or orgL):
        while True:
            warn = input('\nWarning: One or more of the data sets are empty. Continue? [Y/N]: ').lower()
            if (warn == 'y'):
                break
            elif (warn == 'n'):
                return False
            else:
                print('Invalid input!')
    
    try:
        export_format = {'IP': ipList, 'City': cityL, 'Region': regionL, 'Country': countryL, 'Org': orgL}
        export = pd.DataFrame(export_format)
        export.to_csv(filename+'.csv',index=False)
        print('Successfully exported analysis to '+filename+'.csv')
    except:
        print('An error has occured.')
        return False
    return True
#def loadIPFromFile(filename):
#    try:
#        f = open(filename, "r")
#    except(FileNotFoundError):
#        print('\nFile not found!')
#        return
#    except:
#        print('An error has occured.')
#        return
#
#    count = 0
#    for line in f:
#        line=line.split(',')
#        if (line[1] not in ipList): #check if IP is a duplicate
#            ipList.append(line[1])
#            count += 1
#    ipList.remove('IP Address') #remove header
#    f.close()
#
#    if not ipList: #check if empty
#        print('Warning: IP list is empty.')
#    else:
#        print(str(count) + ' IP addresses added to IP list.')


#def requestGeoData():
#    if not ipList: #check if empty
#        print('IP list is empty!')
#        return
#    
#    for ip in ipList:
#        try:
#            response = urlopen('http://ipinfo.io/'+ip+'/json')
#        except:
#            print('Unable to connect to ipinfo.io')
#            return
#        
#        data = json.load(response)
#        orgL.append(data['org'])
#        cityL.append(data['city'])
#        countryL.append(data['country'])
#        regionL.append(data['region'])
#    print('Analysis has been completed.')


#while True:
#    choice = input("""\n===========================================
#                       _           _     
#     /\               | |         (_)    
#    /  \   _ __   __ _| |_   _ ___ _ ___ 
#   / /\ \ | '_ \ / _` | | | | / __| / __|
#  / ____ \| | | | (_| | | |_| \__ \ \__ \\
# /_/    \_\_| |_|\__,_|_|\__, |___/_|___/
#                          __/ |          
#                         |___/
#===========================================
#1. Load IPs from file
#2. Analyse IPs
#3. Export analysis to file
#4. Exit
#
#Choice: """)
#
#    if (choice == '1'):
#        filename = input("Enter filename of input file (including extension): ")
#        loadIPFromFile(filename)
#    elif (choice == '2'):
#        requestGeoData()
#    elif (choice == '3'):
#        filename = input("Enter filename of export file (no extension required): ")
#        exportData(filename)
#    elif (choice == '4'):
#        exit()
#    else:
#        print('Invalid choice!')