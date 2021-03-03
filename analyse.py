import json
from urllib.request import urlopen

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

#def exportData(filename):
#    if (os.path.isfile(filename+'.csv')):
#        while True:
#            warn = input('\nWarning: A file with the same filename exists. Overwrite the file? [Y/N]: ').lower()
#            if (warn == 'y'):
#                break
#            elif (warn == 'n'):
#                return False
#            else:
#                print('Invalid input!')
#    
#    if not (ipList or cityL or regionL or countryL or orgL):
#        while True:
#            warn = input('\nWarning: One or more of the data sets are empty. Continue? [Y/N]: ').lower()
#            if (warn == 'y'):
#                break
#            elif (warn == 'n'):
#                return False
#            else:
#                print('Invalid input!')
#    
#    try:
#        export_format = {'IP': ipList, 'City': cityL, 'Region': regionL, 'Country': countryL, 'Org': orgL}
#        export = pd.DataFrame(export_format)
#        export.to_csv(filename+'.csv',index=False)
#        print('Successfully exported analysis to '+filename+'.csv')
#    except:
#        print('An error has occured.')
#        return False
#    return True