#Bibliotecas relacionadas a visualização dos dados
from inspect import classify_class_attrs
import pandas as pd
import matplotlib.pyplot as plt
from pandas.core import groupby
import seaborn as sns
import numpy as np
from sklearn import preprocessing
from sklearn.cluster import KMeans
from apyori import apriori
import math

#Libs para analise dos pacotes
from re import sub
from pcapfile import savefile
import dpkt
import binascii
from sys import argv
from py import test
import pyshark

class analizadorIE():

    #Construtor da classe. Recebe como parametro o caminho para o arquivo pcap
    def __init__(self,dataset_src):
        self.datasetName = dataset_src
        self.cap = pyshark.FileCapture(dataset_src, display_filter="wlan.fc.type_subtype==4") #Datase de pacotes
        self.pacotesProbes = [] #Armazena apenas os pacotes probes request
        self.globalLocal = { 'global': [], 'local': [], 'quantidade': () } #Distingue pacotes globais de locais
        self.dataBase = [] #Dados do banco de dados com pacotes globais e locais
        self.globalDataBase = [] #Dados do banco de dados com pacotes globais
        self.colunas = [] #Nomes das colunas do banco de dados

    #Extrai os pacotes probes do dataset
    def obter_probes(self):
        n = 0
        for rec in self.cap:
            n = n + 1
            self.pacotesProbes.append(rec)

            if n == 5000:
               break

    #Obtem o mac de um pacote
    def obterMac(self, rec):
        wlan = rec.wlan

        end = ''

        if 'sa' in wlan.field_names:
            end = wlan.sa

        return end

    #Distingue pacotes globais de locais
    def separarGlobaisLocais(self):
        for rec in self.pacotesProbes:

            mac = self.obterMac(rec)

            if mac == '':
                continue

            value = mac[1]

            if value == '2' or value == '3' or value == '6' or value == '7' or value == 'a' or value == 'b' or value == 'e' or value == 'f':
                self.globalLocal['local'].append(rec)
            
            else:
                self.globalLocal['global'].append(rec)

        quant_globais = len(self.globalLocal['global'])
        quant_locais = len(self.globalLocal['local'])

        self.globalLocal['quantidade'] = (quant_globais,quant_locais)

    #Obtem os Information Elements do pacote
    def obterIE(self, rec):
        rec_layers = rec.layers

        if ' <WLAN.MGT Layer>' not in str(rec_layers):
            return -1

        wlan_mgt = rec['wlan.mgt']
        wlan = rec.wlan    

        wlan_names = wlan_mgt.field_names
        
        data = {}

        data['MAC'] = wlan.sa
        data['time_relative'] = rec.frame_info.time_relative
        
        data['wlan_ht_capabilities']= ''
        data['wlan_ht_ampduparam'] = ''
        data['wlan_htex_capabilities'] = ''
        data['wlan_ht_mcsset'] = ''
        data['wlan_ht_mcsset_rxbitmask'] = ''
        data['wlan_ht_mcsset_rxbitmask_0to7'] = ''
        data['wlan_ht_mcsset_rxbitmask_8to15'] = ''
        data['wlan_ht_mcsset_rxbitmask_16to23'] = ''
        data['wlan_ht_mcsset_rxbitmask_24to31'] = ''
        data['wlan_ht_mcsset_rxbitmask_32'] = ''
        data['wlan_ht_mcsset_rxbitmask_33to38'] = ''
        data['wlan_ht_mcsset_rxbitmask_39to52'] = ''
        data['wlan_ht_mcsset_rxbitmask_53to76'] = ''
        data['wlan_txbf'] = ''
        data['wlan_asel_capable'] = ''
        data['wlan_tag_oui'] = ''

        for name in data:
            if name in wlan_names:
                data[name] = str(getattr(wlan_mgt,name))               

        # for name in data:
        #     print(name,": ", data[name])

        # print("--------------------------------")

        self.colunas = data.keys()

        return data.values()

    #Obtem o banco de dados a partir dos pacotes globais
    def obterBancoDados(self):

        for rec in self.globalLocal['local']:
            ie = self.obterIE(rec)

            if ie == -1:
                continue

            self.dataBase.append(ie)

        for rec in self.globalLocal['global']:
            ie = self.obterIE(rec)

            if ie == -1:
                continue

            self.dataBase.append(ie)
            self.globalDataBase.append(ie)

    #Salva em um arquivo os dados globais e locais relacionados ao dataset
    def salvarDadosGlobaisLocais(self):
        arq = open("informacoes.txt", 'w')

        arq.write("Nome do dataset: " + self.datasetName + "\n")
        arq.write("#Pacotes Globais: " + str(self.globalLocal['quantidade'][0]) + "\n")
        arq.write("#Pacotes Locais: " + str(self.globalLocal['quantidade'][1]))

        arq.close()

    #Apresenta o banco de dados obtido utilizando a lib pandas
    def exibirBancoDados(self):
        df = pd.DataFrame(self.dataBase, columns=self.colunas)

        print(df.head(10))

    #Salva o banco de dados obtido
    def salvarBancoDados(self):
        df = pd.DataFrame(self.dataBase, columns=self.colunas)
        df_global = pd.DataFrame(self.globalDataBase, columns=self.colunas)

        df.to_csv("dataBase.csv", index=False)
        df_global.to_csv("globalDataBase.csv", index=False)

    def limparBancoDados(self):
        df = pd.read_csv("./dataBase.csv")
        
        df =  df.dropna()
        
        df_clean = pd.DataFrame()

        labelencoder = preprocessing.LabelEncoder()
        #df_clean['wlan_ht_mcsset'] = labelencoder.fit_transform(df_clean['wlan_ht_mcsset'])
        df_clean['MAC'] = labelencoder.fit_transform(df['MAC'])           
        df_clean['time_relative'] = [ x for x in df['time_relative'] ]

        df_clean['wlan_ht_capabilities'] = [int(x,16) for x in df['wlan_ht_capabilities']]
        df_clean['wlan_ht_ampduparam'] = [int(x,16) for x in df['wlan_ht_ampduparam']]
        #df_clean['wlan_htex_capabilities'] = [int(x,16) for x in df'wlan_htex_capabilities']]
        #df_clean['wlan_ht_mcsset'] = [ x.split(':')[1].strip() for x in df['wlan_ht_mcsset']]
        df_clean['wlan_ht_mcsset_rxbitmask'] = [ int(x.split(' ')[9]) for x in df['wlan_ht_mcsset_rxbitmask']]
        #df_clean['wlan_ht_mcsset_rxbitmask_0to7'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_0to7']]
        #df_clean['wlan_ht_mcsset_rxbitmask_8to15'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_8to15']]
        #df_clean['wlan_ht_mcsset_rxbitmask_16to23'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_16to23']]
        #df_clean['wlan_ht_mcsset_rxbitmask_24to31'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_24to31']]
        df_clean['wlan_ht_mcsset_rxbitmask_32'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_32']]
        #df_clean['wlan_ht_mcsset_rxbitmask_33to38'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_33to38']]
        #df_clean['wlan_ht_mcsset_rxbitmask_39to52'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_39to52']]
        #df_clean['wlan_ht_mcsset_rxbitmask_53to76'] = [int(x,16) for x in df['wlan_ht_mcsset_rxbitmask_53to76']]
        df_clean['wlan_txbf'] = [int(x,16) for x in df['wlan_txbf']]

        classes = list(labelencoder.classes_)
        intervalo = range(0,len(classes))

        mapeamento = labelencoder.inverse_transform(intervalo)

        arq = open("hash.txt", 'w')

        for key,value in zip(intervalo,mapeamento):
            arq.write(str(key) + " " + str(value) + "\n")

        arq.close()

        df_clean.to_csv("cleanDataBase.csv", index=False)

    #Rotina a ser executada para novos datasets
    def exec_dataset(self):
        self.obter_probes()
        self.separarGlobaisLocais()
        self.salvarDadosGlobaisLocais()
         
        self.obterBancoDados()
        self.salvarBancoDados()
        self.limparBancoDados()

        #analizadorIE.rotinaSecundaria()
        #analizadorIE.rotinaTerciaria()
            
    #Rotina para datasets que ja tratados
    @staticmethod
    def histogramas():
        fig,ax = plt.subplots(2)
        
         # Histograma Local + Global
        df_global = pd.read_csv("dataBase.csv")
        
        tops = df_global['MAC']

        top10 = tops.value_counts().head(10)

        print(top10)

        #sns.barplot(x=top10.index,y=top10.values, ax = ax)        
        ax[0].barh(top10.index, top10.values, label='Endereços MAC Global')
        plt.xlabel('Quantidade')
        plt.ylabel('Endereço MAC')
        plt.subplots_adjust(left=0.25,right=0.98,top=0.98)
        plt.legend()
        
        #plt.show()

        # Histograma Global
        df = pd.read_csv("globalDataBase.csv")
        
        tops = df['MAC']

        top10 = tops.value_counts().head(10)

        print(top10)

        ax[1].barh(top10.index, top10.values, label='Endereços MAC Global')

        #sns.barplot(x=top10.index,y=top10.values, ax = ax)

        plt.show()       

    #Hora da brincadeira
    @staticmethod
    def kmeans():
        df = pd.read_csv("cleanDataBase.csv")

        tolerancia = 0.9
        somasInternas = []
        K = range(1,50)

        melhorK = 0

        for k in K:
            km = KMeans(n_clusters=k)
            km = km.fit(df.values)

            somainterna = km.inertia_

            somasInternas.append(somainterna)
            
            if(k == 1):
                if somainterna == 0:
                    melhorK = 1
                    break
                continue

            if(somasInternas[k-1] == 0):
                somasInternas[k-1] = somasInternas[k-2]
            
            div = somasInternas[k-2] / somasInternas[k-1]

            #print(somasInternas)

            if (div <= tolerancia):
                melhorK = k-1
                break
    
        print(f'Melhor k: {melhorK}')

        plt.plot(range(14,len(somasInternas)), somasInternas[14:], 'bx-')
        #plt.plot(range(1,len(somasInternas)+1), somasInternas, 'bx-')
        plt.xlabel('k')
        plt.ylabel('Somas Internas')
        plt.title('Método do Cotovelo para o k Ótimo')
        plt.show()

        k_means_groups = KMeans(n_clusters=melhorK).fit_predict(df.values)

        df['group'] = k_means_groups

        df = df.groupby(["group"])
        
        keys = df.groups.keys()

        for key in keys:
            df_key = df.get_group(key)

            df_key.to_csv("./kmeans_data/"+str(key)+"group.csv", index=False)

    @staticmethod
    def apriori():
        df = pd.read_csv("cleanDataBase.csv")
        df_apriori = pd.DataFrame()

        df_apriori['MAC'] = df['MAC']
        df_apriori['time_relative'] = [ math.floor(x/1000) for x in df['time_relative']]

        df_apriori = df_apriori.groupby(['time_relative'])

        keys = df_apriori.groups.keys()

        data = []

        for key in keys:
            data.append( df_apriori.get_group(key)['MAC'].values )

        #print(data)

        results = list(apriori(data, min_support=0.6,max_length=2)) 

        items = []
        supports = []

        for i in results:
            items.append(str(i.items).split('(')[1].split(')')[0])
            supports.append(i.support)
        
        fig, ax = plt.subplots()
        
        sns.barplot(x=items, y=supports,)
        
        ax.set_ylim([0,1])
        ax.set_xlabel('Items')
        ax.set_ylabel('Porcentagem')
        ax.set_title('Macs mais comprados.')

        plt.show()

if __name__ == "__main__":

    option = argv[1]

    if option == '0':
        obj = analizadorIE(argv[2])
        obj.exec_dataset()

    elif option == '1':
        analizadorIE.histogramas()

    elif option == '2':
        analizadorIE.kmeans()

    else:
        analizadorIE.apriori()