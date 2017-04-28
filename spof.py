#*** TCP SYN Scan ***
from scapy.all import *
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import logging
import os.path
import sys,getopt

class AdviceMachine():
	filename="WhiteList.txt"
	log="informe.log"
	smtp="smtp.gmail.com"
	user="alex94000@gmail.com"
	passw="frende5557111"
	src="alex94000@gmail.com"
	dst="alex94000@gmail.com"

	def scanMachinesNetwork(self,iprange,interface):
		ether=Ether()
		arp=ARP()
		ether.dst='ff:ff:ff:ff:ff:ff'
		arp.pdst=iprange
		ti,resul = srp(ether/arp,iface=interface)
		mac_list= list()
		logging.info("Resultados del ARP Scanner");
		for rc,mac in ti:
			logging.info(mac.sprintf('%Ether.src% - %ARP.psrc%'))
			mac_list.append(mac.sprintf('%Ether.src%'))				
		return mac_list				

	def detecting(self,ti):
		detect=0
		contador=0
		mensaje=""
		for mac in ti:
			for mac2 in ti:
				if mac==mac2:
					contador+=1
			if contador>1:
				detect=1
				mensaje=mensaje+"\n"+str(mac)
			contador=0
		if detect==1:
			logging.info("Se han detectado las siguientes direcciones MAC duplicadas:\n");
			logging.info(mensaje)
			self.sendEmail("Detectado ataque de ARP Spoofing, con las siguientes direcciones MAC duplicadas:\n"+mensaje)	

	def readingWhiteList(self,ti):
		if not os.path.exists(self.filename):
			file=open(self.filename,'w')
			file.close()
		detect=0
		mensaje=""
		file = open(self.filename, 'r') 
		whitelist= open(self.filename,'r').read().split('\n')
		for mac in ti:
			if mac not in whitelist:
				detect=1
				mensaje=mensaje+"\n"+str(mac)
		if detect==1:
			logging.info("Las siguientes direcciones MAC se encuentran en su red LAN y no estan en la White List:")
			logging.info(mensaje)
			self.sendEmail("Las siguientes direcciones MAC se encuentran en su red LAN y no estan en la White List:\n"+mensaje)	
		file.close()

	def doingAll(self):
		opts, args = getopt.getopt(sys.argv[1:],':ir',['iprange=','iface=','smtp=','user=','pass=','src=','dst=','file=']) 
		iprange="192.168.1.0/24"
		iface="eth0"
		for opt,arg in opts:
			if opt=='--file':
				self.filename=arg
			if opt=='--iprange':
				iprange=arg
			if opt=='--iface':
				iface=arg
			if opt=='--smtp':
				self.smtp=arg
			if opt=='--user':
				self.user=arg
			if opt=='--pass':
				self.passw=arg
			if opt=='--src':
				self.src=arg
			if opt=='--dst':
				self.dst=arg
			if opt=='--log':
				self.log=arg
		self.initialize_logger('/root/Escritorio/script')
		listmac=self.scanMachinesNetwork(iprange,iface)
		self.detecting(listmac)
		self.readingWhiteList(listmac)
		print ('El analisis ha finalizado de manera correcta, puede ver los resultados en ',self.log)

	def initialize_logger(self,output_dir):
		    logger = logging.getLogger()
		    logger.setLevel(logging.DEBUG)
		     
		    # create console handler and set level to info
		    handler = logging.FileHandler(os.path.join(output_dir,self.log),"w", encoding=None, delay="true")
		    handler.setLevel(logging.INFO)
		    formatter = logging.Formatter("%(levelname)s - %(message)s")
		    handler.setFormatter(formatter)
		    logger.addHandler(handler)
 		
   
		
	def sendEmail(self,contenido):
		try:
			mailServer = smtplib.SMTP(self.smtp,587)
			mailServer.ehlo()
			mailServer.starttls()
			mailServer.ehlo()
			mailServer.login(self.src,self.passw)

			mensaje = MIMEMultipart()
			mensaje['From']=self.src
			mensaje['To']=self.passw
			mensaje['Subject']="Problema en la red"
			mensaje.attach(MIMEText(""+str(contenido)+""))

			part = MIMEApplication(open(self.log,'rb').read())
			part.add_header('Content-Disposition', 'attachment',filename=self.log)
			mensaje.attach(part)

			mailServer.sendmail(self.src,
		        self.dst,
		        mensaje.as_string())

			mailServer.close()
		except Exception as e:
			logging.exception("Problemas al conectar con el servidor SMTP")


	
if __name__ == "__main__":
	obj = AdviceMachine()
	obj.doingAll()
