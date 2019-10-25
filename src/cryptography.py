####
# REDES 2 - PRACTICA 2
# FICHERO: securebox_crypto.py
# AUTORES:
#	* Carlos Luis Hojas Garcia-Plaza
#	* Sergio Cordero Rojas
# DESCRIPCION: Fichero con las funciones necesarias para encriptar
####

#import securebox_files as files
from src import *
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from Crypto.Signature import pkcs1_15
# from Crypto.Util import Padding
# from Crypto.Signature import pkcs1_15



# Constantes que definen ciertas longitudes (en bytes)

IVLEN = 16 # Longitud del IV
RSALEN = 256 # Longitud del mensaje cifrado con RSA
AESCLEN = 32 # Longitud de la clave de AES
directorio_archivos = "./files" # Directorio de archivos
directorio_archivos_firmados = "./files/signed" # Directorio de archivos firmados
directorio_archivos_encriptados = "./files/encrypted"

#
#
# Funcion crear_firma
# Dado un mensaje devuelve la firma asociada al mismo
# mensaje: mensaje que queremos firmar
# Return: firma del mensaje
#
def crear_firma(mensaje):

	#Obtenemos el hash SHA256 a partir de nuestro mensaje
	hash = SHA256.new(mensaje)

	#Obtenemos la clave privada del archivo correspondiente
	try:
		clave_privada = RSA.import_key(open("./key/private_key.dat").read())
	except FileNotFoundError:
		print("ERROR abriendo archivo de clave privada")
		return None

	#Obtenemos la firma encriptando por RSA (usando la clave privada) el hash obtenido
	firma = pkcs1_15.new(clave_privada).sign(hash)
	return firma

#
#
# Funcion firmar_mensaje
# Dado un mensaje devuelve su firma unida al propio mensaje
# mensaje: mensaje que queremos firmar
# Return: devuelve la firma concatenada al mensaje
#
def firmar_mensaje(mensaje):
	firma_creada= crear_firma(mensaje)
	if firma_creada == None:
		return None
	return  firma_creada + mensaje



#
#
# Funcion firmar_archivo
# Firma un fichero
# archivo: el fichero que vamos a firmar
# Return: crea el fichero firmado sin devolver nada o devuelve none en caso de error
#
def firmar_archivo(archivo):

	print("-> Firmando fichero...")


	#Abrimos el archivo, tratando la exepcion en caso de error
	try:
		with open(archivo, "rb") as descriptor:
			mensaje = descriptor.read()
	except FileNotFoundError:
		print("ERROR abriendo archivo")
		return None

	#TODO: comentar en readme.txt
	#Damos por hecho que los directorios /files y /files/encrypted estan creados

	#Creamos la ruta donde vamos a guardar el fichero donde ademas, guardamos la firma
	ruta = "{}/{}".format(directorio_archivos_firmados, os.path.basename(archivo))

	# Si no existe el directorio donde guardamos los archivos firmados, lo creamos
	if os.path.exists(directorio_archivos_firmados) == False:
		os.mkdir(directorio_archivos_firmados)

	with open(ruta , "wb") as descriptor:
		mensaje_firm = firmar_mensaje(mensaje)
		if mensaje_firm == None:
			return None
		descriptor.write(mensaje_firm)

	print("OK, archivo firmado")

	return

#
#
# Funcion crear_sobre_digital
#
# ID: id del receptor del fichero que estamos enviando
# clave_AES: clave usada por AES, la cual cifraremos mediante RSA
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: el sobre digital, es decir, la clave cifrada
#
def crear_sobre_digital(ID_destino, clave_AES, token):

	print("-> Recuperando clave publica de ID {}...".format(ID_destino))
	clave_auxiliar = users.buscar_clave_publica(ID_destino, token)

	# Si falla la busqueda de la clave retornamos None
	if clave_auxiliar == None:
		print("ERROR buscando clave")
		return None

	#Usamos el resultado de la busqueda como clave RSA
	clave_publica = RSA.import_key(clave_auxiliar)

	print("OK, sobre digital creado.")

	return PKCS1_OAEP.new(clave_publica).encrypt(clave_AES)


#
#
# Funcion encriptarAES
# Encripta un mensaje en modo simetrico
# mensaje: mensaje que queremos encriptar
# clave: la clave que va a utilizar AES para realizar el cifrado, que tiene que ser de 32 bytes por especificacion del enunciado
# iv: vector de inicializacion utilizado por el metodo de encriptacion AES.
# Return: devuelve el iv concatenado con el mensaje cifrado
#
def encriptarAES(mensaje, clave, iv):

	# Ajustamos el mensaje a 16 bytes
	mensaje = Padding.pad(mensaje, 16)

	# Devolvemos el vector de inicializacion unido con el mensaje encriptado
	return AES.new(clave, AES.MODE_CBC, iv).encrypt(mensaje)

#
#
# Funcion encriptar_mensaje
# Encripta un mensaje en modo simetrico
# ID: id del receptor del mensaje
# mensaje: mensaje que queremos encriptar
# Return: devuelve el iv concatenado con el mensaje cifrado
#
def encriptar_mensaje(ID_destino, mensaje, token):

	clave = get_random_bytes(AESCLEN)

	sobre = crear_sobre_digital(ID_destino, clave, token)

	if sobre == None:
		print("ERROR encriptando mensaje")
		return None

	# Generamos el vector de inicializacion para encriptar con AES
	vector_inicializacion = get_random_bytes(IVLEN)

	mensaje_cifrado = encriptarAES(mensaje, clave, vector_inicializacion)

	return vector_inicializacion+sobre+mensaje_cifrado

#
#
# Funcion encriptar_archivo
# Encripta el archivo pasado por argumento en modo simetrico
# ID_destino: id del receptor del mensaje
# archivo: mensaje que queremos encriptar
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: devuelve la ruta del archivo encriptado o None en caso de error
#
def encriptar_archivo(ID_destino, archivo, token):

	print("-> Cifrando fichero...")


	#Abrimos el archivo, tratando la exepcion en caso de error
	try:
		with open(archivo, "rb") as descriptor:
			mensaje = descriptor.read()
			print(mensaje)

	except FileNotFoundError:
		print("ERROR abriendo archivo")
		return None

	#Creamos el path de destino del archivo, donde guardamos el sobre digital + mensaje cifrado
	ruta = "{}/{}".format(directorio_archivos_encriptados, os.path.basename(archivo))

	# Si no existe el directorio donde guardamos los archivos encriptados, lo creamos
	if os.path.exists(directorio_archivos_encriptados) == False:
		os.mkdir(directorio_archivos_encriptados)

	with open(ruta , "wb") as descriptor:
		enc_mensaje = encriptar_mensaje(ID_destino, mensaje, token)
		if enc_mensaje == None:
			print("Error encriptando fichero")
			return None
		descriptor.write(enc_mensaje)
	print("OK, fichero encriptado.")

	return ruta


#
#
# Funcion firmar_y_encriptar_mensaje
# Firma y encripta el mensaje pasado por argumento y crea el sobre digital
# ID: id del receptor del mensaje
# archivo: mensaje que queremos encriptar
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: None en caso de error, el mensaje completamente firmado y cifrado en caso de exito
#
def firmar_y_encriptar_mensaje(ID_destino, mensaje, token):

	print("Firmando fichero...")

	#Firmamos y encriptamos el mensaje con las funciones previamente creadas
	mensaje_cifrado = encriptar_mensaje(ID_destino, firmar_mensaje(mensaje), token)

	#Si hay algun fallo devolvemos None
	if mensaje_cifrado == None:
		print("ERROR cifrando mensaje")
		return None

	#Si todo va bien imprimimos OK y devolvemos el mensaje
	print("OK, mensaje firmado y encriptado")
	return mensaje_cifrado


#
#
# Funcion firmar_y_encriptar_archivo
# Firma y encripta completamente el archivo pasado por argumento
# ID: id del receptor del mensaje
# archivo: archivo que queremos encriptar
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: None en caso de error, la ruta del archivo encriptado en caso de exito
#
def firmar_y_encriptar_archivo(ID_destino, archivo, token):

	print("-> Cifrando fichero...")


	#Abrimos el archivo, tratando la exepcion en caso de error
	try:
		with open(archivo, "rb") as descriptor:
			mensaje = descriptor.read()

	except FileNotFoundError:
		print("ERROR abriendo archivo")
		return None

	#Creamos el path de destino del archivo, donde guardamos el sobre digital + mensaje cifrado
	ruta = "{}/{}".format(directorio_archivos_encriptados, os.path.basename(archivo))

	# Si no existe el directorio donde guardamos la clave, lo creamos
	if os.path.exists(directorio_archivos_encriptados) == False:
		os.mkdir(directorio_archivos_encriptados)

	with open(ruta , "wb") as descriptor:
		enc_sign_mensaje = firmar_y_encriptar_mensaje(ID_destino, mensaje, token)
		if enc_sign_mensaje == None:
			print("Error encriptando fichero")
			return None
		descriptor.write(enc_sign_mensaje)

	print("OK, fichero firmado y encriptado")

	return ruta

#
#
# Funcion descifrar_sobre_digital
# descifra (mediante RSA) la clave que pasamos como argumento y que usaremos en AES
# clave_cifrada: clave que queremos descifrar
# Return: la clave descifrado
#
def descifrar_sobre_digital(clave_cifrada):

	clave_privada = RSA.import_key(open("./key/private_key.dat", "r").read())

	return PKCS1_OAEP.new(clave_privada).decrypt(clave_cifrada)

#
#
# Funcion desencriptarAES
# desencripta el mensaje cifrado mediante AES en modo cbc
# claveAES: la clave usada por AES para desencriptar
# vector_inicializacion: el vector de inicializacion, necesario con AES
# mensaje_cifrado: mensaje a descifrar
# Return: el mensaje desencriptado
#
def desencriptarAES(claveAES, vector_inicializacion, mensaje_cifrado):

	return Padding.unpad(AES.new(claveAES, AES.MODE_CBC, vector_inicializacion).decrypt(mensaje_cifrado), 16)


#
#
# Funcion comprobar_firma
# funcion que se encarga de comprobar si la firma recibida es correcta
# firma: firma recibida y que queremos comprobar si es buena
# mensaje: mensaje del que queremos comprobar la firma
# ID: id del emisor del mensaje que acabamos de recibir
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: None en caso de error, true en caso de que la firma sea valida y false en caso
# 		de que no sea valida
#
def comprobar_firma(firma, mensaje, ID_origen, token):

	print("Verificando firma...")

	clave_auxiliar = users.buscar_clave_publica(ID_origen, token)

	if clave_auxiliar == None:
		print("ERROR buscando clave")
		return None

	clave_publica = RSA.import_key(clave_auxiliar)


	try:
		pkcs1_15.new(clave_publica).verify(SHA256.new(mensaje), firma)
	except (ValueError, TypeError):
		print("ERROR verificando firma")
		return False

	print("OK, firma comprobada")

	return True

#
#
# Funcion desencriptar_mensaje
# funcion que desencripta completamente el mensaje recibido
# ID: id del emisor del mensaje que acabamos de recibir
# mensaje_cifrado: mensaje que queremos descifrar
# token: necesario para poder hacer la peticion de la clave publica a secure box
# Return: None en caso de error, y el mensaje descifrado en caso de exito
#
def desencriptar_mensaje(ID_origen, mensaje_cifrado, token):

	iv = mensaje_cifrado[0:IVLEN] #vector de inicializacion (AES)
	sobre = mensaje_cifrado[IVLEN:RSALEN+IVLEN] #sobre digital del mensaje
	mensajefirmado_cifrado = mensaje_cifrado[RSALEN+IVLEN:] #firma+mensaje, cifrados

	#obtenemos la clave usada por AES descifrando el sobre
	clave = descifrar_sobre_digital(sobre)

 	#Desciframos el mensaje usando para ello la clave que acabamos de obtener
	mensajefirmado = desencriptarAES(clave, iv, mensajefirmado_cifrado)

	firma = mensajefirmado[0:RSALEN] #La firma tiene tama
	mensaje = mensajefirmado[RSALEN:]

	validacion = comprobar_firma(firma, mensaje, ID_origen, token)

	if validacion == True:
		print("OK, mensaje desencriptado")
		return mensaje

	print("ERROR desencriptando mensaje")
	return None
