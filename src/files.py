########
# REDES 2 - PRACTICA 2
# FICHERO: securebox_files.py
# DESCRIPCION: Fichero que define las funciones para manejar ficheros
# AUTORES:
#	* Sergio Cordero Rojas
#	* Carlos Luis Hojas Garcia-Plaza
########

from src import cryptography
import requests
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from shutil import copyfile

url = 'http://vega.ii.uam.es:8080/api/files'
url_subida = url + '/upload'
url_bajada = url + '/download'
url_borrado = url + '/delete'
url_listar = url + '/list'
directorio_archivos_descargados = './files/downloads'

OK_RESPONSE = 200
UNAUTHORIZED_RESPONSE = 401
FORBBIDEN_RESPONSE = 403

#
#
# Funcion subir_archivo
# Cifra y sube un archivo al servidor
# ID: ID del receptor del archivo
# archivo: fichero que queremos subir
# token: token requerido para poder hacer la peticion al servidor
# Return: El id del archivo subido, o None en caso de error
#
def subir_archivo(ID_destino, archivo, token):

	#firmamos y encriptamos el fichero, y obtenemos la ruta en la que se encuentra
	ruta = cryptography.firmar_y_encriptar_archivo(ID_destino, archivo, token)


	try:
		with open(ruta, "rb") as descriptor:
			nombre=os.path.basename(ruta)

			#enviamos una solicitud al servidor y guardamos la respuesta en la variable peticion

			headers = {'Authorization': "Bearer " + token}
			peticion = requests.post(url_subida, headers=headers, files={'ufile': (nombre,descriptor)})


	except FileNotFoundError:
		print("ERROR abriendo archivo")
		return None
	except requests.ConnectionError:
		print("ERROR en la conexión")

	if peticion.status_code == OK_RESPONSE:
		return peticion.json()['file_id']

	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print('{} -> Error del servidor'.format(peticion.status_code))
		return None

#
#
# Funcion descargar_archivo
# Descarga un archivo del servidor
# file_id: ID del archivo que queremos descargar
# ID: ID del emisor del archivo
# token: token requerido para poder hacer la peticion al servidor
# Return: None en caso de error, o la ruta del archivo descargado en caso de exito
#
def descargar_archivo(file_id, ID_origen, token):

	#escribimos los parametros que tendra la peticion
	headers = {'Authorization': "Bearer " + token}
	arguments = {'file_id' : file_id}

	try:
		#hacemos la request al servidor, y guardamos la respuesta en la variable peticion
		peticion = requests.post(url_bajada, headers=headers, json=arguments)

	except requests.ConnectionError:
		print("ERROR en la conexión")
		return None

	#si la respuesta es un 200,
	if peticion.status_code == OK_RESPONSE:
		#obtenemos el nombre del archivo buscando en la cabecera http 'content-disposition'
		file_name = "{}".format(peticion.headers['Content-Disposition']).split('"')[1]

		#obtenemos la ruta en la que guardaremos el archivo
		ruta = "{}/{}".format(directorio_archivos_descargados, file_name)

		# Si no existe el directorio donde guardamos los archivos, lo creamos
		if os.path.exists(directorio_archivos_descargados) == False:
			os.mkdir(directorio_archivos_descargados)

		#desencriptamos el contenido del archivo descargado
		mensaje_desencriptado = cryptography.desencriptar_mensaje(ID_origen, peticion.content, token)

		if mensaje_desencriptado == None:
			return None

		#abrimos el archivo donde guardaremos el contenido
		with open(ruta, "wb") as descriptor:
			descriptor.write(mensaje_desencriptado)

		return ruta

	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print('{} -> Error del servidor'.format(peticion.status_code))
		return None

#
# Funcion listar_archivos
# Lista los archivos de un usario en el servidor
# token: token requerido para poder hacer la peticion al servidor
# Return: None en caso de error,
#
def listar_archivos(token):
	print("Listando ficheros")
	#escribimos los parametros que tendra la peticion
	headers = {'Authorization': "Bearer " + token}

	try:
		#hacemos la request al servidor, y guardamos la respuesta en la variable peticion
		peticion = requests.post(url_listar, headers=headers)
		print(peticion.content)

	except requests.ConnectionError:
		print("ERROR en la conexión")
		return None

	#si la respuesta es un 200,
	if peticion.status_code == OK_RESPONSE:
		print("OK")
		files =  peticion.json()
		print("{} ficheros encontrados".format(files['num_files']))
		i = 0
		# Iteramos la lista de usuarios devuelta por el servidor
		for file in files['files_list']:
			print("[{}] ID : {}, file_name: {}".format(i+1, file['fileID'], file['fileName']))
			i += 1
	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print('{} -> Error del servidor'.format(peticion.status_code))
		return None
#
# Funcion borrar_archivo
# Borra un archivo del servidor
# file_id: ID del archivo que queremos borrar
# token: token requerido para poder hacer la peticion al servidor
# Return: None en caso de error,
#
def borrar_archivo(file_id, token):
		print("Borrando el fichero con ID{}".format(file_id))

		#escribimos los parametros que tendra la peticion
		headers = {'Authorization': "Bearer " + token}
		arguments = {'file_id' : file_id}

		try:
			#hacemos la request al servidor, y guardamos la respuesta en la variable peticion
			peticion = requests.post(url_borrado, headers=headers, json=arguments)

		except requests.ConnectionError:
			print("ERROR en la conexión")
			return None

		#si la respuesta es un 200,
		if peticion.status_code == OK_RESPONSE:
			print("EL fichero con ID{} ha sido borrado correctamente".format(peticion.json()['file_id']))


		elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
			print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
			return None
		else:
			print('{} -> Error del servidor'.format(peticion.status_code))
			return None
