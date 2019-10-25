
#Paquete para crear las claves publicas
from Crypto.PublicKey import RSA
#Paquete para realizar peticiones HTTP
import requests
#Paquete para interacturar con el SO, usado para la gestion de archivos
import os

import json

url = 'http://vega.ii.uam.es:8080/api/users'
url_registro = url + '/register'
url_busqueda = url + '/search'
url_clave = url + '/getPublicKey'
url_borrar= url + '/delete'

OK_RESPONSE = 200
UNAUTHORIZED_RESPONSE = 401
FORBBIDEN_RESPONSE = 403




# Crear una nueva identidad, con la opción --create_id [alias].
# El cliente deberá generar un nuevo par de claves pública y privada, con el alias adecuado (si se ha especificado alguno), y registrarla en SecureBox con la
# llamada adecuada, lo que generará un ID único para el usuario. En cada momento, cada usuario sólo puede
# tener una identidad activa asociada a un token de autenticación. Si se crea y registra una nueva identidad,
# los datos asociadas a la antigua (nombre, email y clave pública) se perderán.

# --create_id nombre email [alias]
# Este comando usara la funcion registrar_usuario
# Funcion registrar_usuario
# Crea una nueva identidad (par de claves púlica y privada) para un usuario y la registra en SecureBox
# nombre: nombre completo del usuario, para que pueda ser buscado después por otros usuarios.
# email: correo electrónico.
# alias: es una cadena identificativa opcional.
# token: token de autenticación
# Return: nada en caso correcto, none en otro caso

def registrar_usuario(nombre, email, alias, token):
	print("Generando par de claves RSA de 2048 bits...")

    #Generacion de claves con el paquete RSA
	keys = RSA.generate(2048)

	#Usamos formato PEM por requisito de la práctica
	private_key = keys.export_key('PEM')
	public_key = keys.publickey().export_key('PEM')
	print("OK")

	#Realizamos la cabecera de la petcion de registro
    #/users/register
#     Argumentos:
#          nombre: nombre completo del usuario, para que pueda ser buscado después por otros usuarios.
#          email: correo electrónico.
#          publicKey: clave pública del usuario, que será utilizada por otros usuarios para enviarle ficheros cifrados. Deberá utilizarse el formato PEM.

	headers = {'Authorization': "Bearer " + token}
	args = {'nombre': nombre, 'email': email,'alias': alias, 'publicKey': public_key.decode('utf-8')}

	# Envio de solicitud de alta de usuario, se almacena respuesta en pet, si se lanza la excepcion de error de conexion la tratamos
	try:
		peticion = requests.post(url_registro, headers = headers, json = args)
	except requests.ConnectionError:
		print("ERROR en Registro de Usuario: falta de conexión")
		return None


    #Si la respuesta tiene un codigo 200 guardamos la clave del fichero en un archivo
	if peticion.status_code == OK_RESPONSE :
		# Si no esta el directorio lo creamos
		try:
			os.stat("./key")
		except:
			os.mkdir("./key")

        # Escribimos la clave privada en el fichero
		with open("./key/private_key.dat", "wb") as privatekey_file:
			privatekey_file.write(private_key)

    	#Como el objeto json devuelto solo contiene el nombre y el timepstamp tenemos que realizar una peticion de busqueda para obtener el id

		headers2 = {'Authorization': "Bearer " + token}
		args2 = {'data_search': nombre}

		#Envio de peticion de búsqueda de identidad, se almacena respuesta en pet, si se lanza la excepcion de error de conexion la tratamos
		try:
			peticion2= requests.post(url_busqueda, headers=headers2, json=args2)
		except requests.ConnectionError:
			print("ERROR en registar_usuario: falta de conexion")
			return None

		if peticion2.status_code == OK_RESPONSE:
			users = peticion2.json()

			# Iteramos la lista de usuarios devuelta por el servidor
			for user in users:
				if user['email'] == email:
					if user['publicKey'] == public_key.decode('utf-8'):
						print("Identidad con ID{} creada correctamente".format(user['userID']))
						return
			print("ERROR en registar_usuario: No se ha podido encontrar el ID del usuario recien creado")
			return None

		elif peticion2.status_code == UNAUTHORIZED_RESPONSE or peticion2.status_code == FORBBIDEN_RESPONSE :
			print('ERROR {} : {}'.format(peticion2.json()['error_code'], peticion2.json()['description']))
			return None
		else:
			print("Error del servidor")
			return None

	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print("Error del servidor")
		return None

	return





# Funcion buscar_clave_publica
# Esta función se llamará cuando sea necesaria encontrar la clave publica de un usuario poder enviarle un fichero cifrado.
# userID: identificador único del usuario cuya clave pública solicitamos
# token: token de autenticación
# Return: la clave publica si es encontrada, none en otro caso

def buscar_clave_publica(userID, token):
    #Realizamos la cabecera de la petcion de clave publica
    # Obtener clave pública - /users/getPublicKey
    # Obtiene la clave pública de un usuario.
    #   Argumentos:
    #       userID: identificador único del usuario cuya clave pública solicitamos.

	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}


	# Envio de peticion de búsqueda de clave pública, se almacena respuesta en pet, si se lanza la excepcion de error de conexion la tratamos
	try:
		peticion = requests.post(url_clave, headers = headers, json = args)
	except requests.ConnectionError:
		print("->  ERROR en Búsqueda de Clave Pública: falta de conexión")
		return None

    # Si la peticion es correcta devolvemos la clave pública, si no imprimimos el error y devolvemos none
	if peticion.status_code == OK_RESPONSE:
		ret = peticion.json()['publicKey']
		if ret == "":
			print("La clave publica no ha sido encontrada")
			return None
		return ret
	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print("Error del servidor")
		return None


# --search_id nombre/correo
# Este comando usara la funcion buscar_id
# Funcion buscar_id
# Permite encontrar un usuario del que sólo sabemos su nombre o correo, por ejemplo, y buscar su ID para poder enviarle un archivo de forma segura
# data_search: cadena de búsqueda, que será contrastada contra el nombre y correo electrónico.
# token: token de autenticación
# Return: nada en caso correcto, none en otro caso

def buscar_id(data_search, token):
	print("Buscando usuario {} en el servidor...".format(data_search))
	# Realizamos la cabecera de la petcion de búsqueda
    # Busar una identidad - /users/search
    # Argumentos:
    #    data_search: cadena de búsqueda, que será contrastada contra el nombre y correo electrónico.
	headers = {'Authorization': "Bearer " + token}
	args = {'data_search': data_search}

	# Envio de peticion de búsqueda de identidad, se almacena respuesta en pet, si se lanza la excepcion de error de conexion la tratamos
	try:
		peticion = requests.post(url_busqueda, headers=headers, json=args)
	except requests.ConnectionError:
		print("ERROR en buscar_id: falta de conexion")
		return None

	# Si la peticion es correcta recorremos el objeto JSON recibido e imprimimos los usuarios encontrados, en caso contrario imprimimos el error
	if peticion.status_code == OK_RESPONSE:
		print("OK")
		users =  peticion.json()
		print("{} usuarios encontrados".format(len(users)))
		i = 0
		# Iteramos la lista de usuarios devuelta por el servidor
		for user in users:
			print("[{}] {}, {}, ID: {}".format(i+1, user['nombre'], user['email'], user['userID']))
			i += 1

	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print("Error del servidor")
		return None

	return


# --delete_id id
# Este comando usara la funcion borrar_id
# Funcion borrar_id
# Permite eliminar un usuario a partir de su identificador. sólo es posible borrar identidades creadas por el propio usuario.
# userID: ID del usuario a ser borrado
# token: token de autenticación
# Return: nada en caso correcto, none en otro caso
def borrar_id(userID, token):
	print("Solicitando borrado de la identidad {}...".format(userID))
	# Realizamos la cabecera de la petcion de borrado
    # Borrar una identidad - /users/delete
    # Argumentos:
    #    userID: ID del usuario a ser borrado

	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	# Envio de peticion para boorar la identidad, se almacena respuesta en pet, si se lanza la excepcion de error de conexion la tratamos
	try:
		peticion = requests.post(url_borrar, headers=headers, json=args)
	except requests.ConnectionError:
		print("ERROR en borrar_id: falta de conexion")
		return None

	# Si la peticion es correcta imprimimos un mensaje de confirmacion, en caso contrario imprimimos el error
	if peticion.status_code == OK_RESPONSE:
		print("OK")
		print("Identidad con ID{} borrada correctamente".format(peticion.json()['userID']))

	elif peticion.status_code == UNAUTHORIZED_RESPONSE or peticion.status_code == FORBBIDEN_RESPONSE :
		print('ERROR {} : {}'.format(peticion.json()['error_code'], peticion.json()['description']))
		return None
	else:
		print("Error del servidor")
		return None
	return
