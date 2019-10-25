#####
# Redes 2
# Practica 2
# securebox.py
#
# Carlos Hojas García-Plaza y Sergio Cordero Rojas
#
# Main del programa que parsea los comandos y ejecuta su funcion correctamente
#
#####


import argparse
from src import users
from src import cryptography
from src import files

ruta = "./files/config/config.txt"


def main():
    try:
        with open(ruta, "r") as fihcero_config:
            mensaje = fihcero_config.read()
            datos = mensaje.split(' ')
            token = datos[0].split(":")[1]
    except FileNotFoundError:
        print("Error en el fichero de configuracion")
        return


    parser = argparse.ArgumentParser(description='SecureBox es un servidor segurp de transferencia de archivos encriptados.')
    parser.add_argument('--create_id', nargs=3, help='Comando de registro de un usuario', metavar=('nombre', 'email', 'alias'))
    parser.add_argument('--search_id', nargs=1, help='Comando de busqueda de un usario', metavar=('nombre/correo'))
    parser.add_argument('--delete_id', nargs=1, help='Comando para borrar un usuario', metavar=('id'))
    parser.add_argument('--encrypt', nargs=1, help='Comando para encriptar un fichero', metavar=('fichero'))
    parser.add_argument('--dest_id', nargs=1, help='ID del receptor del fichero', metavar=('id destino'))
    parser.add_argument('--sign', nargs=1, help='Comando para firmar un fichero', metavar=('fichero'))
    parser.add_argument('--enc_sign', nargs=1, help='Comando para firmar y encriptar un fichero simultamente', metavar=('fichero'))
    parser.add_argument('--source_id', nargs=1, help='ID del emisor del fichero',metavar=('id origen'))
    parser.add_argument('--upload', nargs=1, help='Comando para subir un fichero al servidor firmando y encriptado',metavar=('fichero'))
    parser.add_argument('--list_files', action='store_true', help='Comando para listar los archivos pertenecientes al usuario')
    parser.add_argument('--delete_file', nargs=1, help='Comando para borrar un fichero del servidor',metavar=('id fichero'))
    parser.add_argument('--download', nargs=1, help='Comando para descargar un fichero del servidor',metavar=('id fichero'))
    argumentos = parser.parse_args()

    #Comprobamos que no nos han puesto mas de un comando
    i = 0
    for d in vars(argumentos).values():
        if(d!=None and d!=False):
            i += 1


    if argumentos.create_id:
        if i != 1:
            print ("ERROR: No se puede utilizar --create_id simultaneamente con otro comando")
        else:
            users.registrar_usuario(nombre = argumentos.create_id[0], email = argumentos.create_id[1], alias = argumentos.create_id[2], token = token)

    elif argumentos.search_id:
        if i != 1:
            print ("ERROR: No se puede utilizar --search_id simultaneamente con otro comando")
        else:
            users.buscar_id(data_search = argumentos.search_id[0], token = token)

    elif argumentos.delete_id:
        if i != 1:
            print ("ERROR: No se puede utilizar --delete_id simultaneamente con otro comando")
        else:
            users.borrar_id(userID = argumentos.delete_id[0], token = token)

    elif argumentos.encrypt:
        if i != 2 or argumentos.dest_id == None:
            print ("ERROR: No se puede utilizar --encrypt sin --dest_id")
        else:
            cryptography.encriptar_archivo(ID_destino = argumentos.dest_id[0], archivo = argumentos.encrypt[0], token = token)

    elif argumentos.sign:
        if i != 1:
            print ("ERROR: No se puede utilizar --sign simultaneamente con otro comando")
        else:
            cryptography.firmar_archivo(archivo = argumentos.sign[0])

    elif argumentos.enc_sign:
        if i != 2 or argumentos.dest_id == None:
            print ("ERROR: No se puede utilizar --enc_sign  sin --dest_id")
        else:
            cryptography.firmar_y_encriptar_archivo(ID_destino = argumentos.dest_id[0], archivo = argumentos.enc_sign[0], token = token)

    elif argumentos.upload:
        if i != 2 or argumentos.dest_id == None:
            print ("ERROR: No se puede utilizar --upload sin --dest_id")
        else:
            files.subir_archivo(ID_destino = argumentos.dest_id[0], archivo = argumentos.upload[0], token = token)

    elif argumentos.list_files:
        if i != 1:
            print ("ERROR: No se puede utilizar --list con argumentos")
        else:
            files.listar_archivos(token = token)

    elif argumentos.delete_file:
        if i != 1:
            print ("ERROR: No se puede utilizar --delete_file simultaneamente con otro argumento")
        else:
            files.borrar_archivo(file_id = argumentos.delete_file[0], token = token)

    elif argumentos.download:
        if i != 2 or argumentos.source_id == None:
            print ("ERROR: No se puede utilizar --download sin --source_id")
        else:
            files.descargar_archivo(file_id = argumentos.download[0], ID_origen = argumentos.source_id[0], token = token)

    elif argumentos.source_id:
        if argumentos.download == None:
            print ("ERROR: No se puede utilizar --dest_id sin -download")

    elif argumentos.dest_id:
        if argumentos.encrypt == None and argumentos.enc_sign == None:
            print ("ERROR: No se puede utilizar --dest_id sin --encrypt o --enc_sign")

    else:
        print ("ERROR: Los argumentos no se han introducido correctamente.")


    return

if __name__ == '__main__':
   main()
