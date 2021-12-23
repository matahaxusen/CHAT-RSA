#####################################################
#                      IMPORTS                      #
#####################################################

import socket   
import threading
import sqlite3
import sys
from criptools import criptool

#variables para la conexion al host
host = '25.83.60.172'
port = 63333
#creamos el servidor en capa de internet
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#enlazamos los puertos de nuestra red local al servidor
server.bind((host, port))
server.listen()
print(f"Server running on {host}:{port}")
#creamos las listas donde van a ir los usuarios y sus nicks
clients = []
usernames = []
public_keys = {}

#####################################################
#                      FUNCIONES                    #
#####################################################

#LIMPIAR LOS DATOS PROCEDENTES DEL SQL
def clean_writer(dato):
    dato = str(dato).replace("'","")
    dato = str(dato).replace("b","",1)
    return dato


#ENVIA EL MENSAJE A TODOS LOS CLIENTES QUE ESTEN CONECTADOS
def broadcast_message(message, sender, username):
    for client in clients: #enviamos el mensaje a todos los conectados
        if client != sender: #evitamos enviarnos el mensaje a nosotros mismos
            msg = criptool.RSA_encrypt(f"{username}: {message}", criptool.RSA_key_format(public_keys[client]))
            client.send(msg.encode('utf-8'))

#ENVIA MENSAJE DE SISTEMA
def broadcast(message, sender):
    for client in clients: #enviamos el mensaje a todos los conectados
        if client != sender: #evitamos enviarnos el mensaje a nosotros mismos
            msg = criptool.RSA_encrypt(message.decode('utf-8'), criptool.RSA_key_format(public_keys[client]))
            client.send(msg.encode('utf-8'))

#MANEJA LA RECEPCION DE PETICIONES QUE SE HACEN AL CLIENTE
def handle_messages(client):
    index = clients.index(client)
    username = usernames[index]
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            decrypt = criptool.RSA_decrypt(message, private_key)
            broadcast_message(decrypt, client, username)
        except:
            broadcast(f"CriptoBot: el usuario {username} se ha desconectado.".encode('utf-8'), client)
            del public_keys[client]
            clients.remove(client)
            usernames.remove(username)
            client.close()
            break

#MANEJA LA RECEPCION DE USUARIOS AL CHAT
def receive_connections():
    key_master()
    while True:
        client, address = server.accept()
        client.send("@username".encode("utf-8"))
        pass_conf = criptool.load_server_key()
        pass_conf = criptool.sha_512(pass_conf)
        combined_msg = client.recv(1024).decode('utf-8')
        username, password, node_public_key = combined_msg.split('/')
        if password == pass_conf:
            client.send(("***/"+criptool.RSA_key_cleaner(public_key)).encode("utf-8"))
            clients.append(client)
            usernames.append(username)
            public_keys[client] = node_public_key
            print('\n************************************************')
            print(f"{username} se ha conectado al servidor {str(address)}\n\nHASH DE ACCESO CORRECTO:\n{password}")
            print('\n************************************************')
            message = f"CriptoBot: ¡{username} se ha unido al chat!".encode("utf-8")
            broadcast(message, client)
            #introducimos a cada cliente en un hilo para que cada cliente tenga su handle_message propio
            thread = threading.Thread(target=handle_messages, args=(client,))
            thread.start()
        else:
            print('Identificación errónea, expulsando usuario')
            client.close()


def key_master():
        if criptool.load_server_key() == 'False':
            criptool.key_server_generator()
        else:
            print('Llave recuperada con exito')

try:
    #CREAMOS PARES DE CLAVES PUBLICAS
    keys = criptool.RSA_generator()
    private_key = keys[0]
    public_key = keys[1]
    receive_connections()
except:
    print('Error durante el servicio: cerrando el servidor...')
    sys.exit()