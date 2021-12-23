#####################################################
#                      IMPORTS                      #
#####################################################

import time
import socket   
import threading
import sqlite3
import datetime
import os
import sys
import hashlib
import json
from criptools import criptool
from PyQt5 import QtWidgets, QtCore, QtGui, uic
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.Qt import Qt

#LIMPIAR LOS DATOS PROCEDENTES DEL SQL
def clean_data(dato):
    dato = str(dato).replace("(","")
    dato = str(dato).replace("'","")
    dato = str(dato).replace(",","")
    dato = str(dato).replace(")","")
    dato = str(dato).replace("]","")
    dato = str(dato).replace("[","")
    return dato

#LIMPIAR LOS DATOS PROCEDENTES DEL SQL
def clean_writer(dato):
    dato = str(dato).replace("'","")
    dato = str(dato).replace("b","",1)
    return dato   

#####################################################
#                      LOGIN WINDOW                 #
#####################################################

class LogIn(QMainWindow):
    #INICIALIZACIÓN DEL LA PANTALLA PRINCIPAL DEL PROGRAMA Y LOS COMPONENTES
    def __init__ (self):
        super(LogIn, self).__init__()
        cwd = os.getcwd()
        uic.loadUi(cwd+'/interfaces/login.ui', self)
        global user
        #FUNCIONES DE LOS BOTONES
        self.pushButton_conectar.clicked.connect(self.login_register)
        self.pushButton_usuarios.clicked.connect(self.user_admin_button)
        self.pushButton_conectar_2.clicked.connect(self.auto_login)
        self.label_error.setText("")
        self.lineEdit_pass.setEchoMode(QLineEdit.Password)

    #SI UN USUARIO NO EXISTE LO CREAMOS SI EXISTE COMPROBAMOS CONTRASEÑA
    def login_register(self):
        if self.lineEdit_usuario.text() == "":
            self.label_error.setText("<font color=red>Introduce un nombre de usuario</font>")
            return
        else:
            user = self.lineEdit_usuario.text()
        if self.lineEdit_pass.text() == "":
            self.label_error.setText("<font color=red>Introduce una contraseña</font>")
            return
        else:
            password = self.lineEdit_pass.text()
        if self.lineEdit_host.text() == "":
            self.label_error.setText("<font color=red>Introduce un host</font>")
        else:
            host = self.lineEdit_host.text()
        start_user(host, password, user)
        """
        try:
            start_user(host)
        except:
            print("Unexpected error:", sys.exc_info()[0])
        """

    def auto_login(self):
        with open('criptools/user/initialize.json') as file:
            data = json.load(file)
        for user_data in data['users']:
            user = user_data['user']
            password = user_data['password']
            host = user_data['host'] 
        start_user(host, password, user)
        """
        try:
            start_user(host)
        except:
           print("Unexpected error:", sys.exc_info()[0])
        """
    
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.login_register()

    def user_admin_button(self):
        user_admin()

#####################################################
#                      CHAT WINDOW                  #
#####################################################

class Chat(QMainWindow):
    #INICIALIZACIÓN DEL LA PANTALLA PRINCIPAL DEL PROGRAMA Y LOS COMPONENTES
    def __init__ (self):
        super(Chat, self).__init__()
        cwd = os.getcwd()
        uic.loadUi(cwd+'/interfaces/chat.ui', self)
        #FUNCIONES DE LOS BOTONES
        self.pushButton_enviar.clicked.connect(self.write_message)
        self.textEdit_conversacion.setReadOnly(True)
    
    def write_message(self):
        message = self.lineEdit_mensaje.text()
        if message != "":
            crypt = criptool.RSA_encrypt(message, server_public)
            print(f"\nMensaje enviado al servidor:\n{crypt}")
            client.send(crypt.encode('utf-8'))
            self.lineEdit_mensaje.setText("")
            self.textEdit_conversacion.append(f"{user}: {message}")
        else:
            pass
    
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.write_message()

    def append_msg(self, message):
        self.textEdit_conversacion.append(f"{message}")

#####################################################
#                  REGISTER WINDOW                  #
#####################################################

class Register(QMainWindow):
    #INICIALIZACIÓN DEL LA PANTALLA PRINCIPAL DEL PROGRAMA Y LOS COMPONENTES
    def __init__ (self):
        super(Register, self).__init__()
        cwd = os.getcwd()
        uic.loadUi(cwd+'/interfaces/register.ui', self)
        #FUNCIONES DE LOS BOTONES
        self.pushButton_registro.clicked.connect(self.register_user)
        self.pushButton_volver.clicked.connect(self.back_to_login)
        self.label_error.setText("")
        self.lineEdit_pass.setEchoMode(QLineEdit.Password)
        self.lineEdit_passrepeat.setEchoMode(QLineEdit.Password)

    def register_user(self):
        reg_data = {}
        reg_data['users'] = []
        if self.lineEdit_usuario.text() == "":
            self.label_error.setText("<font color=red>Introduce un nombre de usuario</font>")
            return
        else:
            user = self.lineEdit_usuario.text()
        if self.lineEdit_pass.text() == "":
            self.label_error.setText("<font color=red>Introduce una contraseña</font>")
            return
        else:
            if self.lineEdit_pass.text() != self.lineEdit_passrepeat.text():
                self.label_error.setText("<font color=red>Las contraseñas no coinciden</font>")
                return
            else:
                password = self.lineEdit_pass.text()
        if self.lineEdit_host.text() == "":
            self.label_error.setText("<font color=red>Introduce un Host por defecto</font>")
            return
        else:
            host = self.lineEdit_host.text()

        reg_data['users'].append({
            'user': str(user),
            'password': str(password),
            'host': str(host)})

        with open('criptools/user/initialize.json', 'w') as file:
            json.dump(reg_data, file, indent=4)
        login_window()
        

    def back_to_login(self):
        login_window()

#####################################################
#                      MAIN                         #
#####################################################

#FUNCIÓN PARA MANTENER EL PROGRAMA EN FUNCIONAMIENTO CONTINUO
if __name__ == '__main__':
    #INICIALIZACION DE LA BASE DE DATOS
    cwd = os.getcwd()
    print(cwd+'/databases/users.db')
    bbdd = sqlite3.connect(cwd+'/databases/users.db')
    cursor = bbdd.cursor()
    #CREAMOS LAS TABLAS NECESARIAS PARA EL FUNCIONAMIENTO
    try:
        cursor.execute('''CREATE TABLE users (user text, pass text, host text)''')    
    except:
        print('Base de datos localizada, enseguida accederás al chat.')
    #CREAMOS PARES DE CLAVES PUBLICAS
    global private_key
    global public_key
    keys = criptool.RSA_generator()
    private_key = keys[0]
    public_key = keys[1]
    print('\n************************************************')
    print(f"private key: {private_key}\npublic key: {public_key}")
    print('\n************************************************')
    
    #INICIALIZAMOS LA GUI
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(LogIn())
    widget.setFixedWidth(800)
    widget.setFixedHeight(600)
    widget.setWindowIcon(QtGui.QIcon(cwd+'/pictures/candado.png'))
    widget.setWindowTitle("CriptoChat")
    widget.show()

    ##########   FUNCIONES QUE USAN TODAS LAS CLASES   ##########
    chat = Chat()
    register = Register()
    login = LogIn()
    #CREAMOS LOS HILOS CON LAS FUNCIONES DE LOS USUARIOS
    def start_user(hosting_ip, password, usuario):
        #variables para la conexion al host
        global user
        user = usuario
        global host
        host = hosting_ip
        port = 63333
        #nos conectamos al chat
        global client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))

        receive_thread = threading.Thread(target=receive_messages, args=(password, usuario))
        receive_thread.start()
    
        widget.addWidget(chat)
        widget.setCurrentWidget(chat)

    #CUANDO HAY UN CAMBIO EN EL SERVIDOR SE DETECTA
    def receive_messages(password, usuario):
        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                try:
                    split = message.split("/",1)
                except:
                    print('no spliteable')
                if message == "@username":
                    key_hash = criptool.load_key(password)
                    key_hash = criptool.sha_512(key_hash)
                    public_key_toserver = criptool.RSA_key_cleaner(public_key)
                    client.send((str(usuario)+'/'+key_hash+'/'+public_key_toserver).encode("utf-8"))
                else:
                    if split[0] == "***":
                        global server_public
                        server_public = criptool.RSA_key_format(split[1])
                        chat.append_msg('Welcome to chat!')
                    else:
                        print(f"\nMensaje recibido por el servidor:\n{message}")
                        message = criptool.RSA_decrypt(message, private_key)
                        chat.append_msg(str(message))
            except:
                print("An error Ocurred")
                client.close()
                break

    #CAMBIAMOS A LA VENTANA DE REGISTROS
    def user_admin():
        widget.addWidget(register)
        widget.setCurrentWidget(register)

    #CAMBIAMOS A LA VENTANA DE LOGIN
    def login_window():
        widget.addWidget(login)
        widget.setCurrentWidget(login)

    #METODO PARA SALIR DEL PROGRAMA
    try:
        sys.exit(app.exec_())
    except:
        client.close()
        print("Exiting")