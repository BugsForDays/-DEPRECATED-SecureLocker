#*********************************************
# ADVANCED CIPHER ENCRYPTION LIBRARY MANAGER |
#*********************************************

#############################################################################################

#VARS
Ualpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
cpUalpha = 'UBZETLPSOHWYIRADFMQJXVCKNG'

Lalpha = 'abcdefghijklmnopqrstuvwxyz'
cpLalpha = 'jrpedqbtuxfmigkashcozywvln'

num = '0123456789'
cpnum = '2139064758'

sym = '!@#$%^&*()_+-=[]\{}|;,./<>? '
cpsym = '$%!\]>_(&)+*= -/[?;,}|{^<.#@'

newUalpha = ''
newLalpha = ''
newnum = ''
newsym = ''

from itertools import izip_longest

#FRAMEWORK/FUNCTIONS

#ENCRYPTION ASSIST FUNCTIONS
def cpreorderencrypt(cp, key):
    return cp[key:] + cp[0:key]

def findindex(the_list, substring):
    for i, s in enumerate(the_list):
        if substring in s:
                return i
    return -1

#ENCRYPTION/DECRYPTION METHODS
def encrypt(text, key):
    encrypted = ''
    global newUalpha
    global newLalpha
    global newnum
    global newsym
    newUalpha = list(cpreorderencrypt(Ualpha, key))
    newLalpha = list(cpreorderencrypt(Lalpha, key))
    newnum = list(cpreorderencrypt(num, key))
    newsym = list(cpreorderencrypt(sym, key))
    for i in range(len(text)):
            if text[i] in newUalpha:
                encrypted += cpUalpha[findindex(newUalpha, text[i])]
            if text[i] in newLalpha:
                encrypted += cpLalpha[findindex(newLalpha, text[i])]
            if text[i] in newnum:
                encrypted += cpnum[findindex(newnum, text[i])]
            if text[i] in newsym:
                encrypted += cpsym[findindex(newsym, text[i])]
    return encrypted

def decrypt(text, key):
    newUalpha = ''
    newLalpha = ''
    newnum = ''
    newsym = ''
    newUalpha = list(cpreorderencrypt(Ualpha, key))
    newLalpha = list(cpreorderencrypt(Lalpha, key))
    newnum = list(cpreorderencrypt(num, key))
    newsym = list(cpreorderencrypt(sym, key))
    decrypted = ''
    for i in range(len(text)):
            if text[i] in cpUalpha:
                decrypted += newUalpha[findindex(cpUalpha, text[i])]
            if text[i] in cpLalpha:
                decrypted += newLalpha[findindex(cpLalpha, text[i])]
            if text[i] in cpnum:
                decrypted += newnum[findindex(cpnum, text[i])]
            if text[i] in cpsym:
                decrypted += newsym[findindex(cpsym, text[i])]
    text = ''
    key = 0
    return decrypted


# STORAGE + MAGAGEMENT FRAMEWORK



def appendtofile(filename, contents):
    f = open(filename + '.slock', 'a')
    f.write(contents + '\n')
    f.close()

def striplist(list):
    newlist = []
    for i in list:
        ele = ''
        ele = i.rstrip()
        #ele = ele[1:-1]
        newlist.append(ele)
    return newlist

def readusr(filename):
    lines = []
    with open(filename, 'r') as f:
        for line in f:
            lines.append(line)
    return lines[1]

def readfile(filename, info):
    lines = []
    if filename.endswith('.slock'):
        pcfn = filename
    else:
        pcfn = filename + '.slock'
    with open(pcfn, 'r') as f:
        for line in f:
            lines.append(line)
    keys = map(int, lines[2::3])
    labels = lines[3::3]
    pwds = lines[4::3]
    if info == 'keys':
        return keys
    if info == 'labels':
        return striplist(labels)
    if info == 'pwds':
        return striplist(pwds)
    if info == 'usr':
        return lines[1]

def apusrinfotofile(usr, pwd):
    appendtofile('usrs', usr)
    appendtofile('usrs', pwd)

def readusrsfile():
    usrlines = []
    with open('usrs.slock', 'r') as f:
        for line in f:
            usrlines.append(line)
    print usrlines
    usrnames = usrlines[0::2]
    pds =  usrlines[1::2]
    ind = 0
    print usrnames
    print pds
    decusr = []
    decpd = []
    for usr in usrnames:
        decusr.append(decrypt(usrnames[ind], 7))
        decpd.append(decrypt(pds[ind], 7))
        ind = ind + 1
    print decusr
    print decpd
    usrinfo = dict(zip(decusr, decpd))
    return usrinfo

   
    #INFO TYPES PARSER TESTER MOD
    """
    print('labels' + str(striplist(labels)))
    print('pwds' + str(striplist(pwds)))
    print('keys' + str(striplist(keys)))
    """
#ENCRYPTED INFO STORAGE FUNCTIONS
def apenclabelandpwd(filename, label, pwd, key):
    enclbl = encrypt(label, key)
    encpwd = encrypt(pwd, key)
    appendtofile(filename, enclbl)
    appendtofile(filename, encpwd)

def declabelandpwd(filename):
    keys = readfile(filename, 'keys')
    labels =  readfile(filename,"labels")
    pwds = readfile(filename,"pwds")
    ind = 0
    for key in keys:
        print key
        print decrypt(labels[ind], keys[ind])
        print decrypt(pwds[ind], keys[ind])
        ind = ind + 1
    """
    
    lbl = []
    pwd = []
    for key in usrinfo:
        lbl.append(usrinfo[key][0])
        pwd.append(usrinfo[key][1])
        for i in lbl:
            ind = 0
            lbldec = []
            pwddec = []
            lbldec.append(decrypt(lbl[ind], key))
            pwddec.append(decrypt(pwd[ind], key))
            ind += 1
        print key
        print lbldec
        print pwddec
        """
    """
        dict(zip(keys), zip(labels, pwds))
        print key
        print decrypt(str(labels), key)
        print decrypt(str(pwds), key)
        """
    """
    label = readfile(filename,'labels')
    pwd = readfile(filename,'pwds')
    if info == 'label':
        return decrypt(str(label), key)
    if info == 'pwd':
        return decrypt(str(pwd), key)
    """

def apkey(filename, key):
    appendtofile(filename, key)

#MAINFRAME CMD TESTER MOD(CMD VERSION OF PROGRAM!!)
"""
choice = raw_input('encrypt, decrypt, or create? >>>')
if choice == 'encrypt':
    fn = raw_input('file name: ')
    ky = raw_input('key: ')
    lb = raw_input('label : ')
    pd = raw_input('pwd: ')
    apkey(fn, ky)
    apenclabelandpwd(fn, lb, pd, int(ky))
if choice == 'decrypt':
    fn = raw_input('file name: ')
    print declabelandpwd(fn)

    for i in keys:
        
    print keys
    print labels
    print pwds
    
    for i in keys:
        
        print i
        print labels[i]
        print pwds[i]

if choice == 'create':
    fn = raw_input('file name: ')
    createlocker(fn)

#ENCRYPT/DECRYPT TESTER MOD

input = raw_input('text: ')
kinput = raw_input('key: ')
enc = encrypt(input, int(kinput))
print enc
dinput = raw_input('dkey: ')
de = decrypt(enc,int(dinput))
print de


#FILE WRITING TESTER MOD

writetofile(fn + '.slock', "key")
writetofile(fn + '.slock', "label")
writetofile(fn + '.slock', "pass")
writetofile(fn + '.slock', "key")
writetofile(fn + '.slock', "label")
writetofile(fn + '.slock', "pass")

"""

##########################################################################################

#GUI FRAMEWORK

import Tkinter as tk
import time
import os

#VARS
window = tk.Tk()
frame = tk.Frame(window)
users = readusrsfile()
print users

#WINDOW SETTINGS
window.minsize(400,200)


#FUNCTIONS
def ch():
    for key in users.keys():
          if users[usr.get()] == pas.get():
            return True

def filestrip(text):
    return text[:-6]

def checkusr(event=None):
    if users.has_key(usr.get()) == True and ch() == True:
        usrname = str(usr.get())
        def createlocker(name):
            f = open(name + '.slock', 'w+')
            f.write('DO NOT EDIT THIS FILE(HOW DID YOU GET INTO HERE IN THE FIRST PLACE?!)\n')
            f.write(usrname + '\n')
        time.sleep(0.25)
        confirm.config(text='You have successfully logged on!' )
        time.sleep(0.25)
        usr.delete(0, tk.END)
        pas.delete(0, tk.END)
        logolbl.pack_forget()
        title.pack_forget()
        logtitle.pack_forget()
        usrl.pack_forget()
        usr.pack_forget()
        pasl.pack_forget()
        pas.pack_forget()
        login.pack_forget()
        newusr.pack_forget()
        clear.pack_forget()
        confirm.pack_forget()
        window.unbind("<Return>")
        logolbl.grid(row=0, column=1, padx = 10, pady = 10)
        title.grid(row=0, column= 2, columnspan = 3, padx = 10)
        line = tk.Label(window, text = '--------------------------------------------------------------------------')
        line.grid(row=1, column =1, columnspan = 3)
        sellbl = tk.Label(window, text = 'SecureLocker File associated with account :  ' )
        buttonchoice = ''
        results = []
        for file in os.listdir(os.getcwd()):
            if file.endswith(".slock"):
                results.append(file)
        for file in results:
            if file.startswith(usrname):
                sellbl.config(text = 'SecureLocker File associated with account : ' +  file)
                sellbl.grid(row =2, column = 1, columnspan = 3, padx = 10)
                lbllbl = tk.Label(window, text='LABELS:')
                lbllbl.grid(row =3 , column = 1, pady = 15)
                pwdlbl = tk.Label(window, text='PASSWORDS:')
                pwdlbl.grid(row =3, column = 2)
                controllbl = tk.Label(window, text='ENCRYPT/DECRYPT:')
                controllbl.grid(row=3, column =3,)
                #sel = tk.Radiobutton(window, text = file, variable = buttonchoice, value = file)
                #sel.grid(row = r, column= 1)
                #sel.deselect()
            else:
                sellbl.config(text = 'There are no SecureLocker files \nassociated with your username' )
                
        """
        
        if results == []:
            
            cte = tk.Button(window, text='create', command = createlocker(usrname))
            #cte.grid(row = 4, column =1 )
        else:
            for files in results:
                    
        """    
        
    else:
        confirm.config(text='Your username and/or password is incorrect.' )
        usr.delete(0, tk.END)
        pas.delete(0, tk.END)

def cleart():
    usr.delete(0, tk.END)
    pas.delete(0, tk.END)
    confirm.config(text=' ' )

def ee():
    quit()

def newuser():
    newusrl = tk.Label(window, text='Create a username:')
    newusrl.pack()
    newusr = tk.Entry(window)
    newusr.pack()
    newpasl = tk.Label(window, text='Create a password:')
    newpasl.pack()
    newpas = tk.Entry(window, show='*')
    newpas.pack()
    newconl = tk.Label(window, text='Confirm password:')
    newconl.pack()
    newcon = tk.Entry(window, show='*')
    newcon.pack()
    window.unbind("<Return>")
    def reg():
        if users.has_key(newusr.get()) == False and newpas.get() == newcon.get():
            un = newusr.get()
            pw = newpas.get()
            apusrinfotofile(encrypt(un, 7), encrypt(pw, 7))
            confirm.config(text='You have successfully registered!')
            newusrl.pack_forget()
            newusr.pack_forget()
            newpasl.pack_forget()
            newpas.pack_forget()
            newconl.pack_forget()
            newcon.pack_forget()
            register.pack_forget()
            window.bind("<Return>")

        else:
            confirm.config(text='Username already exists or passwords do not match. Please retry.')
            window.bind("<Return>", checkusr)
    register = tk.Button(window, text="Register!", command=reg)
    register.pack(expand = True)
    
          
#UI WIDGETS         

ex = tk.Button(window, text = 'Exit', command= ee)
logo = tk.PhotoImage(file='E:/Downloads/lock.gif')
logolbl = tk.Label(window, text= '\n', image=logo, pady = 50)
title = tk.Label(window, text="SecureLocker",  font =('Helvetica', 25))
logtitle = tk.Label(window, text="\nLOGIN:")
usr = tk.Entry(window)
pas = tk.Entry(window, show='*')
usrl = tk.Label(window, text='Username:')
pasl = tk.Label(window, text='Password:')
login = tk.Button(window, text='Login', command=checkusr)
newusr = tk.Button(window, text = 'Register', command=newuser)
clear = tk.Button(window, text = 'Clear', command=cleart)
confirm = tk.Label(window)
logolbl.pack()
title.pack()
logtitle.pack()
usrl.pack(expand = True)
usr.pack(expand = True)
pasl.pack(expand = True)
pas.pack(expand = True)
login.pack(expand = True)
newusr.pack(expand = True)
clear.pack(expand = True)
confirm.pack(expand = True)
window.bind("<Return>", checkusr)

#START WINDOWS
window.wm_iconbitmap(window, default ='e:/downloads/favicon.ico')
window.title('SecureLocker')
window.mainloop()

