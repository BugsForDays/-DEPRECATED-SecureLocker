#***************************************************************************
# SECURE LOCKER PASSWORD ENCRYTION MANAGER                                 |
# Created by BugsForDays aka 尸廾工𠃊工尸 乙(https://github.com/BugsForDays)|
# VERSION: 3.1
#***************************************************************************

#############################################################################################

#********************
#FRAMEWORK/FUNCTIONS|
#********************

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

# STORAGE + MAGAGEMENT FRAMEWORK/FUNCTIONS
def appendtousrfile(filename, contents):
    f = open(filename + '.uslock', 'a')
    f.write(contents + '\n')
    f.close()

def appendtofile(filename, contents):
    f = open(filename + '.slock', 'a')
    f.write(contents + '\n')
    f.close()

def striplist(list):
    newlist = []
    for i in list:
        ele = ''
        ele = i.rstrip()
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
    keys = map(int, lines[1::3])
    labels = lines[2::3]
    pwds = lines[3::3]
    if info == 'keys':
        return keys
    if info == 'labels':
        return striplist(labels)
    if info == 'pwds':
        return striplist(pwds)

def apusrinfotofile(usr, pwd):
    def apf(file, contents):
        f = open(file + '.uslock', 'a')
        f.write(contents + '\n')
        f.close()
    apf('usrs', usr)
    apf('usrs', pwd)

def readusrsfile():
    usrlines = []
    with open('usrs.uslock', 'r') as f:
        for line in f:
            usrlines.append(line)
    #print usrlines
    usrnames = usrlines[0::2]
    pds =  usrlines[1::2]
    ind = 0
    #print usrnames
    #print pds
    decusr = []
    decpd = []
    for usr in usrnames:
        decusr.append(decrypt(usrnames[ind], 7))
        decpd.append(decrypt(pds[ind], 7))
        ind = ind + 1
    #print decusr
    #print decpd
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

def declabelandpwd(filename, info):
    keys = readfile(filename, 'keys')
    labels =  readfile(filename,"labels")
    pwds = readfile(filename,"pwds")
    newlabels = [decrypt(labels[x], keys[x]) for x in range(len(keys))]
    newpwds = [decrypt(pwds[x], keys[x]) for x in range(len(keys))]
    if info == 'labels':
        return newlabels
    if info == 'pwds':
        return newpwds

def apkey(filename, key):
    appendtofile(filename, key)

#MAINFRAME CMD TESTER MOD(CMD VERSION OF BASIC PROGRAM(NO STORAGE METHOD)!!)
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
"""

#ENCRYPT/DECRYPT TESTER MOD
"""
input = raw_input('text: ')
kinput = raw_input('key: ')
enc = encrypt(input, int(kinput))
print enc
dinput = raw_input('dkey: ')
de = decrypt(enc,int(dinput))
print de
"""

#FILE WRITING TESTER MOD
"""
writetofile(fn + '.slock', "key")
writetofile(fn + '.slock', "label")
writetofile(fn + '.slock', "pass")
writetofile(fn + '.slock', "key")
writetofile(fn + '.slock', "label")
writetofile(fn + '.slock', "pass")
"""

##########################################################################################

#**************
#GUI FRAMEWORK|
#**************

import Tkinter as tk
import time
import os

#VARS
window = tk.Tk()
frame = tk.Frame(window)
users = readusrsfile()
#print users

#WINDOW SETTINGS
window.minsize(400,200)

#FUNCTIONS
def ch():
    for key in users.keys():
          if users[usr.get()] == pas.get():
            return True

def filestrip(text):
    return text[:-6]

def createlocker(name):
            f = open(name + '.slock', 'w+')
            f.write('DO NOT EDIT THIS FILE(HOW DID YOU GET INTO HERE IN THE FIRST PLACE?!)\n')

def checkusr(event=None):
    users = readusrsfile()
    if users.has_key(usr.get()) == True and ch() == True:
        usrname = str(usr.get())
        confirm.config(text='You have successfully logged on!' )
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
        results = []
        r = 5
        def pwdfromlbl():
            pwds = readfile(file, 'pwds')
            p.config(text = '')
            p.config(text = pwds[buttonchoice.get()])
            d.config(text = 'SHOW DECRYPTED \nPASSWORD')
        def pwdfromlblbc():
            pwdfromlbl()
            d.config(text = 'SHOW DECRYPTED \nPASSWORD', command = showpwd)
        def showpwd():
            pwds = declabelandpwd(file, 'pwds')
            p.config(text = pwds[buttonchoice.get()])
            d.config(text = 'HIDE DECRYPTED \nPASSWORD', command = pwdfromlblbc)
        def encpass():
            def storeencpass():
                if newp.get() == newpc.get():
                    apkey(f[:-6], k.get())
                    apenclabelandpwd(f[:-6], newl.get(), newp.get(), int(k.get()))
                    conf.config(text='Password has been successfully encrypted!')
                    placebuttons()
                    def close():
                        t.destroy()
                    c = tk.Button(t, text='CLOSE WINDOW', command = close)
                    c.pack()
                else:
                    conf.config(text='Passwords do not match. Please retry.')
            t = tk.Toplevel()
            t.geometry('250x275')
            l = tk.Label(t, text = 'ENCRYPT A NEW PASSWORD:\n')
            newll = tk.Label(t, text = 'Enter password identifier/label:')
            newl = tk.Entry(t)
            kl = tk.Label(t, text = 'Enter an encryption key(1 - 26):')
            k = tk.Entry(t)
            newpl = tk.Label(t, text='Enter password:')
            newp = tk.Entry(t, show='*')
            newpcl = tk.Label(t, text='Confirm password:')
            newpc = tk.Entry(t, show='*',)
            eb = tk.Button(t, text='ENCRYPT PASSWORD', command = storeencpass)
            conf = tk.Label(t, text = '')
            l.pack()
            newll.pack()
            newl.pack()
            kl.pack()
            k.pack()
            newpl.pack()
            newp.pack()
            newpcl.pack()
            newpc.pack()
            eb.pack()
            conf.pack()
        buttonchoice = tk.IntVar()
        for file in os.listdir(os.getcwd()):
            if file.endswith(".slock"):
                results.append(file)
        for file in results:
            if file.startswith(encrypt(usrname, 11)):
                f = file
        sellbl.config(text = 'You are logged in as: ' + usrname + '\nThe SecureLocker File that is associated with your account is: ' +  f)
        sellbl.grid(row =2, column = 1, columnspan = 3, padx = 10)
        lbllbl = tk.Label(window, text='WEBSITES/SERVICES:')
        lbllbl.grid(row =3 , column = 1, pady = 15)
        pwdlbl = tk.Label(window, text='PASSWORD:')
        pwdlbl.grid(row =3, column = 2)
        p = tk.Label(window, text = '', font = ('bold', 12))
        p.grid(row = 5 , column= 2)
        controllbl = tk.Label(window, text='ENCRYPT/DECRYPT:')
        controllbl.grid(row=3, column =3,)
        #print results
        def placebuttons():
            r = 5
            lbls = declabelandpwd(f, 'labels')
            lblsd = dict(enumerate(lbls))
            for ind, lbl in lblsd.items(): 
                    #print ind
                    tk.Radiobutton(window, indicatoron = 0, width = 20, height = 3, text = lbl, variable = buttonchoice, value = ind , command=pwdfromlbl).grid(row = r, column =  1)
                    r += 1
        placebuttons()
        e = tk.Button(window, text = 'ENCRYPT \nPASSWORD', width = 20, pady = 5, command = encpass)
        d = tk.Button(window, text = 'SHOW DECRYPTED \nPASSWORD', width = 20, pady = 5, command = showpwd)
        d.grid(row = 5, column = 3)
        e.grid(row = 6, column = 3)
        notif = tk.Label(window, text = '')
        notif.grid(row = 7, column = 3)
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
            createlocker(encrypt(un, 11))
            confirm.config(text='You have successfully registered!\n A new SecureLocker has been created for you.')
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
    
#LOGIN UI WIDGETS         

ex = tk.Button(window, text = 'Exit', command= ee)
logo = tk.PhotoImage(file='E:/Downloads/lock.gif')
logolbl = tk.Label(window, text= '\n', image=logo, pady = 50)
title = tk.Label(window, text="SecureLocker",  font =('Impact', 25))
logtitle = tk.Label(window, text="\nPlease Login:")
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
usrl.pack()
usr.pack()
pasl.pack()
pas.pack()
login.pack()
newusr.pack()
clear.pack()
confirm.pack()
window.bind("<Return>", checkusr)

#START WINDOW
window.wm_iconbitmap(window, default ='e:/downloads/favicon.ico')
window.title('SecureLocker')
window.mainloop()