#***************************************************************************
# SECURE LOCKER PASSWORD ENCRYTION MANAGER                                 |
# Created by BugsForDays aka Philip Z(https://github.com/BugsForDays)      |
# VERSION: 3.3                                                             |
#***************************************************************************

#############################################################################################

#********************
#FRAMEWORK/FUNCTIONS|
#********************

#VARS
ver = 3.3

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

from itertools import zip_longest
import random

#ENCRYPTION ASSIST FUNCTIONS
def cpreorderencrypt(cp, key):
    #reorder cp based on key, returns: cp as new cp list
    return cp[key:] + cp[0:key]

def findindex(the_list, substring):
    #finds index of string in list, returns: index of string as int
    for i, s in enumerate(the_list):
        if substring in s:
                return i
    return -1

#ENCRYPTION/DECRYPTION METHODS
def encrypt(text, key):
    #encrypt text with key via string construction, returns: encrypted text as string
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
    #inverse of encrypt(): decrypts text based on key, returns: decrypted text as string
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
    #appends contents to USR file
    f = open(filename + '.uslock', 'a')
    f.write(contents + '\n')
    f.close()

def appendtofile(filename, contents):
    #appends contents to SL filename
    f = open(filename + '.slock', 'a')
    f.write(contents + '\n')
    f.close()

def striplist(list):
    #strips each element in list, returns: stripped newlist as a list
    newlist = []
    for i in list:
        ele = ''
        ele = i.rstrip()
        newlist.append(ele)
    return newlist

def readfile(filename, info):
    #compiles lines to list, input: file, info('keys', 'labels, or 'pwds'), returns: info in file as a list
    lines = []
    if filename.endswith('.slock'):
        pcfn = filename
    else:
        pcfn = filename + '.slock'
    with open(pcfn, 'r') as f:
        for line in f:
            lines.append(line)
    keys = list(map(int, lines[1::3]))
    labels = lines[2::3]
    pwds = lines[3::3]
    if info == 'keys':
        return keys
    if info == 'labels':
        return striplist(labels)
    if info == 'pwds':
        return striplist(pwds)

def apusrinfotofile(usr, pwd):
    #appends usrname and pwd to USR file
    def apf(file, contents):
        f = open(file + '.uslock', 'a')
        f.write(contents + '\n')
        f.close()
    apf('usrs', usr)
    apf('usrs', pwd)

def readusrsfile():
    #reads USR file, returns: usr info as a dict in format: usr:pwd
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
    usrinfo = dict(list(zip(decusr, decpd)))
    return usrinfo

    #INFO TYPES PARSER TESTER MOD
    """
    print('labels' + str(striplist(labels)))
    print('pwds' + str(striplist(pwds)))
    print('keys' + str(striplist(keys)))
    """

#ENCRYPTED INFO STORAGE FUNCTIONS
def apenclabelandpwd(filename, label, pwd, key):
    #appends encrypted pass, key, lbl to SL file
    enclbl = encrypt(label, key)
    encpwd = encrypt(pwd, key)
    appendtofile(filename, enclbl)
    appendtofile(filename, encpwd)

def declabelandpwd(filename, info):
    #decrypts SL file, input: file, info('labels' or 'pwds'), returns: info as a list
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
    #appends key to SL filename
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

import tkinter as tk
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
    #checks if usrname and pwd match, returns True if correct
    for key in list(users.keys()):
          if users[usr.get()] == pas.get():
            return True

def filestrip(text):
    #returns text w/o last chars
    return text[:-6]

def createlocker(name):
    #creates new SL locker file with defaults
        f = open(name + '.slock', 'w+')
        f.write('DO NOT EDIT THIS FILE(HOW DID YOU GET INTO HERE IN THE FIRST PLACE?!)\n')
        f.close()

def checkusr(event=None):
    #runs ch() and loads next screen with pwds
    users = readusrsfile()
    if (usr.get() in users) == True and ch() == True:
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
        def cptoclip():
            #copies decrypted pwd to clipboard
            pwds = declabelandpwd(f, 'pwds')
            window.clipboard_clear()
            window.clipboard_append(pwds[buttonchoice.get()])
        #def delpw():

        def pwdfromlbl():
            #changes display text of d button and p label
            pwds = readfile(f, 'pwds')
            p.config(text = '')
            p.config(text = pwds[buttonchoice.get()])
            d.config(text = 'SHOW DECRYPTED \nPASSWORD')
        def pwdfromlblbc():
            #runs pwdfromlbl and changes d button display text
            pwdfromlbl()
            d.config(text = 'SHOW DECRYPTED \nPASSWORD')
            d.config(command = showpwd)
        def showpwd():
            #changes p label and d button display text, displayed decrypted pwd
            pwds = declabelandpwd(f, 'pwds')
            p.config(text = pwds[buttonchoice.get()])
            d.config(text = 'HIDE DECRYPTED \nPASSWORD')
            d.config(command = pwdfromlblbc)
        def encpass():
            #creates new window w/ encrypt pwd prompts, stores pwd, lbl, and key to SL file
            cv = tk.IntVar()
            def checkcheck():
                #checks the checkbutton, whether 1 or 0 and blanks out key field or unblanks
                if cv.get() == 1:
                    k.delete(0, tk.END)
                    k.configure(state=tk.DISABLED)
                else:
                    k.configure(state=tk.NORMAL)
            def storeencpass():
                #makes sure pwds match and stores pwds
                if newp.get() == newpc.get():
                    if cv.get() == 1:
                        pk = random.randint(1, 26)
                        apkey(f[:-6], str(pk))
                    else:
                        pk = int(k.get())
                        apkey(f[:-6], str(pk))
                    apenclabelandpwd(f[:-6], newl.get(), newp.get(), pk)
                    conf.config(text='Password has been successfully encrypted!')
                    placebuttons()
                    def close():
                        t.destroy()
                    c = tk.Button(t, text='CLOSE WINDOW', command = close)
                    c.pack()
                else:
                    conf.config(text='Passwords do not match. Please retry.')
            t = tk.Toplevel()
            t.geometry('250x300')
            l = tk.Label(t, text = 'ENCRYPT A NEW PASSWORD:\n')
            newll = tk.Label(t, text = 'Enter password identifier/label:')
            newl = tk.Entry(t)
            kl = tk.Label(t, text = 'Enter an encryption key(1 - 26):')
            k = tk.Entry(t)
            kc = tk.Checkbutton(t, text="Auto select a random key", variable = cv, command=checkcheck)
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
            kc.pack()
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
        pwds = readfile(f, 'pwds')
        sellbl.config(text = 'You are logged in as: ' + usrname + '\nThe SecureLocker File that is associated with your account is: ' +  f)
        sellbl.grid(row =2, column = 1, columnspan = 3, padx = 10)
        lbllbl = tk.Label(window, text='WEBSITES/SERVICES:')
        lbllbl.grid(row =3 , column = 1, pady = 15)
        pwdlbl = tk.Label(window, text='PASSWORD:')
        pwdlbl.grid(row =3, column = 2)
        p = tk.Label(window, text = pwds[0], font = ('bold', 12))
        p.grid(row = 5 , column= 2)
        controllbl = tk.Label(window, text='ENCRYPT/DECRYPT:')
        controllbl.grid(row=3, column =3,)
        #print results
        def placebuttons():
            #places buttons w/ decrypted pwd labels
            r = 5
            lbls = declabelandpwd(f, 'labels')
            lblsd = dict(enumerate(lbls))
            for ind, lbl in list(lblsd.items()):
                    #print ind
                    tk.Radiobutton(window, indicatoron = 0, width = 20, height = 3, text = lbl, variable = buttonchoice, value = ind , command=pwdfromlbl).grid(row = r, column =  1)
                    r += 1
        placebuttons()
        e = tk.Button(window, text = 'ENCRYPT \nPASSWORD', width = 20, pady = 5, command = encpass)
        d = tk.Button(window, text = 'SHOW DECRYPTED \nPASSWORD', width = 20, pady = 5, command = showpwd)
        cp = tk.Button(window, text = 'COPY PASSWORD \nTO CLIPBOARD', width = 20, pady = 5, command = cptoclip)
        delete = tk.Button(window, text = 'DELETE AN ENCRYPTED \nPASSWORD', width = 20, pady = 5)
        d.grid(row = 5, column = 3)
        e.grid(row = 6, column = 3)
        cp.grid(row= 7, column = 3)
        delete.grid(row = 8, column = 3)
    else:
        confirm.config(text='Your username and/or password is incorrect.' )
        usr.delete(0, tk.END)
        pas.delete(0, tk.END)

def cleart():
    #clears fields
    usr.delete(0, tk.END)
    pas.delete(0, tk.END)
    confirm.config(text=' ' )

def ee():
    #exits
    quit()

def newuser():
    #shows prompts to create new user and create new SL locker
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
        #makes sure no two usr names are same, creates locker and displays success lbl
        if (newusr.get() in users) == False and newpas.get() == newcon.get():
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
logo = tk.PhotoImage(file='lock.gif')
logolbl = tk.Label(window, text= '\n', image=logo, pady = 50)
title = tk.Label(window, text="SecureLocker",  font =('Impact', 25))
logtitle = tk.Label(window, text="\nVersion: " + str(ver) + "\n\nPlease Login:")
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
