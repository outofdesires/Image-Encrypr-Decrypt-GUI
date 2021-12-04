import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
def encrypt(imagebyte,key):
    for i in range(len(imagebyte)):
        imagebyte[i]=imagebyte[i]^key
    return imagebyte

def decrypt(imagebyte,key):
    for i in range(len(imagebyte)):
        imagebyte[i]=imagebyte[i]^key
    return imagebyte
def openfile():
    file = filedialog.askopenfilename(filetypes=[('Image Files', '*.jpg'),('Image Files', '*.jpeg')])
    path.set(file)
def start(path,key,choice,check,check1,check2):
    try:
        path=path.get()
        key1=int(key.get())
        check=check.get()
        check1=check1.get()
        check2=check2.get()
        with open(path, "rb") as image:
            ir = image.read()
            imagebyte=bytearray(ir)
        if(choice==1):
            imagebyte=encrypt(imagebyte,key1)
            if(check==1):
                phrase="encryptedWithKey"+str(key1)+".jpg"
            else:
                phrase="encrypted.jpg"
            with open(path+phrase,'wb') as image:
                image.write(imagebyte)
            messagebox.showinfo(title='Done', message="Encryption done by key - "+str(key1))
        if(choice==2):
            imagebyte=decrypt(imagebyte,key1)
            if(check1==0):
                with open(path+"decrypted.jpg",'wb') as image:
                    image.write(imagebyte)
            else:
                with open(path,'wb') as image:
                    image.write(imagebyte)
            messagebox.showinfo(title='Done', message="Decryption done by key"+str(key1))
        if(check2==1):
            key.set('')
    except Exception:
        messagebox.showerror(title='Error', message='Wrong Input')

root = tk.Tk()
root.title("Image Encrypt")
root.configure(background="white")
root.geometry('307x207')
root.iconbitmap("icon.ico")
root.resizable(True, True)
path=tk.StringVar()
key=tk.StringVar()
check=tk.IntVar()
check1=tk.IntVar()
check2=tk.IntVar()

pathlabel = tk.Label(root, text = 'File Path', font=('Helvetica',12, 'bold'),background="white",fg='#330000')
pathInput= tk.Entry(root,textvariable = path, font=('Helvetica',10,'normal'),background="white",fg='#330000')
keylabel = tk.Label(root, text = 'Password', font = ('Helvetica',12,'bold'),background="white",fg='#330000')
keyInput=tk.Entry(root, textvariable =key, font = ('Helvetica',10,'normal'), show = 'X',background="white",fg='#330000')
Encryptbtn=tk.Button(root,text = 'Encrypt',font = ('Times',12,'bold'), command=lambda: start(path,key,1,check,check1,check2),activebackground='red',background="white",fg='#003333')
Decryptbtn=tk.Button(root,text = 'Decrypt',font = ('Times',12,'bold'), command=lambda: start(path,key,2,check,check1,check2),activebackground='blue',background="white",fg='#003300')
C1 = tk.Checkbutton(root, text = "AttachKey", variable = check, onvalue = 1, offvalue = 0, height=1,font=('Helvetica',8) ,background="white",fg='#660000')
C2 = tk.Checkbutton(root, text = "Overwrite", variable = check1, onvalue = 1, offvalue = 0, height=1,font=('Helvetica',8) ,background="white",fg='#660000')
C3 = tk.Checkbutton(root, text = "EraseKey", variable = check2, onvalue = 1, offvalue = 0, height=1,font=('Helvetica',8) ,background="white",fg='#FF0000')
B=tk.Button(root, text="Browse", command=openfile ,bg='white')
t1=tk.Label(root,text='GitHub',bg='white',fg='#000033',font=('Helvetica',8,'normal'))
t2=tk.Label(root,text='@outofdesires ',bg='white',fg='#000033',font=('Helvetica',7,'normal'))
pathlabel.grid(row=0,column=0)
pathInput.grid(row=0,column=1)
B.grid(row=0,column=2)
keylabel.grid(row=1,column=0)
keyInput.grid(row=1,column=1)
Encryptbtn.grid(row=2,column=0)
Decryptbtn.grid(row=2,column=2)
C1.grid(row=3,column=0)
C2.grid(row=3,column=2)
C3.grid(row=1,column=2)
t1.grid(row=7)
t2.grid(row=8)
root.mainloop()
