
from tkinter import*
from tkinter import messagebox
from PIL import ImageTk, Image
import ast
import hashlib




##############################define show hide

def hide():
    eye.config(file='noeye.jpg')
    code.config(show='*')
    eyeButton.config(command=show)


def show():
    eye.config(file='eye.jpg')
    code.config(show='')
    eyeButton.config(command=hide)

#################################signin window

root=Tk()
root.title('Login')
root.geometry('1166x718')
root.config(bg='#B2D2A4')
root.resizable(True,True)




###############################read data from file

def signin():
    username=user.get()
    password=code.get()
    
   
    hashed=hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    file=open('datasheet.txt','r')
    d=file.read()
    r=ast.literal_eval(d)
    file.close()


   

    if username in r.keys() and hashed==r[username]:
        
        screen=Toplevel(root)
        screen.title("Your account")
        screen.geometry('1166x718')
        screen.config(bg='white')

        Label(screen,text='Hello',bg='#000080',font=('Calibri(Body)',50,'bold')).pack(expand=True)
       
        screen.mainloop()

    else:
       messagebox.showerror('Invalid','Invalid username or password')
    
   
    

  
       
##############################signup  window
def signup_command():
    window=Toplevel(root)
    window.title('SignUp')
    window.geometry('1166x718')
    window.config(bg='#4e7140')
    window.resizable(True,True)
    window.state('zoomed')


        
    

###############################canvas for signup
    c= Canvas(window,width=400, height=400,bg='#4e7140')
    c.place(x=450,y=50)

##############################add data to file

    def signup():
        username=user.get()
        password=code.get()
        conform_password=conform_code.get()
       
        hashed=hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        
   
        if password==conform_password:

        

            try:
                file=open('datasheet.txt','r+')
                d=file.read()
                re=ast.literal_eval(d)
                dict2={username:hashed}
                hashed=hashlib.sha256(password.encode('utf-8')).hexdigest()
                
                re.update(dict2)
                file.truncate(0)
                file.close()

                file=open('datasheet.txt','w')
                w=file.write(str(re))
                
                
               
                 
                messagebox.showinfo('Signup','Successfully sign up')
               
                window.destroy()

            except:
                file=open('datasheet.txt','w')
                pp=str({'username':'password'})
                file.write(pp)
                file.close()
            
        else:

            messagebox.showerror('Invalid','Both password should match')
        

#####################################hashing the password

           

        
        # bytes = password.encode('utf-8')
        # salt = bcrypt.gensalt()
        #hash = bcrypt.hashpw(bytes, salt)
        #print(hash)
    


##################define sign command

    def sign():
        window.destroy()
###########################add frame to signup window

    
    frame=Frame(window,width=350,height=350,bg="#B2D2A4")
    frame.place(x=480,y=70)

    heading=Label(frame,text="Sing Up",fg='#000080',bg='#B2D2A4',font=('Microsoft YaHei UI Light',23,'bold'))
    heading.place(x=130,y=5)
   
    


######################################delete user and pass word
    def on_enter(e):
        user.delete(0,'end')

    def on_leave(e):
        if user.get()=='':
            user.insert(0,'Username')


    user = Entry(frame,width=25,fg='#000080',border=0,bg="#B2D2A4",font=('Microsoft YaHei UI Light',11))
    user.place(x=30,y=80)
    user.insert(0,'Username')
    user.bind('<FocusIn>', on_enter)
    user.bind('<FocusOut>', on_leave)

    

######################################delete user and pass word
    def on_enter(e):
        code.delete(0,'end')

    def on_leave(e):
        if code.get()=='':
            code.insert(0,'Password')


    code = Entry(frame,width=25,fg='#000080',border=0,bg="#B2D2A4",font=('Microsoft YaHei UI Light',11))
    code.place(x=30,y=110)
    code.insert(0,'Password')
    code.bind('<FocusIn>', on_enter)
    code.bind('<FocusOut>', on_leave)
     
   

#####################################delete user and pass word
    def on_enter(e):
        conform_code.delete(0,'end')

    def on_leave(e):
        if conform_code.get()=='':
            conform_code.insert(0,'Confirm Password')


    conform_code = Entry(frame,width=25,fg='#000080',border=0,bg="#B2D2A4",font=('Microsoft YaHei UI Light',11))
    conform_code.place(x=30,y=140)
    conform_code.insert(0,'Confirm Password')
    conform_code.bind('<FocusIn>', on_enter)
    conform_code.bind('<FocusOut>', on_leave)
     
    


    

#####################################signup buton
    Button(frame,width=22,pady=7,text='Sign Up',bg='#000080',fg='#000080',border=0,command=signup).place(x=25,y=190,
    )

    label=Label(frame,text="I have an account?",fg='#000080',bg='#B2D2A4',font=('Microsoft YaHei UI Light',9))
    label.place(x=25,y=240)
    

    signin=Button(frame,width=6,text='Sing In',border=0,bg='#B2D2A4',cursor='hand2',fg='#000080',command=sign)
    signin.place(x=170,y=230)
     
    
     
    

####################################add image to signin window


img = ImageTk.PhotoImage(Image.open("Login.jpg"))  
l=Label(image=img)
l.pack()


frame=Frame(root,width=350,height=350,bg="#B2D2A4")
frame.place(x=480,y=70)

heading=Label(frame,text="Sing in",fg='#000080',bg='#B2D2A4',font=('Microsoft YaHei UI Light',23,'bold'))
heading.place(x=130,y=5)

######################################delete user and pass word
def on_enter(e):
    user.delete(0,'end')

def on_leave(e):
    name=user.get()
    if name=='':
        user.insert(0,'Username')
        
user = Entry(frame,width=25,fg='#000080',border=0,bg="#B2D2A4",font=('Microsoft YaHei UI Light',11))
user.place(x=30,y=100)
user.insert(0,'Username')
user.bind('<FocusIn>', on_enter)
user.bind('<FocusOut>', on_leave)


######################################delete user and pass word
def on_enter(e):
    code.delete(0,'end')

def on_leave(e):
    name=code.get()
    if name=='':
        code.insert(0,'Password')
code = Entry(frame,width=25,fg='#000080',border=0,bg="#B2D2A4",font=('Microsoft YaHei UI Light',11))
code.place(x=30,y=130)
code.insert(0,'Password')
code.bind('<FocusIn>', on_enter)
code.bind('<FocusOut>', on_leave)



#####################################signin button
Button(frame,width=20,pady=7,text='Sign in',bg='#57a1f8',fg='#000080',border=0,command=signin).place(x=65,y=200)


label=Label(frame,text="Don't have an account?",fg='#000080',bg='#B2D2A4',font=('Microsoft YaHei UI Light',9))
label.place(x=63,y=240)


sign_up= Button(frame,width=6,text='Sing Up',border=0,bg='#B2D2A4',cursor='hand2',fg='#000080',command=signup_command)
sign_up.place(x=189,y=240)

#######################show and hide imageeye
eye=PhotoImage(file='eye.jpg')
eyeButton=Button(frame,image=eye,cursor='hand2',command=hide,width=20,height=20)
eyeButton.place(x=230,y=130)


root.mainloop()


