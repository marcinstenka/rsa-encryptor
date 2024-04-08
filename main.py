#Import the required Libraries
from generator import generate
from tkinter import *
from tkinter import ttk
import runpy
import sys

#Create an instance of Tkinter frame
win = Tk()

#Set the geometry of Tkinter frame
win.geometry("750x250")

def generateRSA():
   global entry
   generate(entry.get())


label = Label(win, text="Podaj PIN:")
label.pack()
#Create an Entry widget to accept User Input
entry = Entry(win, width= 40)
entry.focus_set()
entry.pack()

#Create a Button to validate Entry Widget
ttk.Button(win, text= "Generuj parę kluczy",width= 20, command=generateRSA).pack(pady=20)

win.mainloop()