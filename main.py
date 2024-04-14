import tkinter as tk
from tkinter import ttk
from tkinter.ttk import *
from tkinter import *
from generator import generate


def enterPIN():
    global entry
    global pinWindow
    pinWindow = Toplevel(win)
    win.eval(f'tk::PlaceWindow {str(pinWindow)} center')
    pinWindow.title("Enter PIN:")
    pinWindow.geometry("145x100")
    Label(pinWindow, text="Enter PIN:").grid(row=0, padx=10, pady=(10, 0))
    entry = Entry(pinWindow)
    entry.grid(row=1, pady=0, padx=10)
    Button(pinWindow, text="Generuj", command=generateRSA).grid(row=2, padx=10, pady=(10, 0))



def generateRSA():
    global entry
    global pinWindow
    global label2
    if len(entry.get()) == 4:
        generate(entry.get())
        pinWindow.destroy()
        label2.config(text="Klucze wygenerowane poprawnie")


win = tk.Tk()
win.eval('tk::PlaceWindow . center')
win.title("Signing APP - BSK Project")

# Ustawienie wag dla kolumn i wierszy
win.columnconfigure(0, weight=1)
win.columnconfigure(1, weight=1)
win.columnconfigure(2, weight=1)
win.rowconfigure(0, weight=1)
win.rowconfigure(1, weight=1)
win.rowconfigure(2, weight=1)

label1 = ttk.Label(win, text="Signing APP - BSK Project", font=("Arial", 14))
label1.grid(row=0, column=1, pady=10)

button1 = ttk.Button(win, text="Generuj parę kluczy", width=20, command=enterPIN)
button1.grid(row=1, column=0, pady=20, padx=20)

button2 = ttk.Button(win, text="Podpisz plik", width=20, command=generateRSA)
button2.grid(row=1, column=2, pady=20, padx=20)

label2 = ttk.Label(win, text="")
label2.grid(row=2, column=1, pady=(0, 20))


def on_resize(event):
    # Tutaj możesz dodać kod reagujący na zmianę rozmiaru okna
    pass

win.bind("<Configure>", on_resize)
win.mainloop()




