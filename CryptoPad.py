from Tkinter import *
from ScrolledText import *
import tkFileDialog, tkMessageBox, tkSimpleDialog
from mZipAES import MiniZipAE1Writer, MiniZipAE1Reader
import os

if 0:
    s_Title = ' - CryptoPad 0.1'
    s_NewDoc = 'New Document'
    s_MenuFile = 'File'
    s_MenuFileNew = 'New'
    s_MenuFileOpen = 'Open'
    s_MenuFileSave = 'Save'
    s_MenuFileSaveAs = 'Save as...'
    s_MenuFileQuit = 'Quit'
    s_MenuEdit = 'Edit'
    s_MenuEditCut = 'Cut'
    s_MenuEditCopy = 'Copy'
    s_MenuEditPaste = 'Paste'
    s_MenuHelp = 'Help'
    s_MenuHelpAbout = 'About'
    s_AskPassword = 'Type in'
    s_RepeatPassword = 'Repeat'
    s_Password = ' the passphrase to encrypt/decrypt the document:'
    s_Quit = 'Quit'
    s_QuitMsg = 'Do you really want to exit CryptoPad and loose modifications?'
    s_Info = 'About CryptoPad'
    s_InfoMsg = 'CryptoPad 0.1\n\nA simple notepad supporting documents in ZIP AES-256 encrypted format.'
else:
    s_Title = ' - CryptoPad 0.1'
    s_NewDoc = 'Senza nome'
    s_MenuFile = 'File'
    s_MenuFileNew = 'Nuovo'
    s_MenuFileOpen = 'Apri...'
    s_MenuFileSave = 'Salva'
    s_MenuFileSaveAs = 'Salva con nome...'
    s_MenuFileQuit = 'Chiudi'
    s_MenuEdit = 'Modifica'
    s_MenuEditCut = 'Taglia'
    s_MenuEditCopy = 'Copia'
    s_MenuEditPaste = 'Incolla'
    s_MenuHelp = '?'
    s_MenuHelpAbout = 'Informazioni su...'
    s_AskPassword = 'Digita'
    s_RepeatPassword = 'Ripeti'
    s_Password = ' la passphrase per cifrare/decifrare il documento:'
    s_Quit = 'Esci'
    s_QuitMsg = 'Si desidera veramente chiudere CryptoPad e scartare le modifiche?'
    s_Info = 'Informazioni su CryptoPad'
    s_InfoMsg = 'CryptoPad 0.1\n\nUn semplice blocco note che supporta documenti in formato ZIP cifrato con AES-256.'
    s_New = 'Avviso'
    s_NewMsg = 'Si desidera davvero creare un nuovo documento senza salvare quello corrente?'
    
class CryptoPad(Tk):
    def __init__ (p):
        Tk.__init__(p)
        p.title(s_NewDoc+s_Title)
        p.textPad = ScrolledText(p, width=100, height=30, wrap=WORD)
        p.PCPfile = None
        p.password = None
        
        menu = Menu(p, tearoff=0)
        p.config(menu=menu)
        
        filemenu = Menu(menu, tearoff=0)
        menu.add_cascade(label=s_MenuFile, menu=filemenu)
        filemenu.add_command(label=s_MenuFileNew, command=p.new_command)
        filemenu.add_command(label=s_MenuFileOpen, command=p.open_command)
        filemenu.add_command(label=s_MenuFileSave, command=p.save_command)
        filemenu.add_command(label=s_MenuFileSaveAs, command=p.saveas_command)
        filemenu.add_separator()
        filemenu.add_command(label=s_MenuFileQuit, command=p.exit_command)

        editmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label=s_MenuEdit, menu=editmenu)
        editmenu.add_command(label=s_MenuEditCut, command=p.cut_command)
        editmenu.add_command(label=s_MenuEditCopy, command=p.copy_command)
        editmenu.add_command(label=s_MenuEditPaste, command=p.paste_command)
        
        helpmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label=s_MenuHelp, menu=helpmenu)
        helpmenu.add_command(label=s_MenuHelpAbout, command=p.about_command)
        
        p.textPad.pack(fill=BOTH, expand=YES)
        
        p.wm_protocol ("WM_DELETE_WINDOW", p.exit_command)
        
    def open_command(p):
        p.PCPfile = tkFileDialog.askopenfile(parent=p, mode='r+b', defaultextension='.etxt', filetypes=[('CryptoPad document', '*.etxt'),], title=s_MenuFileOpen)
        
        if p.PCPfile != None:
            p.password = None
            if p.password == None:
                p.password = tkSimpleDialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
            zip = MiniZipAE1Reader(p.PCPfile, p.password)
            s = zip.get()
            s = s.replace('\x0D\x0A', '\x0A')
            p.textPad.insert('1.0', s)
            p.title(os.path.basename(p.PCPfile.name)[:-5] + s_Title)
            p.textPad.edit_modified(False)

    def save_command(p):
        if p.PCPfile == None:
            p.saveas_command()
        s = p.textPad.get('1.0', END+'-1c')
        s = s.encode('utf-8')
        s = s.replace('\x0A', '\x0D\x0A')
        p.PCPfile.seek(0,0)
        zip = MiniZipAE1Writer(p.PCPfile, p.password)
        zip.append(os.path.basename(p.PCPfile.name).replace('.etxt','.txt'), s)
        zip.zipcomment = 'CryptoPad Document'
        zip.write()
        p.title(os.path.basename(p.PCPfile.name)[:-5] + s_Title)
        p.textPad.edit_modified(False)

    def saveas_command(p):
        new_file = tkFileDialog.asksaveasfile(mode='wb', defaultextension='.etxt', filetypes=[('CryptoPad document', '*.etxt'),], title=s_MenuFileSave)
        if new_file == None:
            return
        p.PCPfile = new_file
        p.password = None
        
        if p.PCPfile != None:
            if p.password == None:
                pw1, pw2 = 0, 1
                while pw1 != pw2:
                    pw1 = tkSimpleDialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
                    pw2 = tkSimpleDialog.askstring("Passphrase", s_RepeatPassword+s_Password, show='*')
                p.password = pw1
        p.save_command()
        
    def exit_command(p):
        if not p.textPad.edit_modified():
            root.destroy()
            return
        if tkMessageBox.askokcancel(s_Quit, s_QuitMsg):
            root.destroy()
     
    def about_command(p):
        tkMessageBox.showinfo(s_Info, s_InfoMsg)

    def copy_command(p):
        p.clipboard_clear()
        text = p.textPad.get("sel.first", "sel.last")
        p.clipboard_append(text)
        
    def paste_command(p):
        text = p.selection_get(selection='CLIPBOARD')
        p.textPad.insert('insert', text)
        
    def cut_command(p):
        p.clipboard_clear()
        text = p.textPad.get("sel.first", "sel.last")
        p.clipboard_append(text)
        p.textPad.delete("sel.first", "sel.last")

    def new_command(p):
        if p.textPad.edit_modified():
            if tkMessageBox.askokcancel(s_New, s_NewMsg):
                p.textPad.delete('1.0', END+'-1c')
                p.textPad.edit_modified(False)

    def dummy(p):
        pass
     

root = CryptoPad()
root.mainloop()
