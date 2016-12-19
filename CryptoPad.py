"""
   CryptoPad 0.4
    
   A simple encrypting Notepad.
   Saves UTF-8 CR-LF encoded text as ZIP archive encrypted with AES-256.
   Uses mZipAES. Both for Python 2.7 & 3.4."""
import sys

if sys.version_info >= (3,0): 
    from tkinter import *
    from tkinter import scrolledtext, filedialog, messagebox, simpledialog
else:
    from Tkinter import *
    import ScrolledText as scrolledtext
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    import tkSimpleDialog as simpledialog

from mZipAES import MiniZipAE1Writer, MiniZipAE1Reader
import os

s_Document = 'CryptoPad Document'
VERSION = '0.4'



if 0:
    s_Title = ' - CryptoPad'
    s_NewDoc = 'New Document'
    s_MenuFile = 'File'
    s_MenuFileNew = 'New'
    s_MenuFileOpen = 'Open'
    s_MenuFileSave = 'Save'
    s_MenuFileSaveAs = 'Save as...'
    s_MenuFileQuit = 'Quit'
    s_MenuEdit = 'Edit'
    s_MenuEditUndo = 'Undo'
    s_MenuEditRedo = 'Redo'
    s_MenuEditDel = 'Delete'
    s_MenuEditCut = 'Cut'
    s_MenuEditCopy = 'Copy'
    s_MenuEditPaste = 'Paste'
    s_MenuEditSelectAll = 'Select all'
    s_MenuHelp = 'Help'
    s_MenuHelpAbout = 'About'
    s_AskPassword = 'Type in'
    s_RepeatPassword = 'Repeat'
    s_Password = ' the passphrase to encrypt/decrypt the document:'
    s_Quit = 'Quit'
    s_QuitMsg = 'Do you really want to discard changes to the open document?'
    s_Info = 'About CryptoPad'
    s_InfoMsg = 'CryptoPad '+VERSION+'\n\nA simple UTF-8 notepad supporting compressed documents in ZIP AES-256 encrypted format.'
    s_Error = 'Error'
    s_ErrorSaveMsg = 'Not saved - There was an error while saving the document!'
else:
    s_Title = ' - CryptoPad'
    s_NewDoc = 'Senza nome'
    s_MenuFile = 'File'
    s_MenuFileNew = 'Nuovo'
    s_MenuFileOpen = 'Apri...'
    s_MenuFileSave = 'Salva'
    s_MenuFileSaveAs = 'Salva con nome...'
    s_MenuFileQuit = 'Esci'
    s_MenuEdit = 'Modifica'
    s_MenuEditUndo = 'Annulla'
    s_MenuEditRedo = 'Ripeti'
    s_MenuEditDel = 'Elimina'
    s_MenuEditCut = 'Taglia'
    s_MenuEditCopy = 'Copia'
    s_MenuEditPaste = 'Incolla'
    s_MenuEditSelectAll = 'Seleziona tutto'
    s_MenuHelp = '?'
    s_MenuHelpAbout = 'Informazioni su...'
    s_AskPassword = 'Digita'
    s_RepeatPassword = 'Ripeti'
    s_Password = ' la passphrase per cifrare/decifrare il documento:'
    s_Quit = 'Esci'
    s_QuitMsg = 'Si desidera veramente chiudere CryptoPad e scartare le modifiche?'
    s_Info = 'Informazioni su CryptoPad'
    s_InfoMsg = 'CryptoPad '+VERSION+'\n\nUn semplice blocco note in UTF-8 che supporta documenti compressi in formato ZIP cifrato con AES-256.'
    s_New = 'Avviso'
    s_NewMsg = 'Si desidera scartare le modifiche al documento corrente?'
    s_Error = 'Errore'
    s_ErrorSaveMsg = 'Errore durante il salvataggio del documento!'
    
    
    
class CryptoPad(Tk):
    def __init__ (p):
        Tk.__init__(p)
        p.title(s_NewDoc+s_Title)
        p.textPad = scrolledtext.ScrolledText(p, width=100, height=30, wrap=WORD, exportselection=True, undo=True)
        p.target_etxt = None
        p.password = None
        
        menu = Menu(p, tearoff=0)
        p.config(menu=menu)
        
        filemenu = Menu(menu, tearoff=0)
        menu.add_cascade(label=s_MenuFile, menu=filemenu, underline=0)
        filemenu.add_command(label=s_MenuFileNew, command=p.new_command, underline=0, accelerator='CTRL+N')
        p.bind('<Control-n>', p.new_command)
        filemenu.add_command(label=s_MenuFileOpen, command=p.open_command, underline=0, accelerator='CTRL+F12')
        p.bind('<Control-F12>', p.open_command)
        filemenu.add_command(label=s_MenuFileSave, command=p.save_command, underline=0, accelerator='CTRL+S')
        p.bind('<Control-s>', p.save_command)
        filemenu.add_command(label=s_MenuFileSaveAs, command=p.saveas_command, underline=3)
        filemenu.add_separator()
        filemenu.add_command(label=s_MenuFileQuit, command=p.exit_command, underline=0)

        editmenu = Menu(menu, tearoff=0, postcommand=p.refresh_menu)
        p.editmenu = editmenu
        menu.add_cascade(label=s_MenuEdit, menu=editmenu)
        editmenu.add_command(label=s_MenuEditUndo, command=p.undo_command, accelerator='CTRL+Z')
        editmenu.add_command(label=s_MenuEditRedo, command=p.redo_command, accelerator='CTRL+Y')
        editmenu.add_separator()
        editmenu.add_command(label=s_MenuEditCut, command=p.cut_command, accelerator='CTRL+X')
        p.bind('<Control-x>', p.cut_command)
        editmenu.add_command(label=s_MenuEditCopy, command=p.copy_command, accelerator='CTRL+C')
        p.bind('<Control-c>', p.copy_command)
        editmenu.add_command(label=s_MenuEditPaste, command=p.paste_command, accelerator='CTRL+V')
        p.bind('<Control-v>', p.paste_command)
        editmenu.add_command(label=s_MenuEditDel, command=p.del_command, accelerator='DEL')
        editmenu.add_separator()
        editmenu.add_command(label=s_MenuEditSelectAll, command=p.selectall_command, accelerator='CTRL+A')
        p.bind('<Control-a>', p.selectall_command)
        
        helpmenu = Menu(menu, tearoff=0)
        menu.add_cascade(label=s_MenuHelp, menu=helpmenu)
        helpmenu.add_command(label=s_MenuHelpAbout, command=p.about_command)
        
        p.textPad.pack(fill=BOTH, expand=YES)
        
        p.wm_protocol ("WM_DELETE_WINDOW", p.exit_command)
        
    def open_command(p, evt=None):
        if p.textPad.edit_modified():
            if not messagebox.askokcancel(s_New, s_NewMsg):
                return

        p.target_etxt = filedialog.askopenfilename(parent=p, defaultextension='.txt', filetypes=[(s_Document, '*.txt'),], title=s_MenuFileOpen)
        
        if p.target_etxt != '':
            p.password = ''
            if not p.password:
                p.password = simpledialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
            s = ''
            with open(p.target_etxt, 'rb') as pkstream:
                zip = MiniZipAE1Reader(pkstream, p.password)
                s = zip.get()
            if not s: return
            if len(s) > 3 and s[:3] == b'\xEF\xBB\xBF':
                s = s.decode('utf-8-sig')
            elif len(s) > 2:
                if s[:2] == b'\xFF\xFE':
                    s = s.decode('utf-16le')
                elif s[:2] == b'\xFE\xFF':
                    s = s.decode('utf-16be')
            # else: is plain ASCII
            s = s.replace('\x0D\x0A', '\x0A')
            p.textPad.delete('1.0', END+'-1c')
            p.textPad.insert('1.0', s)
            p.title(os.path.basename(p.target_etxt)[:-4] + s_Title)
            p.textPad.edit_modified(False)
            p.textPad.edit_separator()

    def save_command(p, evt=None):
        if p.target_etxt == None:
            p.saveas_command()
        s = p.textPad.get('1.0', END+'-1c')
        s = s.replace('\x0A', '\x0D\x0A')
        s = s.encode('utf-8-sig')
        with open(p.target_etxt+'.tmp', 'wb') as pkstream:
            try:
                zip = MiniZipAE1Writer(pkstream, p.password)
                zip.append('data', s)
                zip.zipcomment = s_Document
                zip.write()
                # Cerca di sostituire l'originale solo in assenza di errori
                if os.path.exists(p.target_etxt):
                    os.remove(p.target_etxt)
                pkstream.close()
                os.rename(p.target_etxt+'.tmp', p.target_etxt)
            except:
                messagebox.showerror(s_Error, s_ErrorSaveMsg)
            else:
                p.title(os.path.basename(p.target_etxt)[:-4] + s_Title)
                p.textPad.edit_modified(False)
                p.textPad.edit_separator()

    def saveas_command(p):
        new_target = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[(s_Document, '*.txt'),], title=s_MenuFileSave)
        if not new_target: return
        p.password = None
        
        pw1, pw2 = 1, 2
        while pw1 != pw2:
            pw1 = simpledialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
            # Annulla il loop con la prima pw vuota
            if pw1 == '': return
            pw2 = simpledialog.askstring("Passphrase", s_RepeatPassword+s_Password, show='*')

        p.password = pw1
        p.target_etxt = new_target
        p.save_command()
        
    def exit_command(p):
        if not p.textPad.edit_modified():
            root.destroy()
            return
        if messagebox.askokcancel(s_Quit, s_QuitMsg):
            root.destroy()
     
    def about_command(p):
        messagebox.showinfo(s_Info, s_InfoMsg)

    def copy_command(p, evt=None):
        # Windows 10 intercepts and handles CTRL+[C,X,V] BEFORE Tkinter
        # But not the MENU command (evt == None)
        if os.name == 'nt' and evt: return
        p.clipboard_clear()
        text = p.textPad.get("sel.first", "sel.last")
        p.clipboard_append(text)
        
    def paste_command(p, evt=None):
        if os.name == 'nt' and evt: return
        text = p.selection_get(selection='CLIPBOARD')
        p.textPad.insert('insert', text)

    def undo_command(p, evt=None):
        p.textPad.edit_undo()

    def redo_command(p, evt=None):
        p.textPad.edit_redo()

    def del_command(p, evt=None):
        p.textPad.delete("sel.first", "sel.last")

    def cut_command(p, evt=None):
        # In Windows 8.1 .get raises an exception,
        # since selection is ALREADY cut to clipboard!
        if os.name == 'nt' and evt: return
        p.clipboard_clear()
        text = p.textPad.get("sel.first", "sel.last")
        p.clipboard_append(text)
        p.textPad.delete("sel.first", "sel.last")

    def selectall_command(p, evt=None):
        p.textPad.tag_add('sel', '1.0', 'end')
        
    def new_command(p, evt=None):
        if p.textPad.edit_modified():
            if not messagebox.askokcancel(s_New, s_NewMsg):
                return
        p.textPad.delete('1.0', END+'-1c')
        p.title(s_NewDoc+s_Title)
        p.textPad.edit_modified(False)
        
    def refresh_menu(p):
        "Called thanks to postcommand when menu is selected"
        s = ('active','disabled')[p.textPad.tag_ranges("sel")==()]
        p.editmenu.entryconfig(s_MenuEditDel, state=s)
        p.editmenu.entryconfig(s_MenuEditCut, state=s)
        p.editmenu.entryconfig(s_MenuEditCopy, state=s)
        p.editmenu.entryconfig(s_MenuEditPaste, state=('active','disabled')[p.clipboard_get()==None])
        

root = CryptoPad()
root.mainloop()
