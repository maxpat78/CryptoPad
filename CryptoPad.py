"""
   CryptoPad 0.7 - A simple Tkinter encrypting Notepad
   
   Supports ASCII and UTF-(8|16) encoded text and universal line endings.
   Supports special document format (ZIP archive encrypted with AES-256).
   Uses mZipAES. Requires Python 3.
   
/*
 *  Copyright (C) 2015-2023, maxpat78 <https://github.com/maxpat78>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */ """
import sys, re, os
from tkinter import *
from tkinter import scrolledtext, filedialog, messagebox, simpledialog

from mZipAES import MiniZipAEWriter, MiniZipAEReader



s_Document = 'CryptoPad Document'
VERSION = '0.7'



if 0:
    s_Title = ' - CryptoPad'
    s_NewDoc = 'New Document'
    s_MenuFile = 'File'
    s_MenuFileNew = 'New'
    s_MenuFileOpen = 'Open'
    s_MenuFileSave = 'Save'
    s_MenuFileSaveAs = 'Save as...'
    s_MenuFileQuit = 'Quit'
    s_MenuFileSetPW = 'Set Password'
    s_MenuFileResetPW = 'Reset Password'
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
    s_InfoMsg = 'CryptoPad '+VERSION+'\n\nA simple notepad supporting compressed documents in ZIP AES-256 encrypted format.'
    s_Error = 'Error'
    s_ErrorSaveMsg = 'Not saved - There was an error while saving the document!'
    s_ErrorUnzipMsg = 'Can not load - There was an error while decrypting the document!'
else:
    s_Title = ' - CryptoPad'
    s_NewDoc = 'Senza nome'
    s_MenuFile = 'File'
    s_MenuFileNew = 'Nuovo'
    s_MenuFileOpen = 'Apri...'
    s_MenuFileSave = 'Salva'
    s_MenuFileSaveAs = 'Salva con nome...'
    s_MenuFileQuit = 'Esci'
    s_MenuFileSetPW = 'Imposta Password'
    s_MenuFileResetPW = 'Rimuovi Password'
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
    s_InfoMsg = 'CryptoPad '+VERSION+'\n\nUn semplice blocco note che supporta documenti compressi in formato ZIP cifrato con AES-256.'
    s_New = 'Avviso'
    s_NewMsg = 'Si desidera scartare le modifiche al documento corrente?'
    s_Error = 'Errore'
    s_ErrorSaveMsg = 'Errore durante il salvataggio del documento!'
    s_ErrorUnzipMsg = 'Errore nel decifrare il documento!'
    
    
    
def detect_eol(s):
    "Detects a string line ending"
    crlf = s.count('\r\n')
    cr = s.count('\r') - crlf
    lf = s.count('\n') - crlf
    if not crlf and not cr and not lf:
        return 0 # NONE
    if not cr and not lf:
        return 1 # CRLF
    if not crlf and not lf:
        return 2 # CR
    if not crlf and not cr:
        return 3 # LF
    return 4 # MIXED (=to be fixed)

def convert_eol(s, eol):
    "Converts line ending"
    #~ print "DEBUG: convert_eol --> ", eol
    #~ open('src_eol.bin', 'wb').write(s)
    if eol == 1: # CRLF
        s = re.sub('\r\n?', '\r\n', s)
        s = re.sub('\r?\n', '\r\n', s)
    elif eol == 2: # CR
        s = re.sub('\r?\n', '\r', s)
    elif eol == 3: # LF
        s = re.sub('\r\n?', '\n', s)
    #~ open('dst_eol.bin', 'wb').write(s)
    return s



class CryptoPad(Tk):
    def __init__ (p):
        Tk.__init__(p)
        p.title(s_NewDoc+s_Title)
        p.textPad = scrolledtext.ScrolledText(p, width=100, height=30, wrap=WORD, exportselection=True, undo=True)
        p.target_txt = None
        p.password = None
        p.is_crypted = False
        p.textPad.SetEOL = IntVar() # CRLF
        p.textPad.SetEOL.set(1)
        p.textPad.SetENC = IntVar() # UTF-8
        p.textPad.SetENC.set(1)
        
        menu = Menu(p, tearoff=0)
        p.config(menu=menu)
        
        filemenu = Menu(menu, tearoff=0)
        p.filemenu = filemenu
        menu.add_cascade(label=s_MenuFile, menu=filemenu, underline=0)
        filemenu.add_command(label=s_MenuFileNew, command=p.new_command, underline=0, accelerator='CTRL+N')
        p.bind('<Control-n>', p.new_command)
        filemenu.add_command(label=s_MenuFileOpen, command=p.open_command, underline=0, accelerator='CTRL+F12')
        p.bind('<Control-F12>', p.open_command)
        filemenu.add_command(label=s_MenuFileSave, command=p.save_command, underline=0, accelerator='CTRL+S')
        p.bind('<Control-s>', p.save_command)
        filemenu.add_command(label=s_MenuFileSaveAs, command=p.saveas_command, underline=3)

        filemenu.add_separator()
        smenu = Menu(p, tearoff=0)
        smenu.add_checkbutton(label="CRLF", variable=p.textPad.SetEOL, onvalue=1)
        smenu.add_checkbutton(label="CR", variable=p.textPad.SetEOL, onvalue=2)
        smenu.add_checkbutton(label="LF", variable=p.textPad.SetEOL, onvalue=3)
        filemenu.add_cascade(label='EOL', menu=smenu, underline=0)
        smenu = Menu(p, tearoff=0)
        smenu.add_checkbutton(label="UTF-8", variable=p.textPad.SetENC, onvalue=1)
        smenu.add_checkbutton(label="UTF-16-LE", variable=p.textPad.SetENC, onvalue=2)
        smenu.add_checkbutton(label="UTF-16-BE", variable=p.textPad.SetENC, onvalue=3)
        smenu.add_checkbutton(label="ASCII", variable=p.textPad.SetENC, onvalue=4)
        filemenu.add_cascade(label='Encoding', menu=smenu, underline=0)

        filemenu.add_separator()
        filemenu.add_command(label=s_MenuFileSetPW, command=p.set_password, underline=0)
        filemenu.add_command(label=s_MenuFileResetPW, command=p.reset_password, underline=0)

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

        p.target_txt = filedialog.askopenfilename(parent=p, defaultextension='.txt', filetypes=[(s_Document, '*.txt'),], title=s_MenuFileOpen)
        if p.target_txt == '':
            return

        s = b''
        with open(p.target_txt, 'rb') as stream:
            s = stream.read(4)
            stream.seek(0)
            if len(s) == 4 and s == b'PK\x03\x04':
                p.password = ''
                if not p.password:
                    p.password = simpledialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
                try:
                    zip = MiniZipAEReader(stream, p.password)
                    p.is_crypted = True
                except:
                    messagebox.showerror(s_Error, s_ErrorUnzipMsg)
                    return
                s = zip.get()
                if zip.is_v2:
                    s = s[::-1]
            else:
                s = stream.read()
        if not s: return
        
        p.textPad.SetENC.set(4) # ASCII
        if len(s) > 3 and s[:3] == b'\xEF\xBB\xBF':
            s = s.decode('utf-8-sig')
            p.textPad.SetENC.set(1)
        elif len(s) > 2:
            if s[:2] == b'\xFF\xFE':
                s = s[2:].decode('utf-16le')
                p.textPad.SetENC.set(2)
            elif s[:2] == b'\xFE\xFF':
                s = s[2:].decode('utf-16be')
                p.textPad.SetENC.set(3)
            else: # assume plain ASCII
                if b'\0' in s:
                    s = s.replace(b'\0', b' ')
                s = s.decode('cp1252')
                p.textPad.SetENC.set(4)
        eol = detect_eol(s)
        if eol in (0, 4):
            eol = 1
        p.textPad.SetEOL.set(eol)
        # Assuming buffer is now... ASCII? What is it internal Python encoding??
        s = convert_eol(s, 3) # Tkinter text box wants LF
        p.textPad.delete('1.0', END+'-1c')
        if type(s) == bytes:
            s = s.decode( ('', 'utf-8-sig', 'utf-16le', 'utf-16be', 'cp1252')[p.textPad.SetENC.get()] )
        p.textPad.insert('1.0', s)
        p.title(os.path.basename(p.target_txt)[:-4] + s_Title)
        p.textPad.edit_modified(False)
        p.textPad.edit_separator()

    def save_command(p, evt=None):
        if p.target_txt == None:
            p.saveas_command()
            return
        s = p.textPad.get('1.0', END+'-1c')
        s = convert_eol(s, p.textPad.SetEOL.get())
        if type(s) == str:
            s = bytes(s, ('', 'utf-8-sig', 'utf-16le', 'utf-16be', 'cp1252')[p.textPad.SetENC.get()])
        if p.textPad.SetENC.get() == 2:
            s = b'\xFF\xFE' + s
        elif p.textPad.SetENC.get() == 3:
            s = b'\xFE\xFF' + s
        with open(p.target_txt+'.tmp', 'wb') as stream:
            if p.is_crypted:
                try:
                    zip = MiniZipAEWriter(stream, p.password)
                    zip.append('data', s[::-1]) # inverts text buffer (V2 document format)
                    zip.write()
                    # Cerca di sostituire l'originale solo in assenza di errori
                    if os.path.exists(p.target_txt):
                        os.remove(p.target_txt)
                    stream.close()
                    os.rename(p.target_txt+'.tmp', p.target_txt)
                except:
                    messagebox.showerror(s_Error, s_ErrorSaveMsg)
                else:
                    p.title(os.path.basename(p.target_txt)[:-4] + s_Title)
                    p.textPad.edit_modified(False)
                    p.textPad.edit_separator()
            else:
                stream.write(s)
                stream.close()
                if os.path.exists(p.target_txt):
                    os.remove(p.target_txt)
                os.rename(p.target_txt+'.tmp', p.target_txt)
                p.title(os.path.basename(p.target_txt)[:-4] + s_Title)
                p.textPad.edit_modified(False)
                p.textPad.edit_separator()

    def askpw(p):
        p.password = None
        
        pw1, pw2 = 1, 2
        while pw1 != pw2:
            pw1 = simpledialog.askstring("Passphrase", s_AskPassword+s_Password, show='*')
            # Annulla il loop con la prima pw vuota
            if pw1 == '': return
            pw2 = simpledialog.askstring("Passphrase", s_RepeatPassword+s_Password, show='*')

        p.password = pw1
        
    def saveas_command(p):
        new_target = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[(s_Document, '*.txt'),], title=s_MenuFileSave)
        if not new_target: return
        p.target_txt = new_target
        p.save_command()
        
    def exit_command(p):
        if p.textPad.edit_modified():
            if not messagebox.askokcancel(s_Quit, s_QuitMsg):
                return
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
        p.filemenu.entryconfig(s_MenuFileResetPW, state=('active','disabled')[p.password==None])
        s = ('active','disabled')[p.textPad.tag_ranges("sel")==()]
        p.editmenu.entryconfig(s_MenuEditDel, state=s)
        p.editmenu.entryconfig(s_MenuEditCut, state=s)
        p.editmenu.entryconfig(s_MenuEditCopy, state=s)
        p.editmenu.entryconfig(s_MenuEditPaste, state=('active','disabled')[p.clipboard_get()==None])

    def set_password(p):
        p.askpw()
        p.is_crypted = True
        #~ p.textPad.SetENC.set(1) # Always set UTF-8

    def reset_password(p):
        p.is_crypted = False
        p.password = None


root = CryptoPad()
root.mainloop()
