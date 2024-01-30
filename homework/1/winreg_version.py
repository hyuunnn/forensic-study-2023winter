import winreg
import codecs
import PySimpleGUI as sg

def uninstall():
    result = []
    path = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

    varReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    varKey = winreg.OpenKey(varReg, path, 0, winreg.KEY_ALL_ACCESS)

    i = 0
    try:
        while True:
            folder_name = winreg.EnumKey(varKey, i)
            uninstall_key = winreg.OpenKey(varReg, path + "\\" + folder_name, 0, winreg.KEY_ALL_ACCESS)
            try:
                name = winreg.QueryValueEx(uninstall_key, "DisplayName")
                result.append(name[0])
            except:
                result.append(folder_name)
            i += 1
    except OSError:
        pass

    return result

def userassist(path):
    result = []
    path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{}\\Count".format(path)
    
    varReg = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
    varKey = winreg.OpenKey(varReg, path, 0, winreg.KEY_ALL_ACCESS)

    i = 0
    try:
        while True:
            name, value, _ = winreg.EnumValue(varKey, i)
            result.append(codecs.decode(name, 'rot_13'))
            i += 1
    except OSError:
        pass

    return result

def muicache():
    result = []
    path = "SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"

    varReg = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
    varKey = winreg.OpenKey(varReg, path, 0, winreg.KEY_ALL_ACCESS)

    i = 0
    try:
        while True:
            name, value, _ = winreg.EnumValue(varKey, i)
            result.append(name)
            i += 1
    except OSError:
        pass

    return result

# layout의 첫번째 리스트는 첫번째 행을 의미하고, 두번째 리스트는 두번째 행을 의미한다.
# 첫 번째 리스트에 3개의 버튼을 배치하고, 두 번째 리스트에는 텍스트를 출력할 수 있는 곳을 배치하고 있다.
layout = [
    [sg.Button("Install Programs", key="uninstall"), sg.Button("UserAssist", key="userassist"), sg.Button("MUICache", key="muicache"), sg.Button("Exit", key="exit")],
    [sg.Multiline(key='-TEXT-', size=(100,25))]
]

# https://www.geeksforgeeks.org/themes-in-pysimplegui/
sg.theme('DarkGrey6')

window = sg.Window("Registry Analyzer", layout)

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "exit":
        break

    elif event == "uninstall":
        window['-TEXT-'].update('\n'.join(uninstall()))

    elif event == "muicache":
        window['-TEXT-'].update('\n'.join(muicache()))

    elif event == "userassist":
        result = userassist("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}")
        result.extend(userassist("{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"))

        window['-TEXT-'].update('\n'.join(result))

window.close()
