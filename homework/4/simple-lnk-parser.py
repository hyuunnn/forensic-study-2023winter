import datetime
import os

# https://kali-km.tistory.com/entry/LNK-File-Windows-ShortCut
# https://maj3sty.tistory.com/856
# https://brunch.co.kr/@bl4cksh33p/3
# http://forensic-proof.com/archives/607
# https://asvv.tistory.com/entry/LNK-%ED%8C%8C%EC%9D%BC-%EA%B3%B5%EB%B6%80
# https://gflow-security.tistory.com/entry/Windows-Artifact3-LNK
# https://whitesnake1004.tistory.com/591?category=814007

# http://forensic.korea.ac.kr/DFWIKI/index.php/LNKParser
# http://forensic.korea.ac.kr/DFWIKI/index.php/Lnkanalyser

class LnkParser:
    def __init__(self):
        self.size = 0

        self.DriveType_Value = {
            0: "DRIVE_UNKNOWN (0)",
            1: "DRIVE_NO_ROOT_DIR (1)",
            2: "DRIVE_REMOVABLE (2)",
            3: "DRIVE_FIXED (3)",
            4: "DRIVE_REMOTE (4)",
            5: "DRIVE_CDROM (5)",
            6: "DRIVE_RAMDISK (6)",
        }

        ## https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-showwindow
        self.ShowWindow_value = {
            0: "SW_HIDE (0)",
            1: "SW_SHOWNORMAL, SW_NORMAL (1)",
            2: "SW_SHOWMINIMIZED (2)",
            3: "SW_SHOWMAXIMIZED, SW_MAXIMIZE (3)",
            4: "SW_SHOWNOACTIVATE (4)",
            5: "SW_SHOW (5)",
            6: "SW_MINIMIZE (6)",
            7: "SW_SHOWMINNOACTIVE (7)",
            8: "SW_SHOWNA (8)",
            9: "SW_RESTORE (9)",
            10: "SW_SHOWDEFAULT (10)",
            11: "SW_FORCEMINIMIZE, SW_MAX (11)",
        }

    def set_data(self, path):
        with open(path, "rb") as f:
            self.data = f.read()

    def parse_data(self, size):
        data = self.data[self.size:self.size + size]
        self.size += size
        return data

    def byte2int(self, data):
        return int.from_bytes(data, "little")

    def null_str(self):
        result = b""
        string = b""
        while string != b"\x00":
            string = self.data[self.size:self.size + 1]
            result += string
            self.size += 1
        return result

    def convert_unix_to_window(self, time):
        if time <= 0:
            return "Invalid timestamp"
            
        return datetime.datetime.fromtimestamp(time / 10000000 - 11644473600).strftime("%Y:%m:%d %H:%M:%S")

    def parse(self):
        HeaderSize = self.parse_data(4)
        LinkCLSID = self.parse_data(16)
        LinkFlags = self.parse_data(4)
        FileAttributes = self.parse_data(4)
        CreateTime = self.byte2int(self.parse_data(8))
        AccessTime = self.byte2int(self.parse_data(8))
        WriteTime = self.byte2int(self.parse_data(8))
        FileSize = self.byte2int(self.parse_data(4))
        IconIndex = self.parse_data(4)
        ShowCommand = self.ShowWindow_value[self.byte2int(self.parse_data(4))]
        HotKey = self.parse_data(2)
        Reserved1 = self.parse_data(2)
        Reverved2 = self.parse_data(4)
        Reverved3 = self.parse_data(4)

        IDListSize = self.parse_data(2)
        # 쓸데없는 데이터는 건너띔 78 bytes
        trash_data = self.parse_data(self.byte2int(IDListSize))

        LinkInfoSize = self.parse_data(4)
        LinkInfoHeaderSize = self.parse_data(4)
        LinkInfoFlags = self.parse_data(4)
        VolumeIDOffset = self.parse_data(4)
        LocalBasePathOffset = self.parse_data(4)
        CommonNetworkRelativeLinkOffset = self.parse_data(4)
        CommonPathSuffixOffset = self.parse_data(4)

        VolumeIDSize = self.parse_data(4)
        # 4는 VolumeIDSize 만큼 뺀 값
        VolumeID = self.parse_data(self.byte2int(VolumeIDSize) - 4)
        DriveType = self.DriveType_Value[self.byte2int(VolumeID[:0x4])]
        DriveSerialNumber = self.byte2int(VolumeID[0x4:0x8])

        LocalBasePath = self.null_str()
        CommonPathSuffix = self.parse_data(1)

        RELATIVE_PATH_CountCharacters = self.parse_data(2)
        # 2를 곱하는 이유는 wchar type이기 때문
        RELATIVE_PATH = self.parse_data(self.byte2int(RELATIVE_PATH_CountCharacters) * 2)

        COMMAND_LINE_ARGUMENTS_CountCharacters = self.parse_data(2)
        # 2를 곱하는 이유는 wchar type이기 때문
        COMMAND_LINE_ARGUMENTS = self.parse_data(self.byte2int(COMMAND_LINE_ARGUMENTS_CountCharacters) * 2)

        # index 초기화
        self.size = 0

        return self.convert_unix_to_window(CreateTime), \
            self.convert_unix_to_window(AccessTime), \
            self.convert_unix_to_window(WriteTime), \
            FileSize, ShowCommand, DriveType, DriveSerialNumber, \
            LocalBasePath, RELATIVE_PATH, COMMAND_LINE_ARGUMENTS

        # print("CreateTime : {}".format(self.convert_unix_to_window(CreateTime)))
        # print("AccessTime : {}".format(self.convert_unix_to_window(AccessTime)))
        # print("WriteTime : {}".format(self.convert_unix_to_window(WriteTime)))
        # print("FileSize : {}".format(FileSize))
        # print("ShowCommand : {}".format(ShowCommand))
        # print("DriveType : {}".format(DriveType))
        # print("DriveSerialNumber : {}".format(DriveSerialNumber))
        # print("LocalBasePath : {}".format(LocalBasePath))
        # print("RELATIVE_PATH : {}".format(RELATIVE_PATH.replace(b"\x00", b"")))
        # print("COMMAND_LINE_ARGUMENTS : {}".format(COMMAND_LINE_ARGUMENTS.replace(b"\x00", b"")))

# TODO: 잔버그 고치기
if __name__ == "__main__":
    lnk = LnkParser()
    dir_path = "C:\\Users\\hyuunnnn\\Desktop\\test"

    file_list = os.listdir(dir_path)

    for filename in file_list:
        if filename.endswith(".lnk"):
            print("[*] File: " + filename)
            lnk.set_data(dir_path + "\\" + filename)
            print(lnk.parse())
