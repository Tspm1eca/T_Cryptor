"""
OS的自定義版
"""
import os, re, shutil, math

__all__ = ["exten", "paths", "files", "movep"]

class TypeError(Exception): pass

def exten(filelist, formatlist, upper = False, index = False, name = False):
    """用於檢驗files文件副名中是否包含forlist
       upper: True / False, True為同時檢驗大寫
       index: True / False, True為反回為真的值位置
       注: 數據必須為list."""

       # 如filelist, formatlist其中一個不是list報錯!
    if type(filelist) != list or type(formatlist) != list: raise TypeError("Data must be Type list!")

    i = -1
        # 記錄為真的位置
    loca = []
    file_name = []
        # 文件for
    for fle in filelist:
        i += 1
            # 格式for
        for format in formatlist:
            size = len(format)
                # 對比字尾
            if format in fle[-size:]:
                if index: loca.append(i)
                elif name: file_name.append(fle)
                else: return True
                # 把格式大寫化再對比字尾
            elif upper and format.upper() in fle[-size:]:
                if index: loca.append(i)
                elif name: file_name.append(fle)
                else: return True
    if loca: return loca
    if file_name: return file_name

def paths(path):
    """用於反回所有當前目錄路徑"""
    all_path = []
    for z in os.walk(path):
        # if z[0] in path: continue
        all_path.append(z[0])

    return all_path

def files(path, file_name, prefix = True):
    """用於反回路徑中的文件名關鍵詞的所有文件
       prefix: True / False, True為只查找以關鍵詞開頭的文件
       注: flie_name你可以使用正值表達式的規則"""

    result = []
    if prefix: file_name = "^" + file_name
    for x in os.listdir(path):
        if re.search(file_name, x):
            result.append(x)
    return result

def movep(src, dst, overlay = True):
    """ 移動文件
        overlay: True / False, True為自動覆蓋 """

    if not os.path.isdir(dst): raise TypeError("dst must be a directory.")

        # 移動文件
    if os.path.isfile(src):
        dst_dir = os.path.join(dst, os.path.basename(src))

        if os.path.exists(dst_dir):
            if not overlay: return
            os.remove(dst_dir)
        shutil.move(src, dst_dir)
        return

        # 移動文件夾
    for folder in os.walk(src):
            # 把目標路徑, 系統分隔符 和 src 文件夾的子路徑合成一層路徑
        dst_dir = dst + os.sep + os.path.basename(src) + folder[0].split(src, 1)[-1]
            # 當路徑已存在於目標文件夾, 刪除目標文件夾的文件, 再把新的文件移動
        if os.path.exists(dst_dir):
            for exs_file in folder[-1]:
                abs_path = os.path.join(dst_dir, exs_file)
                if os.path.exists(abs_path):
                    if not overlay: continue
                    os.remove(abs_path)
                shutil.move(os.path.join(folder[0], exs_file), os.path.join(dst_dir, exs_file))

        elif not os.path.exists(dst_dir): shutil.move(folder[0], dst_dir)

        # 刪除移動後的空文件夾
    if os.path.exists(src) and overlay: shutil.rmtree(src)

def get_filesize(file_name, isnum=False):
    """ 獲取文件大小
        isnum: True / False, True: file_name輸入數字 """
    size_list = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    size = file_name if isnum else os.path.getsize(file_name)
    if size == 0: return "0 Bytes"
    # 利用對數找出1024的size平方
    squr = int(math.floor(math.log(size, 1024)))
    # 用size除1024的次方(因: 1024^1 = KB, 1024^2 = MB...)
    file_size = round(size / math.pow(1024, squr), 2)
    return f"{file_size}{size_list[squr]}"


if __name__ == "__main__":
    movep("A", "B", False)

#-----------------------------
# Creat by T1me
# Date: 31-8-2014
#
# Change Log
# exten(): 31-8-2014
# paths(): 19-9-2014
# files(): 11-11-2014
# movep(): 7-9-2015
#		   改名為suos
# get_filesize(): 24-12-2019