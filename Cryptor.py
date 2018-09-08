import os
import asyncio
import stat
import re
import subprocess
import json
from string import digits, ascii_letters
from random import choices
from concurrent.futures import ThreadPoolExecutor
from math import ceil
from log import Logger, level
from hashlib import sha3_256, sha3_512
from bcrypt import gensalt, hashpw
from Cryptodome.Cipher import AES
from suos import get_filesize
from subprocess import check_output


class Checker():
    """ 文件格式檢測 """

    def file_check(self, data):
        if data[:19] == b"T_Cryptor_\xb4\x81\x9a\xb80)\xb1\x08\x1c":
            return True

class Crypto():
    """ AES 加密類 """

    def __init__(self, password=None, key_data=None):
        self.method = None      # 用於模式轉換
        self.key_data = key_data    # 加密key

        if not key_data:
            self.password = password.encode("utf-8")

    def gen_key(self, salt=None, nonce=None):
        """1. 自動轉換 encrypt 和 decrypt 模式, 生成密鑰
           2. 用sha3 512 加hash 密碼
           3. 用bcrypt 和sha3_512把密碼加密
           2. 創建 AES 的 Cipher 用作加密解密
           3. 再用加密後的密碼最後32 bytes 作為AES的密碼
              (AES加密只接受16, 24, 32bytes, 分別是 128, 192, or 256 )
              sha3_256是為了把密碼轉為32bytes
              AES 的EAX 模拭必須要有加密的 nonce 才可解密 """

        # 取 Slat, 轉換模式
        if salt:
            salt = salt
            self.method = False
        else:
            salt = gensalt()
            self.method = True

        if not self.key_data:
            # bcrypt 密碼
            self.key_data = hashpw(
                sha3_512(self.password).hexdigest().encode("utf-8"), salt)
        # AES 密碼
        self.cipher = AES.new(
            sha3_256(self.key_data).digest(), AES.MODE_EAX, nonce)

        return self.key_data

    def encrypt(self, plain_data, file=False):
        """ 加密 """

        if not isinstance(plain_data, bytes):
            plain_data = plain_data.encode("utf-8")

        # 如果非加密模式: 模式轉換
        if not self.method:
            self.gen_key()

        if file:
            # 文件模式，文件內容使用同一組nonce 和 密鑰加密
            # 因多線程調用AES會做成程式不回報, 所以創建多個AES cipher 對象
            cipher = AES.new(sha3_256(self.key_data).digest(),
                             AES.MODE_EAX, self.cipher.nonce)

            return cipher.encrypt(plain_data)

        else:
            data, tag = self.cipher.encrypt_and_digest(plain_data)
            return b"".join([b"T_Cryptor_\xb4\x81\x9a\xb80)\xb1\x08\x1c", self.cipher.nonce, self.key_data[7:29], tag, data])

    def decrypt(self, encry_data, file=False):
        """ 解密 """

        if not isinstance(encry_data, bytes):
            raise TypeError("decrypt() only accept bytes.")

        if self.method != False:
            # 提取 nonce, salt，tag, data
            nonce, salt, tag, encry_data = encry_data[19:35], b"$2b$12$" + \
                encry_data[35:57], encry_data[57:73], encry_data[73:]
            self.gen_key(salt, nonce)

        if file:
            # 文件模式，文件內容使用同一組nonce 和 密鑰加密
            # 因多線程調用AES會做成程式不回報, 所以創建多個AES cipher 對象
            cipher = AES.new(sha3_256(self.key_data).digest(),
                             AES.MODE_EAX, self.cipher.nonce)

            return cipher.decrypt(encry_data)
        else:
            return self.cipher.decrypt_and_verify(encry_data, tag)


class File_Crypto():
    """ 文件加解密 """

    def __init__(self, password=None, key_data=None):
        self.checker = Checker()
        self.cipher = Crypto(password, key_data)
        self.loop = asyncio.get_event_loop()		# 異步loop
        self.executor = ThreadPoolExecutor(max_workers=5)    # 異步多線程
        self.BLOCK_SIZE = 52428800
        self.data_list = dict()			# 暫存加密/解密後data
        self.index = 0					# 用作寫入文件的次序

    def encrypt(self, file_path, no_fn=None):
        return self.loop.run_until_complete(self._encrypt_handle(file_path))

    def decrypt(self, file_path, error_return=False):
        return self.loop.run_until_complete(self._decrypt_handle(file_path, error_return=error_return))

    def _remove(self, file_path):
        try:
            os.remove(file_path)

        except PermissionError:
            os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            os.remove(file_path)
        except Exception as e :
            if gui_mode:
                error_log.append(e)
            else:
                print("[X]", e)

    async def _encrypt_handle(self, file_path, error_pass=False):
        """ 加密程序 """
        def _start_encrypt(area_x):
            """ 異步多線程加密 """
            # 把加密後資料暫存到data_list
            self.data_list[area_x] = self.cipher.encrypt(
                f.read(self.BLOCK_SIZE), file=True)
            while 1:
                try:
                    f_e.write(self.data_list.pop(self.index))
                    self.index += 1
                    break
                except KeyError:
                    pass  # 當要寫入的次序data 未處理完成時,會不停出現KeyError

        file_path_split, filename = os.path.split(file_path)
        # 加密文件名
        filename_encry = self.cipher.encrypt(filename)
        # 隨機偽文件名
        fake_filename = ''.join(choices(
            ascii_letters + digits, k=20))

        # 防止文件名重復
        while os.path.exists(file_path_split + fake_filename):
            fake_filename = ''.join(choices(
                ascii_letters + digits, k=20))

        # 循環次數
        area = ceil(os.path.getsize(file_path) / self.BLOCK_SIZE)

        with open(file_path, "rb") as f:
            file_info = f.read(19)

            if self.checker.file_check(file_info) and error_pass:
                raise ValueError("Do not encrypt same file Twice!")

            elif self.checker.file_check(file_info):
                logger.info(f"[Skip_File] {file_path} already Encrypted")
                return

            f.seek(0)

            with open(os.path.join(file_path_split, fake_filename), "wb") as f_e:
                # b'\xe2\x80\xbb' == "※" 符號，用於方便提取文件名數據
                f_e.write(b"".join([filename_encry + b'\xe2\x80\xbb']))
                if area:
                    task = [self.loop.run_in_executor(
                        self.executor, _start_encrypt, area_x) for area_x in range(area)]
                    # 異步excutor
                    await asyncio.wait(task)
                    self.index = 0
        # 刪除源文件
        self._remove(file_path)

    async def _decrypt_handle(self, file_path, error_return=False):
        """ 解密程序 """
        def _start_decrypt(area_x):
            """ 異步多線程解密 """
            # 把加密後資料暫存到data_list
            self.data_list[area_x] = self.cipher.decrypt(
                f_e.read(self.BLOCK_SIZE), file=True)

            while 1:
                try:
                    f.write(self.data_list.pop(self.index))
                    self.index += 1
                    break
                except KeyError:
                    pass    # 當要寫入的次序data 未處理完成時,會不停出現KeyError
        # 文件路徑
        file_path_split = os.path.split(file_path)[0]

        with open(file_path, "rb") as f_e:
            # 不處理己加密文件
            if not self.checker.file_check(f_e.read(19)):
                logger.info(f"[Skip_File] {file_path} is not Encrypt file")
                return
            f_e.seek(0)
            # 獲取文件的none, salt
            keys = f_e.read(1024).split(b'\xe2\x80\xbb')[0]
            # 重新定位到文件data的最頭
            f_e.seek(len(keys) + 3)
            # 循環次數
            area = ceil((os.path.getsize(file_path) -
                         len(keys) - 3) / self.BLOCK_SIZE)

            try:
                # 解密源文件名
                filename = self.cipher.decrypt(keys).decode("utf-8")
            # 密碼錯誤Error
            except ValueError:
                if error_return:
                    return True
                else:
                    raise KeyError(f"[File]: {file_path}")

            with open(os.path.join(file_path_split, filename), "wb") as f:
                if area:
                    task = [self.loop.run_in_executor(
                        self.executor, _start_decrypt, area_x) for area_x in range(area)]
                    # 異步excutor
                    await asyncio.wait(task)
                    self.index = 0

        self._remove(file_path)


class Folder_Crypto():
    """ 文件夾加解密 """

    def __init__(self, password, bool_count_files = None):
        self.checker = Checker()
        self.password = password
        self.loop = asyncio.get_event_loop()		# 異步
        self.error_files_list = list()
        self.remove_later = list()
        self.undecryptable = list()
        self.compile = re.compile(r"T_.+?")
        if bool_count_files:
            self.count_files = int()

    def _encrypt_handle(self, file):
        # 因多線程調用AES會做成程式不回報, 所以創建多個AES cipher 對象
        try:
            logger.info(f"{file} ~ {get_filesize(file)}")
        except Exception as e:
            logger.warning(f"[Error:] {e}")
            self.count_skip_files += 1
            return

        cipher = File_Crypto(key_data=self.key_data)
        cipher.encrypt(file)

    def _decrypt_handle(self, file, cleanup=False):
        if cleanup:
            file = self.error_files_list[file]     # 因在error_files_list mod 是index
            logger.info(f"[Cleaning] {file} ~ {get_filesize(file)}")

        logger.info(f"{file} ~ {get_filesize(file)}")
        # 因多線程調用AES會做成程式不回報, 所以創建多個AES cipher 對象
        cipher = File_Crypto(self.password, key_data=self.key_data)
        result = cipher.decrypt(file, error_return=True)

        # if result and file not in self.error_files_list:
        if result and not cleanup:
            # key error & 不在解密錯誤list中
            # 這時候的error_files_list有2種可能: salt 不同, 密碼不正確
            self.error_files_list.append(file)

        # 第二次以上解密,解密錯誤,而且是error_files_list的第一個文件(也就是取key_data 的文件)
        elif result and file in self.error_files_list[0]:
            self.remove_later.append(file)
            self.undecryptable.append(file)

        #第二次以上解密, 解密錯誤, 不是error_files_list的第一個文件
        elif result: pass

        else:
            # 正確解密
            if file in self.error_files_list: self.remove_later.append(file)
            self.key_data = cipher.cipher.key_data
            self.count_files += 1

    def _rename(self, folders_list):
        for row_path in sorted(folders_list, reverse=True):
            try:
                # 把文件夾改名
                os.rename(row_path, folders_list[row_path])
            except Exception as e:
                if gui_mode:
                    error_log.append(e)
                else:
                    print("[X]", e)

    def encrypt(self, folder_path, no_fn=False, skip_error=False):
        """ 加密程序 """

        if not os.path.isdir(folder_path):
            raise KeyError(f"Argument must directory. : {folder_path}")

        self.key_data = Crypto(self.password).gen_key()
        files_list = list()     # 需加密文件List
        folders_list = dict()      # 需加密文件夾List

        for folder, _, files in os.walk(folder_path):
            fake_foldername = ''.join(choices(
                ascii_letters + digits, k=20))
            fake_path = os.path.join(os.path.split(folder)[0], fake_foldername)

            for file in list(filter(self.compile.match, files)):
                # 如果文件是"T_"開頭 ，檢測文件內容
                with open(os.path.join(folder, file), "rb") as check_file:
                    if self.checker.file_check(check_file.read(19)):
                        logger.info(
                            f"[Skip_Folder] {folder} is Encrypted")
                        # 當文件夾己加密，跳過
                        break
            else:
                folders_list[folder] = fake_path
                [files_list.append(os.path.join(folder, file)) for file in files]

        [self._encrypt_handle(file) for file in files_list]


        if not no_fn:
            # 加密文件夾
            for folder in folders_list:
                cipher = Crypto(key_data=self.key_data)
                fake_filename = ''.join(choices(
                    ascii_letters + digits, k=18))
                with open(os.path.join(folder, "T_" + fake_filename), "wb") as folder_file:
                    # 把文件夾名加密和寫入"T_"開頭文件中
                    folder_file.write(cipher.encrypt(folder))

            self.count_folders = len(folders_list)
            self._rename(folders_list)

        self.count_files = len(files_list)

    def decrypt(self, folder_path, root_only=False):
        """ 解密程序 """

        if not os.path.isdir(folder_path):
            raise KeyError(f"Argument must directory. : {folder_path}")

        self.key_data = None       # 解密key
        folders_list = dict()      # 需解密文件夾List
        error_folders_list = list()

        for folder, _, files in os.walk(folder_path):
            cipher = Crypto(self.password, self.key_data)
            files_list = list()     # 需解密文件List
            breaker = bool()

            for file in list(filter(self.compile.match, files)):
                # 如果文件是"T_"開頭 ，檢測文件內容
                with open(os.path.join(folder, file), "rb") as f_e:
                    if not self.checker.file_check(f_e.read(19)):
                        continue
                    f_e.seek(0)
                    data = f_e.read()
                    # 把文件夾路徑加入改名列表
                    try:
                        folders_list[folder] = os.path.join(os.path.split(
                            folder)[0], os.path.split(cipher.decrypt(data).decode())[-1])
                        if not self.key_data:
                            self.key_data = cipher.key_data
                    # 當解密失敗可能是2種原因:
                    # 1. salt 不同
                    # 2. 密碼不對
                    except ValueError:
                        if folder == folder_path and not root_only:
                            raise KeyError(
                                f"[Folder]: {folder}")
                        elif not root_only:
                            error_folders_list.append(folder)
                        break

                os.remove(os.path.join(folder, file))
                files.remove(file)
            else:
                [files_list.append(os.path.join(folder, file)) for file in files]

                # root_only: 只解密根目錄
                if root_only and not files_list:
                    break
                else:
                    [self._decrypt_handle(file) for file in files_list]
                    if root_only:
                        break

        if error_folders_list:
            # 嘗試用不同的salt 解密文件夾
            for folder in error_folders_list:
                sub_folders_list, sub_count_files = Folder_Crypto(self.password, bool_count_files=True).decrypt(folder, root_only=True)

                folders_list.update(sub_folders_list)

                self.count_files += sub_count_files

        while self.error_files_list:
            # 嘗試用不同的salt 解密文件
            self.key_data = None

            for x in range(len(self.error_files_list)):
                if self._decrypt_handle(x, cleanup=True):
                    break

            [self.error_files_list.remove(lst) for lst in self.remove_later]
            self.remove_later.clear()

        [logger.warning(f"Password error {file}") for file in self.undecryptable]

        if not root_only:
            self.count_folders = len(folders_list)
            self._rename(folders_list)

        else:
            return folders_list, self.count_files


def terminal():
    import argparse
    from getpass import getpass
    from time import time
    import sys

    parser = argparse.ArgumentParser(description='T_Cryptor')

    parser.add_argument("operation", type=str, help="Operation: E/e, D/d")
    parser.add_argument(
        '--no-fn', help="Not encrypt folder name",  dest="fn", action='store_true')
    parser.add_argument("--log", type=str, dest="log_level",
                        help="Set the Log Level: CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET")

    parser.add_argument('path', type=str, help='File path')

    args = parser.parse_args()

    path = args.path

    if not os.path.exists(args.path):
        print("[X] File/Folder don't exists!")
        sys.exit()

    if not args.log_level:
        args.log_level = "WARNING"

    args.log_level = args.log_level.upper()

    if args.log_level not in level:
        raise ValueError(
            "log_level must be: CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET")

    global logger

    logger = Logger().get_logger(level=level[args.log_level])

    if path[-1] in['"', "'"]:
        path = path[:-1]

    print("- Please remember your password!\n- There no way to restore your password and file if you forget it.")

    password = getpass("[+] Password: ")

    while args.operation in ["E", "e"]:

        password2 = getpass("[+] Password Confirm: ")

        if password != password2:
            print("\n[X] The two password not match!\n")
            password = getpass("[+] Password: ")
        else:
            break

    print("[+] Processing...")

    if os.path.isfile(args.path):
        cipher = File_Crypto(password)

    elif os.path.isdir(args.path):
        cipher = Folder_Crypto(password)

    else:
        print(f"[X] Path Argument Error: \"{args.path}\"")
        sys.exit()

    cipher.count_files = int()
    cipher.count_folders = int()
    cipher.count_skip_files = int()

    start = time()

    if args.operation in ["E", "e"]:
        print("[E]", cipher.encrypt(path, no_fn = args.fn))
        if cipher.count_files:
            print(f"[Encrypted Files]: {cipher.count_files}")
        if cipher.count_skip_files:
            print(f"[Skip Files]: {cipher.count_skip_files}")
        if cipher.count_folders:
            print(f"[Encrypted Folders]: {cipher.count_folders}")

    elif args.operation in ["D", "d"]:
        print("[E]", cipher.decrypt(path))
        if cipher.count_files:
            print(f"[Decrypted Files]: {cipher.count_files}")
        if cipher.count_folders:
            print(f"[Decrypted Folders]: {cipher.count_folders}")

    else:
        print(f"[X] Operation Argument Error: \"{args.operation}\"")

    print("[Done] Program Use:", time() - start)


if __name__ == "__main__":
    gui_mode = False
    terminal()

else:
    gui_mode = True
    error_log = []

# -----------------------------
# [BUG]
# 當己加密文件被改名為T_開頭, 解密ERROR
# -----------------------------
# Creat by T1me
# Start Date: 15-9-2017
#
# -v1.1.1
# 08-09-2018
# [IMP] 優化error_files_list, 加快解密速度
# [ADD] 增加undecryptable list
#
# -v1.1.0
# 28-08-2018
# [FIX] 當文件夾沒有被加密(--no-fn), 解密時會出現重複解密密碼, 因為bcrypt 解密變得十分慢
# [FIX] 加密單文件時出現的no_fn Error
# [IMP] 提前檢查文件/文件夾是否存在
# [FIX] 密碼錯誤時沒有提示
# [ADD] 增加Folder_decrypt 密碼錯誤list
# [ADD] 增加error_files_list，採用單文件單密碼再解密
#
# -v1.0.2
# 20-05-2018
# [Add] 增加不加密文件夾選項
# [Add] 加密文件時出錯跳過文件
# [Add] 增加在Terminal 中調控Logging Level
#
# -v1.0.1
# 14-05-2018
# [Fix]不會解密文件夾內有不同salt的文件
#
# -v1.0
# 20-01-2018
# [ADD] Folder_Crypto decrypt: 只嘗試解密文件夾確的文件夾, 而不是所有文件
# [Fix] 文件夾內的"T_"文件出現同名
# [Fix] 解密時, 如文件夾內第一個文件不是己加密文件其他文件也不會解密
#
# -Beta 0.4
# 07-12-2017
# [ADD] Folder_Crypto decyrpt 使用同一組bcrypt 減少解密時間
# [ADD] terminal 可自動驗測文件/文件夾
# [DELETE] terminal Crypto 加密
# [ADD] 增加加密後的文件特性
# [Fix] 當文件在不同密碼的文件夾下，不會解密
# [Fix] 在加密新文件夾時, 加密不完整
# [Fix] Rename & Remove PermissionError
# [Fix] 文件/文件夾 PermissionError
#
# - Beta 0.3
# 24-11-2017
# [ADD] Folder_Crypto 使用同一組bcrypt 減少加密時間
# [ADD] Terminal() 顯示Argment 錯誤Args
# [ADD] Folder_Crypto decrypt key Error 會返回密碼錯誤文件
# [ADD] 加入tag, 取代舊有密碼驗測
#
# - Beta 0.2
# 16-11-2017
# [Fix] 不可檢測文件夾不存在
#
# - Beta 0.1
# 03-11-2017
# [ADD]加入log
# [ADD]可驗測文件是否已經過加密, 防止二次加密做成資料破壞
# [ADD]找別一個方法測密碼
# [ADD]當文件夾內有已加密和未加密文件時自動篩選
# [Fix]密碼錯誤時, 己對文件做成影響
# [Fix]Folder_Crypto: Checker 需要在寫入文件名(T_XXXXXXX)前執行
# [Fix]當文件使用不同密碼文件出現的錯誤
# [Fix]己加密的文件夾也被再加密
# [Fix]當文件夾內有己加密的文件夾, root文件夾不會加密
#
# - 0.0.5
# 26-10-2017
# [ADD] 增加Folder_Crypto
# [ADD] 增加加密後刪除源文件
# [ADD] 增加文件大小檢測
# [Fix] 修正FIle_Crypto 出現文件使用相同Salt
#
# - 0.0.4
# 21-10-2017
# [ADD] 增加0bytes文件的Error
# [Fix] 修正密碼錯誤檢測
#
# - 0.0.3
# 19-10-2017
# [ADD] File_Cyrpto 加入異步大大優化加解密時間
#
# - 0.0.2
# 15-10-2017
# [Fix] Some Bug
#
# - 0.0.1
# 08-10-2017
# [Add] Argparse 令程序可在Terminal使用
#
# - Init
# 21-9-2017
# [ADD] 建立基本Crypto 和 File_Cyrpto
