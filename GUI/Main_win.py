from PyQt5 import QtWidgets as Qtw
from PyQt5 import QtCore
from PyQt5 import QtGui
from Lib import Cryptor
import os
import webbrowser
import platform

class MyTreeView(Qtw.QTreeView):
    """自定QTreeView"""
    def __init__(self, main):
        super().__init__()
        self.main = main

        self.setSelectionMode(3)
        self.setDragDropMode(Qtw.QAbstractItemView.InternalMove)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setSortingEnabled(True)
        self.setRootIsDecorated(False)
        self.setSelectionBehavior(1)

    def dragEnterEvent(self, event):
        """拖進事件"""
        # 接受拖放
        event.accept()

    def dropEvent(self, event):
        """拖放事件"""

        # 取得文件名
        urlform = event.mimeData().urls()
        paths = [os.path.realpath(url.toLocalFile()) for url in urlform]

        self.main.addItem(paths)


class MainWin(Qtw.QWidget):

    def __init__(self):
        super().__init__()

        self.ui_Init()
        self.encrypt_model = True
        # self.encrypting = False
        self.file_dict = dict()
        self.no_fn = True

        # UI Widgets
    def ui_Init(self):

        font = QtGui.QFont("Consolas", 14, True)

            # 窗口設定
        self.setWindowIcon(QtGui.QIcon("./Icon/Icon.ico"))
        self.setWindowTitle("T_Cryptor")
        self.setFixedSize(650, 750)
        self.setWindowFlags(QtCore.Qt.WindowCloseButtonHint |
                            QtCore.Qt.MSWindowsFixedSizeDialogHint)

        # 用Grid做低布局
        grid = Qtw.QGridLayout()
        grid.setSpacing(0)
        grid.setContentsMargins(0, 0, 0, 0)

        # 版本號, 用CSS來設定文字
        version = Qtw.QLabel('''<a style= "color:#55aaff; text-decoration:none; font-size:12pt; font-family:Consolas; font-weight: bold;" \
                                href="https://www.t1gate.com">- Bata 1 -</a>''', self)
        # 字位置
        version.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignRight)
        # # 開啟超接結
        version.linkActivated.connect(self.openlink)

        # Label
        label = Qtw.QLabel("--- T_Cryptor ---", self)
        label.setAlignment(QtCore.Qt.AlignCenter)
        label.setFont(QtGui.QFont("Consolas", 16, True))

        # Tab
        tab = Qtw.QTabWidget(self)
        # 設定Tab大小
        tab.setStyleSheet('QTabBar { font-size: 12pt; font-family: Consolas; }')

        # 樹狀圖
        self.tree = MyTreeView(self)

        self.tree_model = QtGui.QStandardItemModel()
        self.tree_model.setHorizontalHeaderLabels(["","Path", "State"])
        self.tree_model.setHorizontalHeaderItem

        self.tree.setModel(self.tree_model)
        self.tree.sortByColumn(0, QtCore.Qt.AscendingOrder)
        self.tree.setAlternatingRowColors(True)

        self.tree.setColumnWidth(0, 1)
        self.tree.setColumnWidth(1, 540)
        self.tree.setColumnWidth(2, 20)
        self.root_node = self.tree_model.invisibleRootItem()

        # 增加Tab
        tab.addTab(self.tree, "Process List")

        self.pbar = Qtw.QProgressBar(self)
        self.pbar.setMinimum(0)
        self.pbar.setMaximum(0)
        self.pbar.setAlignment(QtCore.Qt.AlignCenter)
        self.pbar.hide()

        # Label
        self.label_done = Qtw.QLabel("- All Done -", self)
        self.label_done.setAlignment(QtCore.Qt.AlignCenter)
        self.label_done.setFont(QtGui.QFont("Consolas", 16, True))
        self.label_done.setAutoFillBackground(True)

        pe = QtGui.QPalette()
        color = QtGui.QColor('#7bf299')
        pe.setColor(QtGui.QPalette.Window, color)  # 设置背景颜色
        self.label_done.setPalette(pe)

        self.label_done.hide()

        # Button
        self.button = Qtw.QPushButton("More", self)
        self.button.setFont(font)
        self.button.setFixedHeight(35)

        # Button_1
        self.button_1 = Qtw.QPushButton(self)
        self.button_1.setIcon(QtGui.QIcon("./Icon/add.png"))
        self.button_1.setIconSize(QtCore.QSize(25, 25))
        self.button_1.setFont(font)
        self.button_1.setFixedHeight(35)
        # 初始化
        self.button_1.clicked.connect(self.cleanItem)

        # Button_2
        self.button_2 = Qtw.QPushButton("Start: Encrypt (" + commandkey +"+R)", self)
        self.button_2.setFont(font)
        self.button_2.setFixedHeight(35)
        self.button_2.setFixedWidth(400)
        self.button_2.clicked.connect(self.startCrypto)

        # 快捷鍵
        self.ps_shortcut = Qtw.QShortcut(QtGui.QKeySequence("Ctrl+R"), self)
        self.ps_shortcut.activated.connect(self.startCrypto)          # 加解密

        menu = Qtw.QMenu(self)
        menu.setToolTipsVisible(True)

        self.change_model = menu.addAction("&Change Model (" + commandkey + "+C)")
        self.change_model.setShortcut(QtGui.QKeySequence("Ctrl+C"))
        self.change_model.triggered.connect(self.changeModel)
        self.change_model.setToolTip("Change to Encrypt / Decrypt")

        self.no_file_name = menu.addAction("&no_fn")
        self.no_file_name.setToolTip("Disable to Encrypt folders name")
        self.no_file_name.setCheckable(True)
        self.no_file_name.setChecked(True)

        self.button.setMenu(menu)

        # 載入Widgets
        grid.addWidget(version, 0, 0, 1, 3)
        grid.addWidget(label, 1, 0, 1, 3)
        grid.addWidget(tab, 2, 0, 1, 3)
        grid.addWidget(self.pbar, 3, 0, 1, 3)
        grid.addWidget(self.label_done, 4, 0, 1, 3)
        grid.addWidget(self.button_1, 5, 0)
        grid.addWidget(self.button_2, 5, 1)
        grid.addWidget(self.button, 5, 2)

        # 載入布局
        self.setLayout(grid)

    def startCrypto(self):
        if not self.root_node.rowCount():
            self.messBox(titile=" ", mess="List is Empty")
        else:
            PassWin(self).show()
            self.setEnabled(False)

    def addItem(self, paths):
        for path in paths:
            icon = None
            file_name = os.path.split(path)[-1]
            if file_name not in self.file_dict.keys():
                item = QtGui.QStandardItem(file_name)
                item.setEditable(False)

                state = QtGui.QStandardItem("-")
                state.setEditable(False)
                state.setTextAlignment(QtCore.Qt.AlignCenter)

                if os.path.isdir(path):
                    icon = QtGui.QStandardItem(QtGui.QIcon("./Icon/folder.ico"), "")
                    icon.setEditable(False)

                self.root_node.appendRow([icon, item, state])
                self.file_dict[file_name] = [path, item]

        self.button_1.setIcon(QtGui.QIcon(""))
        self.button_1.setText("Clean")

    def cleanItem(self):
        if not self.file_dict:
            self.messBox(titile="- Drag & Drop -", mess="Just drag your file/folder in to program.",
                        messicon=Qtw.QMessageBox.Information)
            return
        self.file_dict.clear()
        self.tree_model.clear()
        self.tree_model.setHorizontalHeaderLabels(["", "Path", "State"])
        self.tree.setColumnWidth(0, 1)
        self.tree.setColumnWidth(1, 540)
        self.tree.setColumnWidth(2, 20)
        self.tree.sortByColumn(0, QtCore.Qt.AscendingOrder)
        self.tree.setAlternatingRowColors(True)
        self.root_node = self.tree_model.invisibleRootItem()

        self.button_1.setText("")
        self.button_1.setIcon(QtGui.QIcon("./Icon/add.png"))

    def changeModel(self):
        if self.encrypt_model:
            self.button_2.setText("Start: Decrypt (" + commandkey + "+R)")
            self.encrypt_model = False
        else:
            self.button_2.setText("Start: Encrypt (" + commandkey + "+R)")
            self.encrypt_model = True

    # 開啟網頁
    def openlink(self, link): webbrowser.open(link)

        # 信息框
    def messBox(self, titile, mess, setbutton=None, messicon=None, detail=[]):
        messbox = Qtw.QMessageBox()
        messbox.setWindowTitle(titile)
        messbox.setWindowIcon(QtGui.QIcon("./Icon/Icon.ico"))
        messbox.setText(mess)
        messbox.setFont(QtGui.QFont("Consolas", 13, True))
        # 先定Icon
        if messicon:
            messbox.setIcon(messicon)
            # 自定Button
        if setbutton:
            messbox.setStandardButtons(setbutton)
            # 如有詳細信息, 啟用
        if detail:
            text = ""
            for x in detail:
                text += "- {}\n".format(x)
            messbox.setDetailedText(text)
            # 反回MessBox的按鍵碼
        return messbox.exec_()


class PassWin(Qtw.QDialog):
    """初始設定窗口"""

    def __init__(self, main_self):

        super().__init__()
        self.main_self = main_self      # Main的self
        self.c_pass = ""
        self.thread = RunThread(pass_win_self=self, main_self=main_self)
        self.thread.postSignal.connect(self.finished)

        # 設定加密文件
        def setup():
            if (self.main_self.encrypt_model and self.init_entry.text() == self.init_entry_2.text()) or (not self.main_self.encrypt_model and self.init_entry.text()):
                self.main_self.setEnabled(True)
                self.main_self.button.setEnabled(False)
                self.main_self.button_1.setEnabled(False)
                self.main_self.pbar.show()
                self.main_self.button_2.setText("Stop")
                # 關閉窗口
                self.close()
                self.c_pass = self.init_entry.text()

                self.thread.start()

            elif self.init_entry.text() != self.init_entry_2.text():
                self.init_label.setStyleSheet('QLabel {color: #ff3030}')
                self.init_label.setText("Password don't match!")
                return
            elif not self.init_entry.text() or not self.init_entry_2.text():
                self.init_label.setStyleSheet('QLabel {color: #ff3030}')
                self.init_label.setText("Password can't be empty!")
                return

        if not self.main_self.label_done.isHidden(): self.main_self.label_done.hide()

        self.setWindowTitle("T_Cryptor")
        self.setWindowIcon(QtGui.QIcon("./Icon/Icon.ico"))
        # 不可改窗口大小
        self.setFixedSize(350, 180)
        # 窗口置頂
        self.setWindowFlags(QtCore.Qt.WindowCloseButtonHint |
                            QtCore.Qt.WindowStaysOnTopHint |
                            QtCore.Qt.MSWindowsFixedSizeDialogHint)

        # 字形
        font = QtGui.QFont("Consolas", 13)
        font.setBold(True)

        # 用Grid做布局
        init_grid = Qtw.QGridLayout()
        init_grid.setHorizontalSpacing(0)
        init_grid.setContentsMargins(0, 0, 0, 0)

        self.init_label = Qtw.QLabel(
            "Please Enter your Password")
        self.init_label.setAlignment(QtCore.Qt.AlignCenter)
        self.init_label.setFont(font)

        self.init_entry = Qtw.QLineEdit()
        self.init_entry.setEchoMode(Qtw.QLineEdit.PasswordEchoOnEdit)
        self.init_entry.setAlignment(QtCore.Qt.AlignCenter)
        self.init_entry.setStyle(Qtw.QStyleFactory.create("Fusion"))
        self.init_entry.setFixedWidth(250)
        self.init_entry.setFont(font)
        self.init_entry.setPlaceholderText("Enter Password")
        self.init_entry.returnPressed.connect(setup)

        self.init_entry_2 = Qtw.QLineEdit()
        self.init_entry_2.setEchoMode(Qtw.QLineEdit.PasswordEchoOnEdit)
        self.init_entry_2.setAlignment(QtCore.Qt.AlignCenter)
        self.init_entry_2.setStyle(Qtw.QStyleFactory.create("Fusion"))
        self.init_entry_2.setFixedWidth(250)
        self.init_entry_2.setFont(font)
        self.init_entry_2.setPlaceholderText("Confirm Password")
        self.init_entry_2.returnPressed.connect(setup)


        self.init_Button_4 = Qtw.QPushButton("Confirm")
        self.init_Button_4.setStyle(Qtw.QStyleFactory.create("Fusion"))
        self.init_Button_4.setFixedHeight(35)
        self.init_Button_4.setFont(font)
        self.init_Button_4.clicked.connect(setup)

        init_grid.addWidget(self.init_label, 0, 0, 1, 0)
        init_grid.addWidget(self.init_entry, 1, 0, 1, 1, QtCore.Qt.AlignCenter)
        init_grid.addWidget(self.init_entry_2, 2, 0, 1, 1,  QtCore.Qt.AlignCenter)
        init_grid.addWidget(self.init_Button_4, 3, 0, 1, 0, QtCore.Qt.AlignCenter)

        self.setLayout(init_grid)

        if not self.main_self.encrypt_model:
            self.init_entry_2.hide()

    def closeEvent(self, event):
        self.main_self.setEnabled(True)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Escape: self.close()


    def finished(self, mess):
        self.main_self.setEnabled(True)
        self.main_self.button.setEnabled(True)
        self.main_self.button_1.setEnabled(True)
        self.main_self.pbar.hide()
        self.main_self.encrypt_model = True
        self.main_self.button_2.setText("Start: Encrypt (" + commandkey + "+R)")
        self.main_self.cleanItem()
        self.main_self.label_done.show()

        if mess:
            self.main_self.messBox(titile="Result", mess=mess)


class RunThread(QtCore.QThread):
    # python3,pyqt5与之前的版本有些不一样
    #  通过类成员对象定义信号对象

    postSignal = QtCore.pyqtSignal(str)

    def __init__(self, pass_win_self=None, main_self=None, parent=None):
        super().__init__()
        self.pass_win_self = pass_win_self
        self.main_self = main_self

    def __del__(self):
        self.wait()

    def Crypto(self, lists):
        mess = str()
        count_files = 0
        count_folders = 0
        count_skip_files = 0
        error_mess = "None"

        for path in lists.keys():

            path = self.main_self.file_dict[path][0]

            if os.path.isfile(path):
                cipher = Cryptor.File_Crypto(self.pass_win_self.c_pass)

            elif os.path.isdir(path):
                cipher = Cryptor.Folder_Crypto(self.pass_win_self.c_pass)

            if self.main_self.encrypt_model:
                try:
                    cipher.encrypt(
                        path, no_fn = self.main_self.no_file_name.isChecked())
                except ValueError:
                    # encrypt same file Twice
                    pass
            else:
                try:
                    cipher.decrypt(path)
                except KeyError:
                    error_mess =  "Some file/folder Password Wrong"

            count_files += cipher.count_files
            count_skip_files += cipher.count_skip_files
            if "count_folders" in dir(cipher): count_folders += cipher.count_folders

        if self.main_self.encrypt_model:
            mess = f"[Encrypted Files]: {count_files}\n[Skiped Files]: {count_skip_files}\n[Encrypted Folders]: {count_folders}\n\n[Error]: {error_mess}"
        else:
            mess = f"[Decrypted Files]: {count_files}\n[Skiped Files]: {count_skip_files}\n[Decrypted Folders]: {count_folders}\n\n[Error]: {error_mess}"

        return mess

    def run(self):
        # 处理你要做的业务逻辑，这里是通过一个回调来处理数据，这里的逻辑处理写自己的方法
        mess = self.Crypto(self.main_self.file_dict)
        self.postSignal.emit(mess)


""" 依不同的平台去改變Ctrl / ⌘ """
ismac = platform.mac_ver()
if ismac[0]:
    commandkey = "⌘"
else:
    commandkey = "Ctrl"

# -----------------------------
# [TODO]:
#
# [BUG]:
#
#
# Created by T1me
# Date: 09-09-2018
#
# Change Log
#
# -Beta v1
# 12-09-2019
# [Fix] 文件+文件夾混時不能正加解密
# [Fix] 文件二次加密
# [Fix] 有不同密碼解密時文件不會跳過問題
# [Add] 轉換加解快捷键
#
# -Alpha v2
# 04-01-2019
# GUI加密解密功能正常使用#
#
# -Alpha v1
# 11-09-2018
# 完成基本GUI
