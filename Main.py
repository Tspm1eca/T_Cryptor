from GUI import Main_win
from PyQt5 import QtWidgets as Qtw
import sys

if __name__ == "__main__":
    app = Qtw.QApplication(sys.argv)
    app.setStyleSheet(open("./Qss/MainWin.qss").read())
    win = Main_win.MainWin()
    win.show()
    sys.exit(app.exec_())
