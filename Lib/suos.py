import os, math

def get_filesize(file):
    size_list = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    size = os.path.getsize(file)
    if size == 0: return "0 Bytes"
    squr = int(math.floor(math.log(size, 1024)))
    file_size = round(size / math.pow(1024, squr), 2)
    return f"{file_size} {size_list[squr]}"