#coding:utf-8
class IIS_ERROR(Exception):
    def __init__(self,value):
        self.value=value

    def __str__(self):
        return self.value

class Log():
    def __init__(self):
        self._log_list=[]

    def logging(self,ll):
        print ll
        self._log_list.append(ll)

    def get(self):
        return '\r\n'.join(self._log_list)

