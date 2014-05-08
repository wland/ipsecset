import test
import test1

def catch_except(func):
    def  t():
        try:
            func()
        except test.IIS_ERROR,e:
            print e.__str__()
    return t

def ttt(func):
    def t():
        print 'ttt'
        func()
    return t

@catch_except
@ttt
def run():
    test1.run()

run()