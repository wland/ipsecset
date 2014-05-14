#coding:utf-8
"""
分析ipsec安全策略
"""
import subprocess

lines=[]

def init(func):
    """装饰器
    初始化
    """
    def t(*args,**kwargs):
        global lines
        output=subprocess.Popen('netsh ipsec static show all format=list',shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output=output.stdout.read()
        lines=[tmp_line.decode('cp936','ignore') for tmp_line in output.split('\r\n')]

        return func(*args,**kwargs)
    return  t

class Mydict(dict):
    def __missing__(self, key):
        return key

@init
def iter_filters():
    """每次返回一条存放filter信息的dict
    在salt下返回的是英文的结果"""
    index=0
    filterlist_line=''
    while(True):
        if (u'筛选器列表名称' in lines[index]) or (u'FilterList Name' in lines[index]):
            filterlist_line=lines[index]

        #两行分别以描述和已镜像开头，说明下面的几行是filter信息
        if (u'描述' in  lines[index] and u'已镜像' in lines[index+1]) or (u'Description' in  lines[index] and u'Mirrored' in lines[index+1]):
            #获取一组规则的line列表
            infos=[filterlist_line,lines[index]]
            while(True):
                index+=1
                #过滤掉dns参数，用不着
                if (lines[index].startswith(u'目标 DNS 名称') or lines[index].startswith(u'源 DNS 名称')) \
                        or (lines[index].startswith(u'Destination DNS Name') or lines[index].startswith(u'Source DNS Name')):
                    continue
                if (u'目标端口' not in lines[index]) and (u'Destination Port' not in lines[index]):#目标端口是一条规则的结尾
                    infos.append(lines[index])
                else:
                    infos.append(lines[index])
                    break
            #将line列表转换为字典
            open('d:\\backup\\ipsecset.log','a').write(str(infos))
            d_filter= {DICT_CONVERSION[info.split(':')[0].strip()]:DICT_CONVERSION[info.split(':')[1].strip()] for info in infos}
            d_filter[u'description']='\"%s\"'%(d_filter[u'description'])    #将描述内容用双引号括起来
            d_filter[u'filterlist']='\"%s\"'%(d_filter[u'filterlist'])
            yield d_filter
        else:
            index+=1

        if index>=len(lines):
            break

def get_filters():
    """返回所有filter字典的列表"""
    return [d for d in iter_filters()]

DICT_CONVERSION = Mydict({
    u'筛选器列表名称' : u'filterlist' ,
    u'协议': u'protocol',
    u'任何': u'0',
    u'<任何 IP 地址>': u'any',
    u'<我的 IP 地址>': u'me',
    u'源 IP 地址': u'srcaddr',
    u'目标 IP 地址': u'dstaddr',
    u'已镜像': u'mirrored',
    u'是': u'YES',
    u'否': u'NO',
    u'无':u'',
    u'源掩码': u'srcmask',
    u'目标掩码': u'dstmask',
    u'源端口': u'srcport',
    u'目标端口': u'dstport',
    u'描述': u'description',
    #english
    u'FilterList Name' : u'filterlist' ,
    u'Protocol': u'protocol',
    u'ANY': u'0',
    u'<Any IP Address>': u'any',
    u'<My IP Address>': u'me',
    u'Source IP Address': u'srcaddr',
    u'Destination IP Address': u'dstaddr',
    u'Mirrored': u'mirrored',
    u'YES': u'YES',
    u'NO': u'NO',
    u'NONE':u'',
    u'Source Mask': u'srcmask',
    u'Destination Mask': u'dstmask',
    u'Source Port': u'srcport',
    u'Destination Port': u'dstport',
    u'Description': u'description'
})


def get_policyName():
    """返回策略名称"""
    return lines[1].split(':')[1].strip()

def get_filterlists():
    """返回筛选器列表名称的集合"""
    l = []
    for line in lines:
        if line.startswith(u'筛选器列表名称'):
            l.append(line.split(':')[1].strip())

if __name__=='__main__':
    #print get_policyName()
    #print get_filterlists()
    for  d in iter_filters():
        for k,v in d.iteritems():
            print r"u'"+k+r"'",":",r"u'"+v+r"'",','
            #print k,':',v
        print '---------------------'

